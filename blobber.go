package blobber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/config"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/validator_proxy"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	"github.com/pkg/errors"
	"github.com/protolambda/eth2api"
	"github.com/protolambda/eth2api/client/beaconapi"
	"github.com/protolambda/zrnt/eth2/beacon"
	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/tree"
	"github.com/sirupsen/logrus"
)

const (
	PortBeaconTCP    = 9000
	PortBeaconUDP    = 9000
	PortBeaconAPI    = 4000
	PortBeaconGRPC   = 4001
	PortMetrics      = 8080
	PortValidatorAPI = 5000
	FarFutureEpoch   = beacon_common.Epoch(0xffffffffffffffff)

	DEFAULT_BLOBBER_HOST       = "0.0.0.0"
	DEFAULT_BLOBBER_PORT       = 19999
	DEFAULT_PROXIES_PORT_START = 20000

	DEFAULT_VALIDATOR_LOAD_TIMEOUT_SECONDS = 20
)

type Blobber struct {
	ctx context.Context

	proxies []*validator_proxy.ValidatorProxy
	cls     []*p2p.BeaconClientPeer

	// Configuration object
	*config.Config

	// Other
	forkDecoder *beacon.ForkDecoder

	// Records
	builtBlocksMap    *BuiltBlocksMap
	includeBlobRecord *common.BlobRecord
	rejectBlobRecord  *common.BlobRecord
}

type BuiltBlocksMap struct {
	BlockRoots map[beacon_common.Slot][32]byte
	sync.RWMutex
}

func init() {
	logrus.SetLevel(logrus.InfoLevel)
}

func NewBlobber(ctx context.Context, opts ...config.Option) (*Blobber, error) {
	b := &Blobber{
		ctx: ctx,

		proxies: make([]*validator_proxy.ValidatorProxy, 0),
		cls:     make([]*p2p.BeaconClientPeer, 0),

		Config: &config.Config{
			TestP2P: &p2p.TestP2P{
				ChainStatus: p2p.NewStatus(),
			},
			Host:             DEFAULT_BLOBBER_HOST,
			Port:             DEFAULT_BLOBBER_PORT,
			ProxiesPortStart: DEFAULT_PROXIES_PORT_START,

			ValidatorLoadTimeoutSeconds: DEFAULT_VALIDATOR_LOAD_TIMEOUT_SECONDS,
		},

		builtBlocksMap: &BuiltBlocksMap{
			BlockRoots: make(map[beacon_common.Slot][32]byte),
		},
		includeBlobRecord: common.NewBlobRecord(),
		rejectBlobRecord:  common.NewBlobRecord(),
	}

	// Apply the options
	if err := b.Config.Apply(opts...); err != nil {
		return nil, errors.Wrap(err, "failed to apply options")
	}

	if b.Spec == nil {
		return nil, fmt.Errorf("no spec configured")
	}
	if b.ProxiesPortStart == 0 {
		return nil, fmt.Errorf("no proxies port start configured")
	}
	if b.GenesisValidatorsRoot == (tree.Root{}) {
		return nil, fmt.Errorf("no genesis validators root configured")
	}
	if b.ExternalIP == nil {
		return nil, fmt.Errorf("no external ip configured")
	}
	if b.BeaconPortStart == 0 {
		b.BeaconPortStart = PortBeaconTCP
	}

	// Create the fork decoder
	b.forkDecoder = beacon.NewForkDecoder(b.Spec, b.GenesisValidatorsRoot)

	return b, nil
}

func (b *Blobber) Address() string {
	return fmt.Sprintf(
		"http://%s:%d",
		b.ExternalIP,
		b.Port,
	)
}

// Return a list of blobs that each proposal action has classified as must-be-included
func (b *Blobber) IncludeBlobRecord() *common.BlobRecord {
	return b.includeBlobRecord
}

// Return a list of blobs that each proposal action has classified as must-be-rejected
func (b *Blobber) RejectBlobRecord() *common.BlobRecord {
	return b.rejectBlobRecord
}

func (b *Blobber) Close() {
	for _, proxy := range b.proxies {
		proxy.Cancel()
	}
}

func (b *Blobber) AddBeaconClient(cl *beacon_client.BeaconClient, validatorProxy bool) *validator_proxy.ValidatorProxy {
	b.cls = append(b.cls, &p2p.BeaconClientPeer{BeaconClient: cl})
	if !validatorProxy {
		return nil
	}
	beaconAPIEndpoint := cl.GetAddress()
	logrus.WithFields(logrus.Fields{
		"beacon_endpoint": beaconAPIEndpoint,
	}).Info("Adding proxy")
	id := len(b.proxies)
	port := b.ProxiesPortStart + id
	proxy, err := validator_proxy.NewProxy(b.ctx, id, b.Host, port, beaconAPIEndpoint,
		map[string]validator_proxy.ResponseCallback{
			"/eth/v2/validator/blocks/{slot}": b.genValidatorBlockHandler(cl, id, 2),
			"/eth/v3/validator/blocks/{slot}": b.genValidatorBlockHandler(cl, id, 3),
		},
		b.AlwaysErrorValidatorResponse,
	)
	if err != nil {
		panic(err)
	}
	b.proxies = append(b.proxies, proxy)

	// Update the validators map
	if b.ValidatorKeys == nil {
		b.ValidatorKeys = make(map[beacon_common.ValidatorIndex]*keys.ValidatorKey)
	}
	validatorResponses, err := b.loadStateValidators(b.ctx, cl, eth2api.StateHead, nil, nil)
	if err != nil {
		panic(err)
	}
	logrus.WithFields(
		logrus.Fields{
			"state_validator_count": validatorResponses,
			"keyed_validator_count": len(b.ValidatorKeys),
		},
	).Info("Loaded validators from beacon node")

	return proxy
}

func (b *Blobber) loadStateValidators(
	parentCtx context.Context,
	bn *beacon_client.BeaconClient,
	stateId eth2api.StateId,
	validatorIds []eth2api.ValidatorId,
	statusFilter []eth2api.ValidatorStatus,
) (int, error) {
	var (
		validatorResponses = make(
			[]eth2api.ValidatorResponse,
			0,
		)
		exists bool
		err    error
	)
	ctx, cancel := context.WithTimeout(
		parentCtx,
		time.Second*time.Duration(b.ValidatorLoadTimeoutSeconds),
	)
	defer cancel()
	exists, err = beaconapi.StateValidators(
		ctx,
		bn.API(),
		stateId,
		validatorIds,
		statusFilter,
		&validatorResponses,
	)
	if !exists {
		return 0, fmt.Errorf("endpoint not found on beacon client")
	}
	if err != nil {
		return 0, errors.Wrap(err, "failed to get validators")
	}

	for _, validatorResponse := range validatorResponses {
		validatorIndex := validatorResponse.Index
		validatorPubkey := validatorResponse.Validator.Pubkey
		for _, key := range b.ValidatorKeysList {
			if bytes.Equal(key.PubKeyToBytes(), validatorPubkey[:]) {
				b.ValidatorKeys[validatorIndex] = key
				break
			}
		}
	}

	return len(validatorResponses), err
}

func (b *Blobber) GetProducedBlockRoots() map[beacon_common.Slot][32]byte {
	b.builtBlocksMap.RLock()
	defer b.builtBlocksMap.RUnlock()
	blockRoots := make(map[beacon_common.Slot][32]byte)
	for slot, blockRoot := range b.builtBlocksMap.BlockRoots {
		blockRoots[slot] = blockRoot
	}
	return blockRoots
}

func (b *Blobber) updateStatus(cl *beacon_client.BeaconClient) error {
	ctx, cancel := context.WithTimeout(b.ctx, time.Second*1)
	defer cancel()
	block, err := cl.BlockV2(ctx, eth2api.BlockHead)
	if err != nil {
		logrus.WithError(err).Error("Failed to get block")
		return errors.Wrap(err, "failed to get block")
	}

	// Update the chainstate
	b.ChainStatus.SetHead(block.Root(), block.Slot())

	// Update the fork digest
	b.ChainStatus.SetForkDigest(b.forkDecoder.ForkDigest(b.Spec.SlotToEpoch(block.Slot())))

	return nil
}

func (b *Blobber) calcBeaconBlockDomain(slot beacon_common.Slot) beacon_common.BLSDomain {
	return beacon_common.ComputeDomain(
		beacon_common.DOMAIN_BEACON_PROPOSER,
		b.Spec.ForkVersion(slot),
		b.GenesisValidatorsRoot,
	)
}

func (b *Blobber) executeProposalActions(trigger_cl *beacon_client.BeaconClient, blResponse *deneb.BlockContents, validatorKey *keys.ValidatorKey) (bool, error) {
	b.Lock()
	proposalAction := b.ProposalAction
	b.Unlock()

	if proposalAction == nil {
		logrus.WithFields(logrus.Fields{
			"slot": uint64(blResponse.Block.Slot),
		}).Info("No proposal action configured")
		return false, nil
	}

	// Check the frequency
	if proposalAction.Frequency() > 1 && uint64(blResponse.Block.Slot)%proposalAction.Frequency() != 0 {
		logrus.WithFields(logrus.Fields{
			"slot":      uint64(blResponse.Block.Slot),
			"frequency": proposalAction.Frequency(),
		}).Info("Skipping proposal action due to configured frequency")
		return false, nil
	}

	// Check the max execution times
	if proposalAction.MaxExecutionTimes() > 0 && proposalAction.TimesExecuted() >= proposalAction.MaxExecutionTimes() {
		logrus.WithFields(logrus.Fields{
			"slot":             uint64(blResponse.Block.Slot),
			"max_execution":    proposalAction.MaxExecutionTimes(),
			"times_executed":   proposalAction.TimesExecuted(),
			"action_frequency": proposalAction.Frequency(),
		}).Info("Skipping proposal action due to max execution times")
		return false, nil
	}

	// Log the proposal action
	proposalActionFields := logrus.Fields(proposalAction.Fields())
	if len(proposalActionFields) > 0 {
		logrus.WithFields(proposalActionFields).Info("Action configuration")
	}

	// Check whether the proposal action should be executed
	if canExec, reason := proposalAction.CanExecute(b.Spec, blResponse); !canExec {
		logrus.WithFields(logrus.Fields{
			"slot":   uint64(blResponse.Block.Slot),
			"reason": reason,
		}).Info("Skipping proposal action")
		return false, nil
	}

	testPeerCount := proposalAction.GetTestPeerCount()

	// Peer with the beacon nodes and broadcast the block and blobs
	testPeers, err := b.GetTestPeer(b.ctx, testPeerCount)
	if err != nil {
		return false, errors.Wrap(err, "failed to create p2p")
	} else if len(testPeers) != testPeerCount {
		return false, fmt.Errorf("failed to create p2p, expected %d, got %d", testPeerCount, len(testPeers))
	}
	for i, testPeer := range testPeers {
		logrus.WithFields(logrus.Fields{
			"index":   i,
			"peer_id": testPeer.Host.ID().String(),
		}).Debug("Created test p2p")
	}

	// Connect to the beacon nodes
	for i, cl := range b.cls {
		testPeer := testPeers[i%len(testPeers)]
		if err := testPeer.Connect(b.ctx, cl); err != nil {
			return false, errors.Wrap(err, "failed to connect to beacon node")
		}
	}

	// Log current action info
	blockRoot := blResponse.Block.HashTreeRoot(b.Spec, tree.GetHashFn())
	logrus.WithFields(logrus.Fields{
		"slot":              blResponse.Block.Slot,
		"block_root":        blockRoot.String(),
		"parent_block_root": blResponse.Block.ParentRoot.String(),
		"blob_count":        len(blResponse.Blobs),
		"action_name":       proposalAction.Name(),
	}).Info("Preparing action for block and blobs")

	calcBeaconBlockDomain := b.calcBeaconBlockDomain(blResponse.Block.Slot)
	executed, err := proposalAction.Execute(
		b.Spec,
		testPeers,
		blResponse,
		calcBeaconBlockDomain,
		validatorKey,
		b.includeBlobRecord,
		b.rejectBlobRecord,
	)
	if executed && err == nil {
		b.builtBlocksMap.Lock()
		b.builtBlocksMap.BlockRoots[blResponse.Block.Slot] = blockRoot
		b.builtBlocksMap.Unlock()
		b.ProposalAction.IncrementTimesExecuted()
	}
	return executed, errors.Wrap(err, "failed to execute proposal action")
}

func (b *Blobber) genValidatorBlockHandler(cl *beacon_client.BeaconClient, id int, version int) validator_proxy.ResponseCallback {
	return func(request *http.Request, response []byte) (bool, error) {
		var slot beacon_common.Slot
		if err := slot.UnmarshalJSON([]byte(mux.Vars(request)["slot"])); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal slot")
		}
		blockVersion, blockBlobResponse, err := ParseResponse(response)
		if err != nil || blockBlobResponse == nil {
			logrus.WithFields(logrus.Fields{
				"proxy_id":   id,
				"version":    version,
				"slot":       slot,
				"requestURL": request.URL.String(),
				"response":   string(response),
			}).Debug("Failed to parse response")
			if err != nil {
				return false, errors.Wrap(err, "failed to parse response")
			}
			return false, errors.New("failed to parse response")
		}
		var validatorKey *keys.ValidatorKey
		if b.ValidatorKeys != nil {
			validatorKey = b.ValidatorKeys[blockBlobResponse.Block.ProposerIndex]
		}
		logrus.WithFields(logrus.Fields{
			"proxy_id":               id,
			"endpoint":               request.URL.Path,
			"endpoint_method":        request.Method,
			"version":                version,
			"slot":                   slot,
			"block_version":          blockVersion,
			"blob_count":             len(blockBlobResponse.Blobs),
			"proposer_index":         blockBlobResponse.Block.ProposerIndex,
			"proposer_key_available": validatorKey != nil,
		}).Debug("Received response")

		// Update the chainstate
		if err := b.updateStatus(cl); err != nil {
			logrus.WithError(err).Error("Failed to update chain status")
			return false, errors.Wrap(err, "failed to update chain status")
		}

		// Execute the proposal actions
		if validatorKey == nil {
			logrus.Warn("No validator key found, skipping proposal actions")
			return false, errors.Wrap(err, "no validator key found, skipping proposal actions")
		}
		override, err := b.executeProposalActions(cl, blockBlobResponse, validatorKey)
		if err != nil {
			logrus.WithError(err).Error("Failed to execute proposal actions")
		}
		return override, errors.Wrap(err, "failed to execute proposal actions")
	}
}

type BlockDataStruct struct {
	Version *string          `json:"version"`
	Data    *json.RawMessage `json:"data"`
}

func ParseResponse(response []byte) (string, *deneb.BlockContents, error) {
	var (
		blockDataStruct BlockDataStruct
	)
	if err := json.Unmarshal(response, &blockDataStruct); err != nil || blockDataStruct.Version == nil || blockDataStruct.Data == nil {
		return "", nil, errors.Wrap(err, "failed to unmarshal response into BlockDataStruct")
	}

	if *blockDataStruct.Version != "deneb" {
		logrus.WithField("version", blockDataStruct.Version).Warn("Unsupported version, skipping actions")
		logrus.WithField("response", string(response)).Debug("Unsupported version, skipping actions")
		return *blockDataStruct.Version, nil, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(*blockDataStruct.Data))
	data := new(deneb.BlockContents)
	if err := decoder.Decode(&data); err != nil {
		return *blockDataStruct.Version, nil, errors.Wrap(err, "failed to decode block contents")
	}

	return *blockDataStruct.Version, data, nil
}
