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
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/slot_actions"
	"github.com/marioevz/blobber/validator_proxy"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	"github.com/pkg/errors"
	"github.com/protolambda/eth2api"
	"github.com/protolambda/eth2api/client/beaconapi"
	"github.com/protolambda/zrnt/eth2/beacon"
	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/rpc/eth/shared"
	"github.com/sirupsen/logrus"

	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
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
	builtBlocksMap *BuiltBlocksMap
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
				ChainStatus: common.NewStatus(),
			},
			Host:             DEFAULT_BLOBBER_HOST,
			Port:             DEFAULT_BLOBBER_PORT,
			ProxiesPortStart: DEFAULT_PROXIES_PORT_START,

			ValidatorLoadTimeoutSeconds: DEFAULT_VALIDATOR_LOAD_TIMEOUT_SECONDS,
		},

		builtBlocksMap: &BuiltBlocksMap{
			BlockRoots: make(map[beacon_common.Slot][32]byte),
		},
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
		b.ValidatorKeys = make(map[beacon_common.ValidatorIndex]*config.ValidatorKey)
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
			if bytes.Equal(key.ValidatorPubkey[:], validatorPubkey[:]) {
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

func (b *Blobber) getSlotAction(slot uint64) (slot_actions.SlotAction, error) {
	var slotAction slot_actions.SlotAction

	b.Lock()
	defer b.Unlock()

	if b.SlotAction != nil {
		if b.SlotActionFrequency <= 1 || slot%b.SlotActionFrequency == 0 {
			slotAction = b.SlotAction
		}
	}

	if slotAction == nil {
		slotAction = slot_actions.Default{}
	}

	return slotAction, nil
}

func (b *Blobber) calcBeaconBlockDomain(slot beacon_common.Slot) beacon_common.BLSDomain {
	return beacon_common.ComputeDomain(
		beacon_common.DOMAIN_BEACON_PROPOSER,
		b.Spec.ForkVersion(slot),
		b.GenesisValidatorsRoot,
	)
}

func (b *Blobber) calcBlobSidecarDomain(slot beacon_common.Slot) beacon_common.BLSDomain {
	b.Spec.ForkVersion(slot)
	return beacon_common.ComputeDomain(
		beacon_common.DOMAIN_BLOB_SIDECAR,
		b.Spec.ForkVersion(slot),
		b.GenesisValidatorsRoot,
	)
}

func (b *Blobber) executeSlotActions(trigger_cl *beacon_client.BeaconClient, blResponse *eth.BeaconBlockAndBlobsDeneb, proposerKey *config.ValidatorKey) (bool, error) {
	// Log current action info
	blockRoot, err := blResponse.Block.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "failed to get block hash tree root")
	}
	logrus.WithFields(logrus.Fields{
		"slot":              blResponse.Block.Slot,
		"block_root":        fmt.Sprintf("%x", blockRoot),
		"parent_block_root": fmt.Sprintf("%x", blResponse.Block.ParentRoot),
		"blob_count":        len(blResponse.Blobs),
	}).Info("Preparing action for block and blobs")

	slotAction, err := b.getSlotAction(uint64(blResponse.Block.Slot))
	if err != nil {
		return false, errors.Wrap(err, "failed to get slot action")
	}
	if slotAction == nil {
		panic("slot action is nil")
	}

	testPeerCount := slotAction.GetTestPeerCount()

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

	calcBeaconBlockDomain := b.calcBeaconBlockDomain(beacon_common.Slot(blResponse.Block.Slot))
	blobSidecarDomain := b.calcBlobSidecarDomain(beacon_common.Slot(blResponse.Block.Slot))
	executed, err := slotAction.Execute(testPeers, blResponse.Block, calcBeaconBlockDomain, blResponse.Blobs, blobSidecarDomain, &proposerKey.ValidatorSecretKey)
	if executed {
		b.builtBlocksMap.Lock()
		b.builtBlocksMap.BlockRoots[beacon_common.Slot(blResponse.Block.Slot)] = blockRoot
		b.builtBlocksMap.Unlock()
	}
	return executed, errors.Wrap(err, "failed to execute slot action")
}

func (b *Blobber) genValidatorBlockHandler(cl *beacon_client.BeaconClient, id int, version int) validator_proxy.ResponseCallback {
	return func(request *http.Request, response []byte) (bool, error) {
		var slot beacon_common.Slot
		if err := slot.UnmarshalJSON([]byte(mux.Vars(request)["slot"])); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal slot")
		}
		blockVersion, blockBlobResponse, err := ParseResponse(response)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"proxy_id": id,
				"version":  version,
				"slot":     slot,
				"response": string(response),
			}).Debug("Failed to parse response")
			return false, errors.Wrap(err, "failed to parse response")
		}
		if blockBlobResponse == nil {
			return false, errors.Wrap(err, "response is nil")
		}
		var validatorKey *config.ValidatorKey
		if b.ValidatorKeys != nil {
			validatorKey = b.ValidatorKeys[beacon_common.ValidatorIndex(blockBlobResponse.Block.ProposerIndex)]
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

		// Execute the slot actions
		if validatorKey == nil {
			logrus.Warn("No validator key found, skipping slot actions")
			return false, errors.Wrap(err, "no validator key found, skipping slot actions")
		}
		override, err := b.executeSlotActions(cl, blockBlobResponse, validatorKey)
		if err != nil {
			logrus.WithError(err).Error("Failed to execute slot actions")
		}
		return override, errors.Wrap(err, "failed to execute slot actions")
	}
}

type BlockDataStruct struct {
	Version string          `json:"version"`
	Data    json.RawMessage `json:"data"`
}

func ParseResponse(response []byte) (string, *eth.BeaconBlockAndBlobsDeneb, error) {
	var (
		blockDataStruct BlockDataStruct
		err             error
	)
	if err := json.Unmarshal(response, &blockDataStruct); err != nil {
		return blockDataStruct.Version, nil, errors.Wrap(err, "failed to unmarshal response into BlockDataStruct")
	}

	if blockDataStruct.Version != "deneb" {
		logrus.WithField("version", blockDataStruct.Version).Warn("Unsupported version, skipping actions")
		return blockDataStruct.Version, nil, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(blockDataStruct.Data))
	data := new(shared.BeaconBlockContentsDeneb)
	if err := decoder.Decode(&data); err != nil {
		return blockDataStruct.Version, nil, errors.Wrap(err, "failed to decode block contents")
	}

	beaconBlockContents := new(eth.BeaconBlockAndBlobsDeneb)

	beaconBlockContents.Block, err = data.Block.ToConsensus()
	if err != nil {
		return blockDataStruct.Version, nil, err
	}
	beaconBlockContents.Blobs = make([]*eth.BlobSidecar, len(data.BlobSidecars))
	for i, blob := range data.BlobSidecars {
		beaconBlockContents.Blobs[i], err = blob.ToConsensus()
		if err != nil {
			return blockDataStruct.Version, nil, err
		}
	}

	return blockDataStruct.Version, beaconBlockContents, nil
}
