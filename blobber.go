package blobber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/gorilla/mux"
	"github.com/marioevz/blobber/api"
	"github.com/marioevz/blobber/beacon"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/config"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/validator_proxy"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	PortBeaconTCP    = 9000
	PortBeaconUDP    = 9000
	PortBeaconAPI    = 4000
	PortBeaconGRPC   = 4001
	PortMetrics      = 8080
	PortValidatorAPI = 5000
	FarFutureEpoch   = phase0.Epoch(0xffffffffffffffff)

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
	// Note: ForkDecoder is not needed with go-eth2-client

	// Records
	builtBlocksMap    *BuiltBlocksMap
	includeBlobRecord *common.BlobRecord
	rejectBlobRecord  *common.BlobRecord
}

type BuiltBlocksMap struct {
	BlockRoots map[phase0.Slot][32]byte
	sync.RWMutex
}

func init() {
	logrus.SetLevel(logrus.InfoLevel)
}

func NewBlobber(ctx context.Context, opts ...config.Option) (*Blobber, error) {
	logrus.Info("Creating new Blobber instance")
	logrus.Infof("Number of options to apply: %d", len(opts))
	
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
			BlockRoots: make(map[phase0.Slot][32]byte),
		},
		includeBlobRecord: common.NewBlobRecord(),
		rejectBlobRecord:  common.NewBlobRecord(),
	}

	logrus.Info("Applying configuration options...")
	// Apply the options
	if err := b.Config.Apply(opts...); err != nil {
		logrus.Errorf("Failed to apply options: %v", err)
		return nil, errors.Wrap(err, "failed to apply options")
	}
	logrus.Info("Successfully applied all configuration options")

	if b.Spec == nil {
		return nil, fmt.Errorf("no spec configured")
	}
	if b.ProxiesPortStart == 0 {
		return nil, fmt.Errorf("no proxies port start configured")
	}
	if b.GenesisValidatorsRoot == (phase0.Root{}) {
		return nil, fmt.Errorf("no genesis validators root configured")
	}
	if b.ExternalIP == nil {
		return nil, fmt.Errorf("no external ip configured")
	}
	if b.BeaconPortStart == 0 {
		b.BeaconPortStart = PortBeaconTCP
	}

	// Note: ForkDecoder is not needed with go-eth2-client
	// Fork digest calculation is handled differently

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

func (b *Blobber) AddBeaconClient(cl *beacon.BeaconClientAdapter, validatorProxy bool) *validator_proxy.ValidatorProxy {
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
		b.ValidatorKeys = make(map[phase0.ValidatorIndex]*keys.ValidatorKey)
	}
	validatorResponses, err := b.loadStateValidators(b.ctx, cl, api.StateHead, nil, nil)
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
	bn *beacon.BeaconClientAdapter,
	stateId api.StateId,
	validatorIds []api.ValidatorId,
	statusFilter []api.ValidatorStatus,
) (int, error) {
	ctx, cancel := context.WithTimeout(
		parentCtx,
		time.Second*time.Duration(b.ValidatorLoadTimeoutSeconds),
	)
	defer cancel()

	// Use the GetStateValidators function from api package
	// Convert beacon types to api types
	apiStateId := api.StateId(stateId)
	apiValidatorIds := make([]api.ValidatorId, len(validatorIds))
	for i, id := range validatorIds {
		apiValidatorIds[i] = api.ValidatorId(id)
	}
	apiStatusFilter := make([]api.ValidatorStatus, len(statusFilter))
	for i, status := range statusFilter {
		apiStatusFilter[i] = api.ValidatorStatus(status)
	}

	validatorResponses, err := api.GetStateValidators(
		ctx,
		bn,
		apiStateId,
		apiValidatorIds,
		apiStatusFilter,
	)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get validators")
	}

	for _, validatorResponse := range validatorResponses {
		validatorIndex := validatorResponse.Index
		validatorPubkey := validatorResponse.Validator.Pubkey
		for _, key := range b.ValidatorKeysList {
			if bytes.Equal(key.PubKeyToBytes(), validatorPubkey[:]) {
				b.ValidatorKeys[phase0.ValidatorIndex(validatorIndex)] = key
				break
			}
		}
	}

	return len(validatorResponses), nil
}

func (b *Blobber) GetProducedBlockRoots() map[phase0.Slot][32]byte {
	b.builtBlocksMap.RLock()
	defer b.builtBlocksMap.RUnlock()
	blockRoots := make(map[phase0.Slot][32]byte)
	for slot, blockRoot := range b.builtBlocksMap.BlockRoots {
		blockRoots[slot] = blockRoot
	}
	return blockRoots
}

func (b *Blobber) updateStatus(cl *beacon.BeaconClientAdapter) error {
	ctx, cancel := context.WithTimeout(b.ctx, time.Second*1)
	defer cancel()
	// cl is already a *beacon.BeaconClient, not an interface

	block, err := cl.BlockV2(ctx, beacon.BlockHead)
	if err != nil {
		logrus.WithError(err).Error("Failed to get block")
		return errors.Wrap(err, "failed to get block")
	}

	// Update the chainstate
	blockRoot := phase0.Root(block.Root())
	b.ChainStatus.SetHead(blockRoot, phase0.Slot(block.Slot()))

	// Update the fork digest
	forkVersion, err := common.GetForkVersion(b.Spec, block.Slot())
	if err != nil {
		logrus.WithError(err).Warn("Failed to get fork version")
	} else {
		forkDigest, err := common.ComputeForkDigest(forkVersion, b.GenesisValidatorsRoot)
		if err != nil {
			logrus.WithError(err).Warn("Failed to compute fork digest")
		} else {
			b.ChainStatus.SetForkDigest(forkDigest)
		}
	}

	return nil
}

func (b *Blobber) calcBeaconBlockDomain(slot phase0.Slot) phase0.Domain {
	// Get domain type for beacon proposer
	domainType, err := common.GetDomainType(b.Spec, "DOMAIN_BEACON_PROPOSER")
	if err != nil {
		logrus.WithError(err).Error("Failed to get domain type")
		return phase0.Domain{}
	}
	
	// Get fork version for the slot
	forkVersion, err := common.GetForkVersion(b.Spec, slot)
	if err != nil {
		logrus.WithError(err).Error("Failed to get fork version")
		return phase0.Domain{}
	}
	
	// Compute domain
	return common.ComputeDomain(domainType, forkVersion, b.GenesisValidatorsRoot)
}

func (b *Blobber) executeProposalActions(trigger_cl *beacon.BeaconClientAdapter, blResponse *common.VersionedBlockContents, validatorKey *keys.ValidatorKey) (bool, error) {
	b.Lock()
	proposalAction := b.ProposalAction
	b.Unlock()

	if proposalAction == nil {
		logrus.WithFields(logrus.Fields{
			"slot": uint64(blResponse.GetSlot()),
		}).Info("No proposal action configured")
		return false, nil
	}

	// Check the frequency
	if proposalAction.Frequency() > 1 && uint64(blResponse.GetSlot())%proposalAction.Frequency() != 0 {
		logrus.WithFields(logrus.Fields{
			"slot":      uint64(blResponse.GetSlot()),
			"frequency": proposalAction.Frequency(),
		}).Info("Skipping proposal action due to configured frequency")
		return false, nil
	}

	// Check the max execution times
	if proposalAction.MaxExecutionTimes() > 0 && proposalAction.TimesExecuted() >= proposalAction.MaxExecutionTimes() {
		logrus.WithFields(logrus.Fields{
			"slot":             uint64(blResponse.GetSlot()),
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

	// Convert versioned block to Deneb format for proposal actions
	denebBlock := common.ConvertVersionedToDeneb(blResponse)
	if denebBlock == nil {
		logrus.Error("Failed to convert block to Deneb format")
		return false, errors.New("failed to convert block")
	}
	
	// Check whether the proposal action should be executed
	if canExec, reason := proposalAction.CanExecute(b.Spec, denebBlock); !canExec {
		logrus.WithFields(logrus.Fields{
			"slot":   uint64(blResponse.GetSlot()),
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
	blockRoot, err := denebBlock.Block.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "failed to calculate block root")
	}
	logrus.WithFields(logrus.Fields{
		"slot":              blResponse.GetSlot(),
		"block_root":        fmt.Sprintf("%#x", blockRoot),
		"parent_block_root": fmt.Sprintf("%#x", denebBlock.Block.ParentRoot),
		"blob_count":        blResponse.GetBlobsCount(),
		"action_name":       proposalAction.Name(),
	}).Info("Preparing action for block and blobs")

	calcBeaconBlockDomain := b.calcBeaconBlockDomain(blResponse.GetSlot())
	executed, err := proposalAction.Execute(
		b.Spec,
		testPeers,
		denebBlock,
		calcBeaconBlockDomain,
		validatorKey,
		b.includeBlobRecord,
		b.rejectBlobRecord,
	)
	if executed && err == nil {
		b.builtBlocksMap.Lock()
		b.builtBlocksMap.BlockRoots[blResponse.GetSlot()] = blockRoot
		b.builtBlocksMap.Unlock()
		b.ProposalAction.IncrementTimesExecuted()
	}
	return executed, errors.Wrap(err, "failed to execute proposal action")
}

func (b *Blobber) genValidatorBlockHandler(cl *beacon.BeaconClientAdapter, id int, version int) validator_proxy.ResponseCallback {
	return func(request *http.Request, response []byte) (bool, error) {
		var slot phase0.Slot
		if err := slot.UnmarshalJSON([]byte(mux.Vars(request)["slot"])); err != nil {
			return false, errors.Wrap(err, "failed to unmarshal slot")
		}
		blockBlobResponse, err := ParseResponse(response)
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
		
		// Skip if not Deneb or Electra
		if blockBlobResponse.Version != "deneb" && blockBlobResponse.Version != "electra" {
			logrus.WithField("version", blockBlobResponse.Version).Info("Skipping non-blob version")
			return false, nil
		}
		
		var validatorKey *keys.ValidatorKey
		if b.ValidatorKeys != nil {
			validatorKey = b.ValidatorKeys[blockBlobResponse.GetProposerIndex()]
		}
		logrus.WithFields(logrus.Fields{
			"proxy_id":               id,
			"endpoint":               request.URL.Path,
			"endpoint_method":        request.Method,
			"version":                version,
			"slot":                   slot,
			"block_version":          blockBlobResponse.Version,
			"blob_count":             blockBlobResponse.GetBlobsCount(),
			"proposer_index":         blockBlobResponse.GetProposerIndex(),
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

func ParseResponse(response []byte) (*common.VersionedBlockContents, error) {
	var blockDataStruct BlockDataStruct
	if err := json.Unmarshal(response, &blockDataStruct); err != nil || blockDataStruct.Version == nil || blockDataStruct.Data == nil {
		return nil, errors.Wrap(err, "failed to unmarshal response into BlockDataStruct")
	}

	version := *blockDataStruct.Version
	decoder := json.NewDecoder(bytes.NewReader(*blockDataStruct.Data))
	
	switch version {
	case "deneb":
		data := new(apiv1deneb.BlockContents)
		if err := decoder.Decode(&data); err != nil {
			return nil, errors.Wrap(err, "failed to decode deneb block contents")
		}
		return &common.VersionedBlockContents{
			Version: version,
			Deneb:   data,
		}, nil
		
	case "electra":
		data := new(apiv1electra.BlockContents)
		if err := decoder.Decode(&data); err != nil {
			return nil, errors.Wrap(err, "failed to decode electra block contents")
		}
		return &common.VersionedBlockContents{
			Version: version,
			Electra: data,
		}, nil
		
	default:
		logrus.WithField("version", version).Warn("Unsupported version, skipping actions")
		logrus.WithField("response", string(response)).Debug("Unsupported version, skipping actions")
		return &common.VersionedBlockContents{Version: version}, nil
	}
}
