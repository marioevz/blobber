package blobber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"

	"github.com/marioevz/blobber/beacon"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/config"
	blobberrors "github.com/marioevz/blobber/errors"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/logger"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/validator_proxy"
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
	ctx    context.Context
	logger logger.Logger

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
	
	// Track slots we've already processed to avoid duplicate execution
	processedSlots sync.Map
}

type BuiltBlocksMap struct {
	BlockRoots map[phase0.Slot][32]byte
	sync.RWMutex
}

func NewBlobber(ctx context.Context, log logger.Logger, opts ...config.Option) (*Blobber, error) {
	if log == nil {
		log = logger.New()
	}

	log.Info("Creating new Blobber instance")
	log.Infof("Number of options to apply: %d", len(opts))

	b := &Blobber{
		ctx:    ctx,
		logger: log,

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

	log.Info("Applying configuration options...")

	// Apply the options
	if err := b.Config.Apply(opts...); err != nil {
		log.Errorf("Failed to apply options: %v", err)

		// Check if this is the specific error we're seeing
		if strings.Contains(err.Error(), "cannot set ProposalActionFrequency without ProposalAction") {
			fmt.Fprintf(os.Stderr, "\n!!! KNOWN ISSUE DETECTED !!!\n")
			fmt.Fprintf(os.Stderr, "This error occurs when proposal action parameters are not passed correctly.\n")
			fmt.Fprintf(os.Stderr, "Check that blobber_extra_params in your Kurtosis YAML includes:\n")
			fmt.Fprintf(os.Stderr, "  - '--proposal-action={\"name\": \"blob_gossip_delay\", \"delay_milliseconds\": 1500}'\n")
			fmt.Fprintf(os.Stderr, "  - '--proposal-action-frequency=1'\n")
			fmt.Fprintf(os.Stderr, "\nCurrent command line args: %v\n", os.Args)
		}

		return nil, errors.Wrap(err, "failed to apply options")
	}
	log.Info("Successfully applied all configuration options")

	if b.Spec == nil {
		return nil, blobberrors.ErrNoSpecConfigured
	}
	if b.ProxiesPortStart == 0 {
		return nil, blobberrors.ErrNoProxiesPortConfigured
	}
	if b.GenesisValidatorsRoot == (phase0.Root{}) {
		return nil, blobberrors.ErrNoGenesisValidatorsRoot
	}
	if b.ExternalIP == nil {
		return nil, blobberrors.ErrNoExternalIPConfigured
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

func (b *Blobber) Close(ctx context.Context) error {
	for _, proxy := range b.proxies {
		proxy.Cancel()
	}
	return nil
}

func (b *Blobber) AddBeaconClient(cl *beacon.BeaconClientAdapter, validatorProxy bool) *validator_proxy.ValidatorProxy {
	b.cls = append(b.cls, &p2p.BeaconClientPeer{BeaconClient: cl})
	if !validatorProxy {
		return nil
	}
	beaconAPIEndpoint := cl.GetAddress()
	b.logger.WithFields(map[string]interface{}{
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
	validatorCount, err := b.loadStateValidators(b.ctx, cl, beacon.StateId("head"), nil, nil)
	if err != nil {
		b.logger.WithFields(map[string]interface{}{
			"error": err,
		}).Error("Failed to load validators from beacon node")
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load validators: %v\n", err)
		panic(err)
	}
	b.logger.WithFields(map[string]interface{}{
		"state_validator_count": validatorCount,
		"keyed_validator_count": len(b.ValidatorKeys),
	}).Info("Loaded validators from beacon node")

	return proxy
}

func (b *Blobber) loadStateValidators(
	parentCtx context.Context,
	bn *beacon.BeaconClientAdapter,
	stateId beacon.StateId,
	validatorIds []beacon.ValidatorId,
	statusFilter []beacon.ValidatorStatus,
) (int, error) {
	ctx, cancel := context.WithTimeout(
		parentCtx,
		time.Second*time.Duration(b.ValidatorLoadTimeoutSeconds),
	)
	defer cancel()

	// Use the beacon adapter's StateValidators method which already handles proper types
	validatorResponses, err := bn.StateValidators(
		ctx,
		stateId,
		validatorIds,
		statusFilter,
	)
	if err != nil {
		return 0, errors.Wrap(err, "failed to get validators")
	}

	for _, validatorResponse := range validatorResponses {
		// Index is already a phase0.ValidatorIndex
		validatorIndex := validatorResponse.Index
		validatorPubkey := validatorResponse.Validator.PublicKey
		for _, key := range b.ValidatorKeysList {
			if bytes.Equal(key.PubKeyToBytes(), validatorPubkey[:]) {
				b.ValidatorKeys[validatorIndex] = key
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
		b.logger.WithField("error", err).Error("Failed to get block")
		return blobberrors.NewBeaconClientError("BlockV2", cl.GetAddress(), err)
	}

	// Update the chainstate
	blockRoot := phase0.Root(block.Root())
	b.ChainStatus.SetHead(blockRoot, phase0.Slot(block.Slot()))

	// Update the fork digest
	forkVersion, err := common.GetForkVersion(b.Spec, block.Slot())
	if err != nil {
		b.logger.WithField("error", err).Warn("Failed to get fork version")
	} else {
		forkDigest, err := common.ComputeForkDigest(forkVersion, b.GenesisValidatorsRoot)
		if err != nil {
			b.logger.WithField("error", err).Warn("Failed to compute fork digest")
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
		b.logger.WithField("error", err).Error("Failed to get domain type")
		return phase0.Domain{}
	}

	// Get fork version for the slot
	forkVersion, err := common.GetForkVersion(b.Spec, slot)
	if err != nil {
		b.logger.WithField("error", err).Error("Failed to get fork version")
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
		b.logger.WithFields(map[string]interface{}{
			"slot": uint64(blResponse.GetSlot()),
		}).Info("No proposal action configured")
		return false, nil
	}

	// Check the frequency
	if proposalAction.Frequency() > 1 && uint64(blResponse.GetSlot())%proposalAction.Frequency() != 0 {
		b.logger.WithFields(map[string]interface{}{
			"slot":      uint64(blResponse.GetSlot()),
			"frequency": proposalAction.Frequency(),
		}).Info("Skipping proposal action due to configured frequency")
		return false, nil
	}

	// Check the max execution times
	if proposalAction.MaxExecutionTimes() > 0 && proposalAction.TimesExecuted() >= proposalAction.MaxExecutionTimes() {
		b.logger.WithFields(map[string]interface{}{
			"slot":             uint64(blResponse.GetSlot()),
			"max_execution":    proposalAction.MaxExecutionTimes(),
			"times_executed":   proposalAction.TimesExecuted(),
			"action_frequency": proposalAction.Frequency(),
		}).Info("Skipping proposal action due to max execution times")
		return false, nil
	}

	// Log the proposal action
	proposalActionFields := proposalAction.Fields()
	if len(proposalActionFields) > 0 {
		b.logger.WithFields(proposalActionFields).Info("Action configuration")
	}

	// Convert versioned block to Deneb format for proposal actions
	denebBlock := common.ConvertVersionedToDeneb(blResponse)
	if denebBlock == nil {
		b.logger.Error("Failed to convert block to Deneb format")
		return false, blobberrors.ErrBlockConversionFailed
	}

	// Check whether the proposal action should be executed
	if canExec, reason := proposalAction.CanExecute(b.Spec, denebBlock); !canExec {
		b.logger.WithFields(map[string]interface{}{
			"slot":   uint64(blResponse.GetSlot()),
			"reason": reason,
		}).Info("Skipping proposal action")
		return false, nil
	}

	testPeerCount := proposalAction.GetTestPeerCount()

	// Try to create P2P peers if needed
	var testPeers p2p.TestPeers
	if testPeerCount > 0 {
		// Peer with the beacon nodes and broadcast the block and blobs
		var err error
		testPeers, err = b.TestP2P.GetTestPeer(b.ctx, testPeerCount)
		if err != nil {
			b.logger.WithField("error", err).Warn("Failed to create P2P test peers, continuing without P2P support")
			// Create empty test peers array to continue
			testPeers = make(p2p.TestPeers, 0)
		} else if len(testPeers) != testPeerCount {
			b.logger.WithFields(map[string]interface{}{
				"expected": testPeerCount,
				"got":      len(testPeers),
			}).Warn("Did not get expected number of test peers")
		} else {
			for i, testPeer := range testPeers {
				b.logger.WithFields(map[string]interface{}{
					"index":   i,
					"peer_id": testPeer.Host.ID().String(),
				}).Debug("Created test p2p")
			}

			// Connect to the beacon nodes
			connectedCount := 0
			for i, cl := range b.cls {
				testPeer := testPeers[i%len(testPeers)]
				// Always try to connect/reconnect to ensure fresh connection
				if err := testPeer.Connect(b.ctx, cl); err != nil {
					// Log the error but continue with other connections
					b.logger.WithFields(map[string]interface{}{
						"error":           err,
						"beacon_index":    i,
						"test_peer_index": i % len(testPeers),
					}).Warn("Failed to connect to beacon node via P2P")
				} else {
					connectedCount++
				}
			}
			b.logger.WithFields(map[string]interface{}{
				"connected":     connectedCount,
				"total_beacons": len(b.cls),
			}).Info("P2P connection summary")
		}
	}

	// Log current action info
	blockRoot, err := denebBlock.Block.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(blobberrors.ErrBlockRootCalculation, err.Error())
	}
	b.logger.WithFields(map[string]interface{}{
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
		// Extract slot from URL path
		// URL format: /eth/v2/validator/blocks/{slot} or /eth/v3/validator/blocks/{slot}
		pathParts := strings.Split(request.URL.Path, "/")
		if len(pathParts) < 6 {
			return false, fmt.Errorf("invalid URL path: %s", request.URL.Path)
		}
		slotStr := pathParts[len(pathParts)-1] // Last part should be the slot

		slotUint, err := strconv.ParseUint(slotStr, 10, 64)
		if err != nil {
			return false, errors.Wrap(err, "failed to parse slot from URL")
		}
		slot := phase0.Slot(slotUint)
		blockBlobResponse, err := ParseResponse(response)
		if err != nil || blockBlobResponse == nil {
			b.logger.WithFields(map[string]interface{}{
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
			b.logger.WithField("version", blockBlobResponse.Version).Info("Skipping non-blob version")
			return false, nil
		}

		var validatorKey *keys.ValidatorKey
		if b.ValidatorKeys != nil {
			validatorKey = b.ValidatorKeys[blockBlobResponse.GetProposerIndex()]
		}
		b.logger.WithFields(map[string]interface{}{
			"proxy_id":               id,
			"endpoint":               request.URL.Path,
			"endpoint_method":        request.Method,
			"version":                version,
			"slot":                   slot,
			"block_version":          blockBlobResponse.Version,
			"blob_count":             blockBlobResponse.GetBlobsCount(),
			"proposer_index":         blockBlobResponse.GetProposerIndex(),
			"proposer_key_available": validatorKey != nil,
			"request_id":             request.Header.Get("X-Request-ID"),
		}).Info("Processing validator block request")

		// Update the chainstate
		if err := b.updateStatus(cl); err != nil {
			b.logger.WithField("error", err).Error("Failed to update chain status")
			return false, blobberrors.NewBeaconClientError("updateStatus", cl.GetAddress(), err)
		}

		// Check if we've already processed this slot to avoid duplicate execution
		// This can happen when validators are configured with multiple beacon endpoints
		slotKey := fmt.Sprintf("%d", slot)
		if _, exists := b.processedSlots.LoadOrStore(slotKey, true); exists {
			b.logger.WithFields(map[string]interface{}{
				"slot": slot,
				"proxy_id": id,
			}).Info("Slot already processed by another proxy, skipping proposal actions")
			return false, nil
		}
		
		// Clean up old slots (keep only last 32 slots)
		if slotUint > 32 {
			oldSlotKey := fmt.Sprintf("%d", slotUint-32)
			b.processedSlots.Delete(oldSlotKey)
		}
		
		// Execute the proposal actions
		if validatorKey == nil {
			b.logger.Warn("No validator key found, skipping proposal actions")
			// Let the block proceed without modification
			return false, nil
		}
		override, err := b.executeProposalActions(cl, blockBlobResponse, validatorKey)
		if err != nil {
			b.logger.WithFields(map[string]interface{}{
				"error": err,
				"slot": blockBlobResponse.GetSlot(),
				"always_error": b.AlwaysErrorValidatorResponse,
			}).Error("Failed to execute proposal actions")
			
			// Check if we should fail block production on errors
			if b.AlwaysErrorValidatorResponse {
				// Fail block production - validator will receive HTTP 500
				return false, err
			}
			// Otherwise, let the block proceed despite the error
			// This allows testing proposal actions even when broadcasting fails
			return false, nil
		}
		return override, nil
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
		// Log unsupported version if needed (caller can log this)
		return &common.VersionedBlockContents{Version: version}, nil
	}
}
