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
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
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
	builtBlocksMap *BuiltBlocksMap

	// Slot deduplication removed - allowing multiple proposal actions per slot
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
	}

	log.Info("Applying configuration options...")

	// Apply the options
	if err := b.Apply(opts...); err != nil {
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

	// Set logger for TestP2P
	if b.TestP2P != nil {
		b.SetLogger(log)
	}

	// Connect to beacon clients via P2P (automatically discovers and connects)
	go b.connectToStaticPeers(ctx)

	return b, nil
}

func (b *Blobber) Address() string {
	return fmt.Sprintf(
		"http://%s:%d",
		b.ExternalIP,
		b.Port,
	)
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
		b.logger,
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
	blockRoot := block.Root()
	b.ChainStatus.SetHead(blockRoot, block.Slot())

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
		// Create one peer per beacon node for better connection success
		actualPeerCount := testPeerCount
		if len(b.cls) > testPeerCount {
			actualPeerCount = len(b.cls)
			b.logger.WithFields(map[string]interface{}{
				"requested_peers": testPeerCount,
				"beacon_nodes":    len(b.cls),
				"actual_peers":    actualPeerCount,
			}).Info("Creating one P2P peer per beacon node for better connectivity")
		}

		// Peer with the beacon nodes and broadcast the block and blobs
		var err error
		testPeers, err = b.GetTestPeer(b.ctx, actualPeerCount)
		if err != nil {
			b.logger.WithField("error", err).Warn("Failed to create P2P test peers, continuing without P2P support")
			// Create empty test peers array to continue
			testPeers = make(p2p.TestPeers, 0)
		} else if len(testPeers) != actualPeerCount {
			b.logger.WithFields(map[string]interface{}{
				"expected": actualPeerCount,
				"got":      len(testPeers),
			}).Warn("Did not get expected number of test peers")
		} else {
			for i, testPeer := range testPeers {
				b.logger.WithFields(map[string]interface{}{
					"index":   i,
					"peer_id": testPeer.Host.ID().String(),
				}).Debug("Created test p2p")
			}

			// Connect to the beacon nodes with retry logic
			const maxRetries = 3
			const retryDelay = 2 * time.Second
			connectedCount := 0

			for i, cl := range b.cls {
				testPeer := testPeers[i%len(testPeers)]
				connected := false

				// Retry connection up to maxRetries times
				for retry := 0; retry < maxRetries && !connected; retry++ {
					if retry > 0 {
						b.logger.WithFields(map[string]interface{}{
							"beacon_index": i,
							"retry":        retry,
							"max_retries":  maxRetries,
						}).Info("Retrying P2P connection to beacon node")
						time.Sleep(retryDelay)
					}

					// Always try to connect/reconnect to ensure fresh connection
					if err := testPeer.Connect(b.ctx, cl); err != nil {
						// Log the error but continue with retries
						b.logger.WithFields(map[string]interface{}{
							"error":           err,
							"beacon_index":    i,
							"test_peer_index": i % len(testPeers),
							"retry":           retry,
						}).Warn("Failed to connect to beacon node via P2P")
					} else {
						connected = true
						connectedCount++
						b.logger.WithFields(map[string]interface{}{
							"beacon_index":    i,
							"test_peer_index": i % len(testPeers),
							"peer_id":         testPeer.Host.ID().String(),
						}).Info("Successfully connected to beacon node via P2P")
					}
				}

				if !connected {
					b.logger.WithFields(map[string]interface{}{
						"beacon_index": i,
						"max_retries":  maxRetries,
					}).Error("Failed to connect to beacon node after all retries")
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
		"test_peer_count":   testPeerCount,
	}).Info("Preparing action for block and blobs")

	b.logger.WithFields(map[string]interface{}{
		"action_name":    proposalAction.Name(),
		"slot":           blResponse.GetSlot(),
		"frequency":      proposalAction.Frequency(),
		"times_executed": proposalAction.TimesExecuted(),
	}).Debug("About to execute proposal action")

	calcBeaconBlockDomain := b.calcBeaconBlockDomain(blResponse.GetSlot())
	executed, err := proposalAction.Execute(
		b.Spec,
		testPeers,
		denebBlock,
		calcBeaconBlockDomain,
		validatorKey,
	)

	if executed && err == nil {
		b.logger.WithFields(map[string]interface{}{
			"action_name": proposalAction.Name(),
			"slot":        blResponse.GetSlot(),
			"block_root":  fmt.Sprintf("%#x", blockRoot),
		}).Info("Proposal action executed successfully")

		b.builtBlocksMap.Lock()
		b.builtBlocksMap.BlockRoots[blResponse.GetSlot()] = blockRoot
		b.builtBlocksMap.Unlock()
		b.ProposalAction.IncrementTimesExecuted()

		b.logger.WithFields(map[string]interface{}{
			"times_executed": b.ProposalAction.TimesExecuted(),
			"max_executions": b.ProposalAction.MaxExecutionTimes(),
		}).Debug("Updated proposal action execution count")
	} else if err != nil {
		b.logger.WithFields(map[string]interface{}{
			"action_name": proposalAction.Name(),
			"slot":        blResponse.GetSlot(),
			"error":       err,
			"executed":    executed,
		}).Error("Proposal action execution failed")
	} else {
		b.logger.WithFields(map[string]interface{}{
			"action_name": proposalAction.Name(),
			"slot":        blResponse.GetSlot(),
		}).Debug("Proposal action completed but was not executed")
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

		// Skip if not Deneb, Electra, or Fulu
		if blockBlobResponse.Version != common.VersionDeneb && blockBlobResponse.Version != common.VersionElectra && blockBlobResponse.Version != common.VersionFulu {
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

		// Execute the proposal actions
		if validatorKey == nil {
			b.logger.Warn("No validator key found, skipping proposal actions")
			// Let the block proceed without modification
			return false, nil
		}

		b.logger.WithFields(map[string]interface{}{
			"slot":                  slot,
			"proposer_index":        blockBlobResponse.GetProposerIndex(),
			"validator_key_present": validatorKey != nil,
		}).Debug("Starting proposal action execution")

		override, err := b.executeProposalActions(cl, blockBlobResponse, validatorKey)
		if err != nil {
			b.logger.WithFields(map[string]interface{}{
				"error":        err,
				"slot":         blockBlobResponse.GetSlot(),
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

	// Log version detection
	logger.New().WithFields(map[string]interface{}{
		"version":       version,
		"response_size": len(response),
	}).Debug("Parsing block response")

	switch version {
	case common.VersionDeneb:
		logger.New().WithField("version", "deneb").Debug("Processing Deneb fork block")
		data := new(apiv1deneb.BlockContents)
		if err := decoder.Decode(&data); err != nil {
			logger.New().WithField("error", err).WithField("version", "deneb").Error("Failed to parse Deneb block")
			return nil, errors.Wrap(err, "failed to decode deneb block contents")
		}
		logger.New().WithFields(map[string]interface{}{
			"version":    "deneb",
			"blob_count": len(data.Blobs),
		}).Debug("Successfully parsed Deneb block contents")
		return &common.VersionedBlockContents{
			Version: version,
			Deneb:   data,
		}, nil

	case common.VersionElectra:
		logger.New().WithField("version", "electra").Debug("Processing Electra fork block")
		data := new(apiv1electra.BlockContents)
		if err := decoder.Decode(&data); err != nil {
			logger.New().WithField("error", err).WithField("version", "electra").Error("Failed to parse Electra block")
			return nil, errors.Wrap(err, "failed to decode electra block contents")
		}
		logger.New().WithFields(map[string]interface{}{
			"version":    "electra",
			"blob_count": len(data.Blobs),
		}).Debug("Successfully parsed Electra block contents")
		return &common.VersionedBlockContents{
			Version: version,
			Electra: data,
		}, nil

	case common.VersionFulu:
		logger.New().WithField("version", "fulu").Info("Processing Fulu fork block - treating as Electra format")
		data := new(apiv1electra.BlockContents)
		if err := decoder.Decode(&data); err != nil {
			logger.New().WithField("error", err).WithField("version", "fulu").Error("Failed to parse Fulu block")
			return nil, errors.Wrap(err, "failed to decode fulu block contents")
		}
		logger.New().WithFields(map[string]interface{}{
			"version":    "fulu",
			"blob_count": len(data.Blobs),
			"note":       "Using Electra format for Fulu blocks",
		}).Info("Successfully parsed Fulu block contents")
		return &common.VersionedBlockContents{
			Version: version,
			Fulu:    data,
		}, nil

	default:
		// Log unsupported version if needed (caller can log this)
		return &common.VersionedBlockContents{Version: version}, nil
	}
}

// connectToStaticPeers connects to configured static peers
func (b *Blobber) connectToStaticPeers(ctx context.Context) {
	// Fetch node identities from beacon clients and connect
	b.logger.Info("Fetching node identities from beacon clients")

	// Get test peers for P2P connections
	testPeerCount := 1 // Start with one peer for static connections
	testPeers, err := b.GetTestPeer(ctx, testPeerCount)
	if err != nil {
		b.logger.WithFields(map[string]interface{}{
			"error": err,
		}).Error("Failed to create test peer for static connections")
		return
	}

	testPeer := testPeers[0]

	// Fetch and connect to each beacon client's P2P endpoint
	staticPeers := make([]string, 0)
	for i, cl := range b.cls {
		b.logger.WithFields(map[string]interface{}{
			"beacon_index": i,
		}).Debug("Getting peer address info from beacon client")

		// Get peer address info using the existing GetPeerAddrInfo method
		peerAddrInfo, err := cl.GetPeerAddrInfo(ctx)
		if err != nil {
			b.logger.WithFields(map[string]interface{}{
				"beacon_index": i,
				"error":        err,
			}).Warn("Failed to get peer address info")
			continue
		}

		// Connect to the peer
		if err := testPeer.Connect(ctx, cl); err != nil {
			b.logger.WithFields(map[string]interface{}{
				"beacon_index": i,
				"peer_id":      peerAddrInfo.ID.String(),
				"error":        err,
			}).Warn("Failed to connect to beacon node")
			continue
		}

		b.logger.WithFields(map[string]interface{}{
			"beacon_index": i,
			"peer_id":      peerAddrInfo.ID.String(),
		}).Info("Successfully connected to beacon node P2P endpoint")

		// Build multiaddr string for tracking
		if len(peerAddrInfo.Addrs) > 0 {
			p2pAddr := fmt.Sprintf("%s/p2p/%s", peerAddrInfo.Addrs[0].String(), peerAddrInfo.ID.String())
			staticPeers = append(staticPeers, p2pAddr)
		}
	}

	// Also connect to any manually configured static peers
	for _, peerAddr := range b.StaticPeers {
		b.logger.WithFields(map[string]interface{}{
			"peer_addr": peerAddr,
		}).Info("Attempting to connect to manually configured static peer")

		peerID, err := testPeer.ConnectToPeerTemporarily(ctx, peerAddr)
		if err != nil {
			b.logger.WithFields(map[string]interface{}{
				"peer_addr": peerAddr,
				"error":     err,
			}).Warn("Failed to connect to static peer")
			continue
		}

		b.logger.WithFields(map[string]interface{}{
			"peer_addr": peerAddr,
			"peer_id":   peerID.String(),
		}).Info("Successfully connected to static peer")

		staticPeers = append(staticPeers, peerAddr)
	}

	// Update the static peers list with discovered peers
	b.StaticPeers = staticPeers

	b.logger.WithFields(map[string]interface{}{
		"total_static_peers": len(staticPeers),
	}).Info("Completed static peer connections")

	// Keep connections alive
	if len(staticPeers) > 0 {
		go b.maintainStaticPeerConnections(ctx, testPeer)
	}
}

// maintainStaticPeerConnections periodically checks and reconnects to static peers
func (b *Blobber) maintainStaticPeerConnections(ctx context.Context, testPeer *p2p.TestPeer) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check each static peer connection
			for _, peerAddr := range b.StaticPeers {
				// Extract peer ID from multiaddr
				// Format: /ip4/1.2.3.4/tcp/9000/p2p/16Uiu2...
				parts := strings.Split(peerAddr, "/")
				var peerIDStr string
				for i, part := range parts {
					if part == "p2p" && i+1 < len(parts) {
						peerIDStr = parts[i+1]
						break
					}
				}

				if peerIDStr == "" {
					continue
				}

				// Check if still connected
				peerID, err := peer.Decode(peerIDStr)
				if err != nil {
					b.logger.WithFields(map[string]interface{}{
						"peer_addr": peerAddr,
						"error":     err,
					}).Warn("Failed to decode peer ID")
					continue
				}

				if testPeer.Host.Network().Connectedness(peerID) != network.Connected {
					b.logger.WithFields(map[string]interface{}{
						"peer_addr": peerAddr,
						"peer_id":   peerIDStr,
					}).Info("Reconnecting to disconnected static peer")

					// Attempt to reconnect
					_, err := testPeer.ConnectToPeerTemporarily(ctx, peerAddr)
					if err != nil {
						b.logger.WithFields(map[string]interface{}{
							"peer_addr": peerAddr,
							"error":     err,
						}).Warn("Failed to reconnect to static peer")
					} else {
						b.logger.WithFields(map[string]interface{}{
							"peer_addr": peerAddr,
						}).Info("Successfully reconnected to static peer")
					}
				}
			}
		}
	}
}
