package blobber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/marioevz/blobber/api"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/config"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/proposal_actions"
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

	// planned one-time actions from api
	plannedActions []*PlannedAction

	// Other
	forkDecoder *beacon.ForkDecoder
	blobberApi  *api.BlobberApi

	// Records
	builtBlocksMap    *BuiltBlocksMap
	includeBlobRecord *common.BlobRecord
	rejectBlobRecord  *common.BlobRecord
}

type BuiltBlocksMap struct {
	BlockRoots map[beacon_common.Slot][32]byte
	sync.RWMutex
}

type PlannedAction struct {
	action     proposal_actions.ProposalAction
	result     *PlannedActionResult
	resultChan chan bool
}

type PlannedActionResult struct {
	Success    bool   `json:"success"`
	Slot       uint64 `json:"slot"`
	Root       []byte `json:"root"`
	ActionName string `json:"action_name"`
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

	// Start blobber api
	if b.ApiPort != 0 {
		blobberApi, err := api.NewBlobberApi(ctx, b.Host, b.ApiPort, map[string]api.ApiHandlerCallback{
			"/ProposalAction":          b.handleProposalActionApi,
			"/ProposalActionFrequency": b.handleProposalActionFrequencyApi,
			"/ProducedBlockRoots":      b.handleProducedBlockRootsApi,
			"/RunProposalAction":       b.handleRunProposalActionApi,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to start blobber api")
		}
		b.blobberApi = blobberApi
	}

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
	if b.blobberApi != nil {
		b.blobberApi.Cancel()
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

func (b *Blobber) getProposalAction(slot uint64) (proposal_actions.ProposalAction, *PlannedAction, error) {
	var proposalAction proposal_actions.ProposalAction

	b.Lock()
	defer b.Unlock()

	if len(b.plannedActions) > 0 {
		plannedAction := b.plannedActions[0]
		b.plannedActions = b.plannedActions[1:]

		return plannedAction.action, plannedAction, nil
	}

	if b.ProposalActionFrequency == 0 {
		return nil, nil, nil
	}

	if b.ProposalAction != nil {
		if b.ProposalActionFrequency == 1 || slot%b.ProposalActionFrequency == 0 {
			proposalAction = b.ProposalAction
		}
	}

	if proposalAction == nil {
		proposalAction = proposal_actions.Default{}
	}

	return proposalAction, nil, nil
}

func (b *Blobber) calcBeaconBlockDomain(slot beacon_common.Slot) beacon_common.BLSDomain {
	return beacon_common.ComputeDomain(
		beacon_common.DOMAIN_BEACON_PROPOSER,
		b.Spec.ForkVersion(slot),
		b.GenesisValidatorsRoot,
	)
}

func (b *Blobber) executeNextProposalAction(trigger_cl *beacon_client.BeaconClient, blResponse *deneb.BlockContents, validatorKey *keys.ValidatorKey) (bool, error) {
	proposalAction, plannedAction, err := b.getProposalAction(uint64(blResponse.Block.Slot))
	if err != nil {
		return false, errors.Wrap(err, "failed to get proposal action")
	}
	if proposalAction == nil {
		return false, nil
	}

	executed, blockRoot, err := b.executeProposalAction(trigger_cl, blResponse, validatorKey, proposalAction)
	if executed {
		b.builtBlocksMap.Lock()
		b.builtBlocksMap.BlockRoots[blResponse.Block.Slot] = blockRoot
		b.builtBlocksMap.Unlock()
	}

	if plannedAction != nil {
		plannedAction.result = &PlannedActionResult{
			Success:    executed,
			Slot:       uint64(blResponse.Block.Slot),
			Root:       blockRoot[:],
			ActionName: proposalAction.Name(),
		}
		close(plannedAction.resultChan)
	}

	return executed, err
}

func (b *Blobber) executeProposalAction(trigger_cl *beacon_client.BeaconClient, blResponse *deneb.BlockContents, validatorKey *keys.ValidatorKey, proposalAction proposal_actions.ProposalAction) (bool, tree.Root, error) {
	proposalActionFields := logrus.Fields(proposalAction.Fields())
	if len(proposalActionFields) > 0 {
		logrus.WithFields(proposalActionFields).Info("Action configuration")
	}

	testPeerCount := proposalAction.GetTestPeerCount()

	// Peer with the beacon nodes and broadcast the block and blobs
	testPeers, err := b.GetTestPeer(b.ctx, testPeerCount)
	if err != nil {
		return false, tree.Root{}, errors.Wrap(err, "failed to create p2p")
	} else if len(testPeers) != testPeerCount {
		return false, tree.Root{}, fmt.Errorf("failed to create p2p, expected %d, got %d", testPeerCount, len(testPeers))
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
			return false, tree.Root{}, errors.Wrap(err, "failed to connect to beacon node")
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

	return executed, blockRoot, errors.Wrap(err, "failed to execute proposal action")
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
		override, err := b.executeNextProposalAction(cl, blockBlobResponse, validatorKey)
		if err != nil {
			logrus.WithError(err).Error("Failed to execute proposal actions")
		}
		return override, errors.Wrap(err, "failed to execute proposal actions")
	}
}

type BlockDataStruct struct {
	Version string          `json:"version"`
	Data    json.RawMessage `json:"data"`
}

func ParseResponse(response []byte) (string, *deneb.BlockContents, error) {
	var (
		blockDataStruct BlockDataStruct
	)
	if err := json.Unmarshal(response, &blockDataStruct); err != nil {
		return blockDataStruct.Version, nil, errors.Wrap(err, "failed to unmarshal response into BlockDataStruct")
	}

	if blockDataStruct.Version != "deneb" {
		logrus.WithField("version", blockDataStruct.Version).Warn("Unsupported version, skipping actions")
		return blockDataStruct.Version, nil, nil
	}

	decoder := json.NewDecoder(bytes.NewReader(blockDataStruct.Data))
	data := new(deneb.BlockContents)
	if err := decoder.Decode(&data); err != nil {
		return blockDataStruct.Version, nil, errors.Wrap(err, "failed to decode block contents")
	}

	return blockDataStruct.Version, data, nil
}

func (b *Blobber) handleProposalActionApi(request *http.Request, body []byte) (interface{}, error) {
	if request.Method == http.MethodPost {
		proposalAction, err := proposal_actions.UnmarshallProposalAction(body)
		if err != nil {
			return nil, err
		}
		b.ProposalAction = proposalAction
	}
	return b.ProposalAction, nil
}

func (b *Blobber) handleProposalActionFrequencyApi(request *http.Request, body []byte) (interface{}, error) {
	if request.Method == http.MethodPost {
		value, err := strconv.ParseUint(string(body), 10, 64)
		if err != nil {
			return nil, err
		}

		b.ProposalActionFrequency = value
	}
	return b.ProposalActionFrequency, nil
}

func (b *Blobber) handleProducedBlockRootsApi(request *http.Request, body []byte) (interface{}, error) {
	if request.Method != http.MethodGet {
		return nil, fmt.Errorf("invalid method")
	}
	return b.GetProducedBlockRoots(), nil
}

func (b *Blobber) handleRunProposalActionApi(request *http.Request, body []byte) (interface{}, error) {
	if request.Method != http.MethodPost {
		return nil, fmt.Errorf("invalid method")
	}

	proposalAction, err := proposal_actions.UnmarshallProposalAction(body)
	if err != nil {
		return nil, err
	}

	plannedAction := &PlannedAction{
		action:     proposalAction,
		resultChan: make(chan bool),
	}
	b.Lock()
	b.plannedActions = append(b.plannedActions, plannedAction)
	b.Unlock()

	// wait for execution
	<-plannedAction.resultChan

	return plannedAction.result, nil
}
