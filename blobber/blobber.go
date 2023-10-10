package blobber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/p2p"
	"github.com/marioevz/blobber/validator_proxy"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	"github.com/pkg/errors"
	"github.com/protolambda/eth2api"
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
)

type Blobber struct {
	ctx context.Context

	proxies []*validator_proxy.ValidatorProxy
	cls     []*p2p.BeaconClientPeer

	// Configuration object
	cfg *config

	// State objects
	chainStatus *common.Status

	// Other
	forkDecoder *beacon.ForkDecoder
}

func init() {
	logrus.SetLevel(logrus.InfoLevel)
}

func NewBlobber(ctx context.Context, opts ...Option) (*Blobber, error) {
	var (
		err error
	)

	b := &Blobber{
		ctx:     ctx,
		proxies: make([]*validator_proxy.ValidatorProxy, 0),
		cls:     make([]*p2p.BeaconClientPeer, 0),

		cfg: &config{
			host:             DEFAULT_BLOBBER_HOST,
			port:             DEFAULT_BLOBBER_PORT,
			proxiesPortStart: DEFAULT_PROXIES_PORT_START,
		},

		chainStatus: common.NewStatus(),
	}

	for _, o := range opts {
		if err = o.apply(b); err != nil {
			return nil, err
		}
	}

	if b.cfg.spec == nil {
		return nil, fmt.Errorf("no spec configured")
	}
	if b.cfg.proxiesPortStart == 0 {
		return nil, fmt.Errorf("no proxies port start configured")
	}
	if b.cfg.genesisValidatorsRoot == (tree.Root{}) {
		return nil, fmt.Errorf("no genesis validators root configured")
	}
	if b.cfg.externalIP == nil {
		return nil, fmt.Errorf("no external ip configured")
	}

	// Create the fork decoder
	b.forkDecoder = beacon.NewForkDecoder(b.cfg.spec, b.cfg.genesisValidatorsRoot)

	return b, nil
}

func (b *Blobber) calcBeaconBlockDomain(slot beacon_common.Slot) beacon_common.BLSDomain {
	return beacon_common.ComputeDomain(
		beacon_common.DOMAIN_BEACON_PROPOSER,
		b.cfg.spec.ForkVersion(slot),
		b.cfg.genesisValidatorsRoot,
	)
}

func (b *Blobber) calcBlobSidecarDomain(slot beacon_common.Slot) beacon_common.BLSDomain {
	b.cfg.spec.ForkVersion(slot)
	return beacon_common.ComputeDomain(
		beacon_common.DOMAIN_BLOB_SIDECAR,
		b.cfg.spec.ForkVersion(slot),
		b.cfg.genesisValidatorsRoot,
	)
}

func (b *Blobber) Address() string {
	return fmt.Sprintf(
		"http://%s:%d",
		b.cfg.externalIP,
		b.cfg.port,
	)
}

func (b *Blobber) AddBeaconClient(cl *beacon_client.BeaconClient) *validator_proxy.ValidatorProxy {
	b.cls = append(b.cls, &p2p.BeaconClientPeer{
		BeaconClient: cl,
		TCPPort:      PortBeaconTCP,
		UDPPort:      PortBeaconUDP,
	})

	beaconEndpoint := fmt.Sprintf("http://%s:%d", cl.GetIP(), cl.Config.BeaconAPIPort)
	logrus.WithFields(logrus.Fields{
		"beacon_endpoint": beaconEndpoint,
	}).Info("Adding proxy")
	fmt.Printf("Adding proxy for %s\n", beaconEndpoint)
	id := len(b.proxies)
	port := b.cfg.proxiesPortStart + id
	proxy, err := validator_proxy.NewProxy(b.ctx, id, b.cfg.host, b.cfg.externalIP, port, beaconEndpoint,
		map[string]validator_proxy.ResponseCallback{
			"/eth/v2/validator/blocks/{slot}": b.genValidatorBlockHandler(cl, id, 2),
			"/eth/v3/validator/blocks/{slot}": b.genValidatorBlockHandler(cl, id, 3),
		})
	if err != nil {
		panic(err)
	}
	b.proxies = append(b.proxies, proxy)
	return proxy
}

func (b *Blobber) Close() {
	for _, proxy := range b.proxies {
		proxy.Cancel()
	}
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
	b.chainStatus.SetHead(block.Root(), block.Slot())

	// Update the fork digest
	b.chainStatus.SetForkDigest(b.forkDecoder.ForkDigest(b.cfg.spec.SlotToEpoch(block.Slot())))

	return nil
}

func (b *Blobber) executeSlotActions(trigger_cl *beacon_client.BeaconClient, blResponse *eth.BeaconBlockAndBlobsDeneb, proposerKey *[32]byte) (bool, error) {

	// Log current action info
	blockRoot, err := blResponse.Block.HashTreeRoot()
	if err != nil {
		logrus.WithError(err).Error("Failed to get block hash tree root")
		return false, errors.Wrap(err, "failed to get block hash tree root")
	}
	logrus.WithFields(logrus.Fields{
		"slot":              blResponse.Block.Slot,
		"block_root":        fmt.Sprintf("%x", blockRoot),
		"parent_block_root": fmt.Sprintf("%x", blResponse.Block.ParentRoot),
		"blob_count":        len(blResponse.Blobs),
	}).Info("Preparing action for block and blobs")

	// Peer with the beacon nodes and broadcast the block and blobs
	testP2P, err := p2p.NewTestP2P(b.ctx, b.cfg.externalIP, int64(PortBeaconTCP), b.chainStatus)
	if err != nil {
		logrus.WithError(err).Error("Failed to create p2p")
		return false, errors.Wrap(err, "failed to create p2p")
	}
	defer testP2P.Close()
	logrus.WithFields(logrus.Fields{
		"peer_id": testP2P.Host.ID().String(),
	}).Debug("Created test p2p")

	// Connect to the beacon nodes
	for _, cl := range b.cls {
		if err := testP2P.Connect(b.ctx, cl); err != nil {
			logrus.WithError(err).Error("Failed to connect to beacon node")
			return false, errors.Wrap(err, "failed to connect to beacon node")
		}
	}

	calcBeaconBlockDomain := b.calcBeaconBlockDomain(beacon_common.Slot(blResponse.Block.Slot))
	blobSidecarDomain := b.calcBlobSidecarDomain(beacon_common.Slot(blResponse.Block.Slot))

	var slotAction SlotAction

	if slotAction == nil {
		slotAction = DefaultSlotAction{}
	}

	return slotAction.Execute(testP2P, blResponse.Block, calcBeaconBlockDomain, blResponse.Blobs, blobSidecarDomain, proposerKey)
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
		var validatorKey *[32]byte
		if b.cfg.validatorKeys != nil {
			validatorKey = b.cfg.validatorKeys[beacon_common.ValidatorIndex(blockBlobResponse.Block.ProposerIndex)]
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
