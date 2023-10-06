package blobber

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/marioevz/blobber/validator_proxy"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	"github.com/marioevz/eth-clients/clients/validator"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
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
	FarFutureEpoch   = beacon.Epoch(0xffffffffffffffff)

	DEFAULT_BLOBBER_HOST       = "0.0.0.0"
	DEFAULT_BLOBBER_PORT       = 19999
	DEFAULT_PROXIES_PORT_START = 20000
)

type Blobber struct {
	ctx context.Context

	proxies []*validator_proxy.ValidatorProxy
	cls     []*beacon_client.BeaconClient

	// Configuration object
	cfg *config
}

func NewBlobber(ctx context.Context, opts ...Option) (*Blobber, error) {
	var (
		err error
	)

	b := &Blobber{
		ctx:     ctx,
		proxies: make([]*validator_proxy.ValidatorProxy, 0),
		cls:     make([]*beacon_client.BeaconClient, 0),

		cfg: &config{
			host:             DEFAULT_BLOBBER_HOST,
			port:             DEFAULT_BLOBBER_PORT,
			proxiesPortStart: DEFAULT_PROXIES_PORT_START,
		},
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

	return b, nil
}

func (b *Blobber) Address() string {
	return fmt.Sprintf(
		"http://%s:%d",
		b.cfg.externalIP,
		b.cfg.port,
	)
}

func (b *Blobber) AddBeaconClient(cl *beacon_client.BeaconClient) *validator_proxy.ValidatorProxy {
	b.cls = append(b.cls, cl)
	beaconEndpoint := fmt.Sprintf("http://%s:%d", cl.GetIP(), cl.Config.BeaconAPIPort)
	logrus.WithFields(logrus.Fields{
		"beacon_endpoint": beaconEndpoint,
	}).Info("Adding proxy")
	fmt.Printf("Adding proxy for %s\n", beaconEndpoint)
	id := len(b.proxies)
	port := b.cfg.proxiesPortStart + id
	proxy, err := validator_proxy.NewProxy(b.ctx, id, b.cfg.host, b.cfg.externalIP, port, beaconEndpoint,
		map[string]validator_proxy.ResponseCallback{
			"/eth/v2/validator/blocks/{slot}": b.genValidatorBlockHandler(id, 2),
			"/eth/v3/validator/blocks/{slot}": b.genValidatorBlockHandler(id, 3),
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

func (b *Blobber) genValidatorBlockHandler(id int, version int) validator_proxy.ResponseCallback {
	return func(request *http.Request, response []byte) error {
		var slot beacon.Slot
		if err := slot.UnmarshalJSON([]byte(mux.Vars(request)["slot"])); err != nil {
			return err
		}
		blockVersion, blockBlobResponse, err := ParseResponse(response)
		if err != nil {
			return err
		}
		if blockBlobResponse == nil {
			return nil
		}
		var validatorKey *validator.ValidatorKeys
		if b.cfg.validatorKeys != nil {
			validatorKey = b.cfg.validatorKeys[beacon.ValidatorIndex(blockBlobResponse.Block.ProposerIndex)]
		}
		msg := fmt.Sprintf("Received response, proxy %d, endpoint version %d, slot %d, block version \"%s\", blobs %d", id, version, slot, blockVersion, len(blockBlobResponse.Blobs))
		if validatorKey != nil {
			msg += fmt.Sprintf(", proposer index %d, proposer pubkey %x\n", blockBlobResponse.Block.ProposerIndex, validatorKey.ValidatorPubkey)
		}
		fmt.Printf("%s\n", msg)
		return nil
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
		return blockDataStruct.Version, nil, err
	}

	if blockDataStruct.Version != "deneb" {
		logrus.WithField("version", blockDataStruct.Version).Info("Unsupported version, skipping actions")
	}

	decoder := json.NewDecoder(bytes.NewReader(blockDataStruct.Data))
	data := new(shared.BeaconBlockContentsDeneb)
	if err := decoder.Decode(&data); err != nil {
		return blockDataStruct.Version, nil, err
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
