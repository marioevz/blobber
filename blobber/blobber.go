package blobber

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/marioevz/blobber/validator_proxy"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
)

const (
	PortBeaconTCP    = 9000
	PortBeaconUDP    = 9000
	PortBeaconAPI    = 4000
	PortBeaconGRPC   = 4001
	PortMetrics      = 8080
	PortValidatorAPI = 5000
	FarFutureEpoch   = beacon.Epoch(0xffffffffffffffff)
)

type Blobber struct {
	hostIP    net.IP
	portStart int

	ctx context.Context

	proxies []*validator_proxy.ValidatorProxy
}

func NewBlobber(ctx context.Context, hostIP net.IP, portStart int) *Blobber {
	return &Blobber{
		ctx:       ctx,
		hostIP:    hostIP,
		portStart: portStart,
		proxies:   make([]*validator_proxy.ValidatorProxy, 0),
	}
}

func (b *Blobber) NewProxy(consensusEndpoint string) *validator_proxy.ValidatorProxy {
	id := len(b.proxies)
	port := b.portStart + id
	proxy, err := validator_proxy.NewProxy(b.ctx, id, b.hostIP, port, fmt.Sprintf("http://%s", consensusEndpoint),
		map[string]validator_proxy.ResponseCallback{
			"/eth/v2/validator/blocks/{slot}": genValidatorBlockHandler(id, 2),
			"/eth/v3/validator/blocks/{slot}": genValidatorBlockHandler(id, 3),
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

func genValidatorBlockHandler(id int, version int) validator_proxy.ResponseCallback {
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
		fmt.Printf("Received response, proxy %d, endpoint version %d, slot %d, block version \"%s\", blobs %d\n", id, version, slot, blockVersion, len(blockBlobResponse.BlobSidecars))
		return nil
	}
}

type versionStruct struct {
	Version string `json:"version"`
}

type blockDataStruct struct {
	Data *DenebBlockResponse `json:"data"`
}

type DenebBlockResponse struct {
	Block        *deneb.BeaconBlock  `json:"block"`
	BlobSidecars []deneb.BlobSidecar `json:"blob_sidecars"`
}

func ParseResponse(response []byte) (string, *DenebBlockResponse, error) {
	var (
		versionStr versionStruct
	)
	if err := json.Unmarshal(response, &versionStr); err != nil {
		return versionStr.Version, nil, err
	}
	var data blockDataStruct
	switch versionStr.Version {
	case "deneb":
		data.Data = new(DenebBlockResponse)
	default:
		return versionStr.Version, nil, nil
	}
	if err := json.Unmarshal(response, &data); err != nil {
		return versionStr.Version, nil, err
	}

	return versionStr.Version, data.Data, nil
}
