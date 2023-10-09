package p2p_test

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/p2p"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/p2p/encoder"
)

var sszNetworkEncoder = encoder.SszNetworkEncoder{}

func TestTypesEncoding(t *testing.T) {
	chainState := common.NewStatus()
	testP2P, err := p2p.NewTestP2P(context.Background(), net.IP{127, 0, 0, 1}, 8080, chainState)
	if err != nil {
		t.Fatal(err)
	}
	defer testP2P.Close()

	var b bytes.Buffer
	if _, err := sszNetworkEncoder.EncodeWithMaxLength(&b, testP2P.MetaData); err != nil {
		t.Fatalf("failed to encode metadata: %v", err)
	}
}
