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

func TestDeterministicPeerIDs(t *testing.T) {
	for _, s := range []struct {
		id        p2p.TestP2PID
		expPeerID string
	}{
		{
			id:        p2p.TestP2PID(1),
			expPeerID: "16Uiu2HAm2DyWWCgyB9vyRg1WEyrLBhTxCpZrpq1iYXBtiZwdcDSe",
		},
		{
			id:        p2p.TestP2PID(2),
			expPeerID: "16Uiu2HAm9L7BLw3kqF6nLUJVHo2KQrc4qRZkMWfF55Fn4zaFDEQ6",
		},
		{
			id:        p2p.TestP2PID(3),
			expPeerID: "16Uiu2HAmH2eD6zmU2BEyUz3kJaN89zhfAENYw68Jmh3XwP1s1VvB",
		},
		{
			id:        p2p.TestP2PID(4),
			expPeerID: "16Uiu2HAkxTEdRWDFi3snqrsn47io7m8URPoxPgPwgBFZPexjUf5P",
		},
		{
			id:        p2p.TestP2PID(5),
			expPeerID: "16Uiu2HAmTUnRa3oDa7K1psWS21qxJJfC1uzmHxnxsF3Hrfv4H9R2",
		},
	} {
		t.Run(s.expPeerID, func(t *testing.T) {
			peerID := s.id.PeerID()
			if peerID != s.expPeerID {
				t.Fatalf("expected peer ID %s, got %s", s.expPeerID, peerID)
			}
		})
	}
}
