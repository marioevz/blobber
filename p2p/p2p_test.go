package p2p_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/marioevz/blobber/p2p"
	"github.com/prysmaticlabs/prysm/v4/beacon-chain/p2p/encoder"
)

var sszNetworkEncoder = encoder.SszNetworkEncoder{}

func GetFreePort() (port int64, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return int64(l.Addr().(*net.TCPAddr).Port), nil
		}
	}
	return
}

func TestTypesEncoding(t *testing.T) {
	testP2PInstance := &p2p.TestP2P{
		ExternalIP:  net.IP{127, 0, 0, 1},
		ChainStatus: p2p.NewStatus(),
	}
	port, err := GetFreePort()
	if err != nil {
		t.Fatal(err)
	}
	testPeer, err := testP2PInstance.NewTestPeer(context.Background(), port)
	if err != nil {
		t.Fatal(err)
	}
	defer testPeer.Close()

	var b bytes.Buffer
	if _, err := sszNetworkEncoder.EncodeWithMaxLength(&b, p2p.WrapSSZObject(testPeer.MetaData)); err != nil {
		t.Fatalf("failed to encode metadata: %v", err)
	}
}

var expectedPeerIDsPerInstanceID = map[uint64][5]string{
	0: {
		"16Uiu2HAm2DyWWCgyB9vyRg1WEyrLBhTxCpZrpq1iYXBtiZwdcDSe",
		"16Uiu2HAm9L7BLw3kqF6nLUJVHo2KQrc4qRZkMWfF55Fn4zaFDEQ6",
		"16Uiu2HAmH2eD6zmU2BEyUz3kJaN89zhfAENYw68Jmh3XwP1s1VvB",
		"16Uiu2HAkxTEdRWDFi3snqrsn47io7m8URPoxPgPwgBFZPexjUf5P",
		"16Uiu2HAmTUnRa3oDa7K1psWS21qxJJfC1uzmHxnxsF3Hrfv4H9R2",
	},
	1: {
		"16Uiu2HAmQoEwGBgsACp67cCAXNjCQBkHRVqtwBK2Sq1jcsyc154U",
		"16Uiu2HAmKfnranVvseqy1BYDfbXbMs2FuYKbbf6hL3r77CcWTwMH",
		"16Uiu2HAmKWFFj9a2JDBR595rFyKDZEXer5PppgkXNG5ESGCXoA8m",
		"16Uiu2HAm4ebhKMsRLTUmJ5REdXjPWpZ69JmUsMKjn9MhTNAU3yve",
		"16Uiu2HAm2BjMuoccupkyzif1rBVv1wMXdV7fKTRh2UFgceApuhei",
	},
}

func TestDeterministicPeerIDs(t *testing.T) {
	for instanceID, expPeerIDs := range expectedPeerIDsPerInstanceID {
		testP2PInstance := &p2p.TestP2P{InstanceID: instanceID}

		for i, expPeerID := range expPeerIDs {
			t.Run(expPeerID, func(t *testing.T) {
				peerID := p2p.TestPeerIndex(i + 1).PeerID(instanceID)
				if peerID != expPeerID {
					t.Fatalf("expected peer ID %s, got %s", expPeerID, peerID)
				}
			})
		}

		// Also test GetNextPeerIDs
		t.Run(fmt.Sprintf("GetNextPeerIDs (Instance ID %d)", instanceID), func(t *testing.T) {
			peerIDs := testP2PInstance.GetNextPeerIDs(uint64(len(expPeerIDs)))
			for i, expPeerID := range expPeerIDs {
				if peerIDs[i] != expPeerID {
					t.Fatalf("expected peer ID %s, got %s", expPeerID, peerIDs[i])
				}
			}
		})
	}
}
