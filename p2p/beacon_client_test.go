package p2p_test

import (
	"context"
	"testing"

	"github.com/marioevz/blobber/p2p"
)

type FakeClient struct {
	ENRString string
}

func (fc *FakeClient) ENR(ctx context.Context) (string, error) {
	return fc.ENRString, nil
}

func TestENRParsing(t *testing.T) {
	type enrTest struct {
		name          string
		enr           string
		wantID        string
		wantMultiAddr []string
	}
	tests := []enrTest{
		{
			name:   "test1",
			enr:    "enr:-Ly4QGJ784HYJnwnb3jtYaUqxFcrRNEjwAuh_m9YZ70BiiwgbVdlbz-n0QeAhCVkWkCSHtyfm9H7f10wKLSdkXph4GEBh2F0dG5ldHOIAAAAAAAAAACEZXRoMpA4MRPHBAAACv__________gmlkgnY0gmlwhKwZAAWJc2VjcDI1NmsxoQNitNN8ww9vqpQSQVjXo0rzzQcmzijtqke5vXnmbiPocohzeW5jbmV0cwCDdGNwgiMog3VkcIIjKA",
			wantID: "16Uiu2HAmKJJED6835NsYwwT3MZVVi4idg2jiULBYb1kPzqw9jzAM",
			wantMultiAddr: []string{
				"/ip4/172.25.0.5/tcp/9000/p2p/16Uiu2HAmKJJED6835NsYwwT3MZVVi4idg2jiULBYb1kPzqw9jzAM",
				"/ip4/172.25.0.5/udp/9000/p2p/16Uiu2HAmKJJED6835NsYwwT3MZVVi4idg2jiULBYb1kPzqw9jzAM",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bcp := &p2p.BeaconClientPeer{
				BeaconClient: &FakeClient{
					ENRString: tt.enr,
				},
			}

			addrInfo, err := bcp.GetPeerAddrInfo(context.Background())
			if err != nil {
				t.Fatalf("parseENR() error = %v", err)
			}
			if addrInfo.ID.String() != tt.wantID {
				t.Fatalf("parseENR() id = %v, want %v", addrInfo.ID.String(), tt.wantID)
			}

			if len(addrInfo.Addrs) != len(tt.wantMultiAddr) {
				t.Fatalf("parseENR() addrs = %v, want %v", len(addrInfo.Addrs), len(tt.wantMultiAddr))
			}

			for i, addr := range addrInfo.Addrs {
				if addr.String() != tt.wantMultiAddr[i] {
					t.Fatalf("parseENR() addr = %v, want %v", addr.String(), tt.wantMultiAddr[i])
				}
			}
		})
	}
}
