package p2p

import (
	"context"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"

	"github.com/pkg/errors"
)

type ENR interface {
	ENR(ctx context.Context) (string, error)
}

type BeaconClientPeer struct {
	BeaconClient ENR
}

func multiAddressBuilderWithID(parsedIP net.IP, protocol string, port uint, id peer.ID) (ma.Multiaddr, error) {
	if id.String() == "" {
		return nil, errors.New("empty peer id given")
	}
	if parsedIP.To4() != nil {
		return ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/%s/%d/p2p/%s", parsedIP.To4().String(), protocol, port, id.String()))
	}
	return ma.NewMultiaddr(fmt.Sprintf("/ip6/%s/%s/%d/p2p/%s", parsedIP.To16().String(), protocol, port, id.String()))
}

func (bcp *BeaconClientPeer) GetPeerAddrInfo(ctx context.Context) (*peer.AddrInfo, error) {
	enr, err := bcp.BeaconClient.ENR(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "could not get ENR from beacon node")
	}

	// Check if ENR is empty or invalid
	if enr == "" {
		return nil, errors.New("ENR is empty - beacon node may not support P2P or ENR endpoint")
	}

	// ENR should start with "enr:" prefix
	if len(enr) < 4 || enr[:4] != "enr:" {
		return nil, fmt.Errorf("invalid ENR format: missing 'enr:' prefix (got: %q) - beacon node returned invalid ENR", enr)
	}

	node, err := enode.Parse(enode.ValidSchemes, enr)
	if err != nil {
		return nil, errors.Wrapf(err, "could not parse ENR: %q", enr)
	}

	pubKey := node.Pubkey()
	assertedKey, err := ConvertToInterfacePubkey(pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not get pubkey")
	}
	id, err := peer.IDFromPublicKey(assertedKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not get peer ID")
	}
	addrs := make([]ma.Multiaddr, 0)

	tcpAddr, err := multiAddressBuilderWithID(node.IP(), "tcp", uint(node.TCP()), id)
	if err != nil {
		return nil, errors.Wrap(err, "could not get tcp address")
	}
	addrs = append(addrs, tcpAddr)

	udpAddr, err := multiAddressBuilderWithID(node.IP(), "udp", uint(node.UDP()), id)
	if err != nil {
		return nil, errors.Wrap(err, "could not get udp address")
	}
	addrs = append(addrs, udpAddr)
	addrInfo := &peer.AddrInfo{
		ID:    id,
		Addrs: addrs,
	}
	return addrInfo, nil
}
