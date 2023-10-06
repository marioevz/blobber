package p2p

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/sirupsen/logrus"

	"github.com/protolambda/zrnt/eth2/beacon/common"

	"github.com/prysmaticlabs/prysm/v4/beacon-chain/p2p/encoder"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
)

var sszNetworkEncoder = encoder.SszNetworkEncoder{}

type Goodbye = primitives.SSZUint64

type PingData = primitives.SSZUint64

type ChainState struct {
	CurrentForkVersion  common.Version
	CurrentForkDigest   common.ForkDigest
	FinalizedCheckpoint common.Checkpoint
	CurrentHead         common.Checkpoint
	CurrentSlot         common.Slot

	sync.Mutex
	// MetaData            MetaData
}

type TestP2P struct {
	Host       host.Host
	PubSub     *pubsub.PubSub
	PrivateKey crypto.PrivKey
	PublicKey  crypto.PubKey
	LocalNode  *enode.LocalNode
	Digest     [4]byte
	MetaData   MetaData

	cancel context.CancelFunc
	state  *ChainState
	// BeaconAPITest *BeaconAPITest
}

func createLocalNode(
	privKey *ecdsa.PrivateKey,
	ipAddr net.IP,
	udpPort, tcpPort int,
) (*enode.LocalNode, error) {
	db, err := enode.OpenDB("")
	if err != nil {
		return nil, err
	}
	localNode := enode.NewLocalNode(db, privKey)

	ipEntry := enr.IP(ipAddr)
	udpEntry := enr.UDP(udpPort)
	tcpEntry := enr.TCP(tcpPort)
	localNode.Set(ipEntry)
	localNode.Set(udpEntry)
	localNode.Set(tcpEntry)
	localNode.SetFallbackIP(ipAddr)
	localNode.SetFallbackUDP(udpPort)

	return localNode, nil
}

func ConvertFromInterfacePrivKey(privkey crypto.PrivKey) (*ecdsa.PrivateKey, error) {
	secpKey, ok := privkey.(*crypto.Secp256k1PrivateKey)
	if !ok {
		return nil, fmt.Errorf("could not cast to Secp256k1PrivateKey")
	}
	rawKey, err := secpKey.Raw()
	if err != nil {
		return nil, err
	}
	privKey := new(ecdsa.PrivateKey)
	k := new(big.Int).SetBytes(rawKey)
	privKey.D = k
	privKey.Curve = gcrypto.S256() // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1.
	privKey.X, privKey.Y = gcrypto.S256().ScalarBaseMult(rawKey)
	return privKey, nil
}

func NewTestP2P(ctx context.Context /*beaconAPITest *BeaconAPITest,*/, ip net.IP, port int64, chainState *ChainState) (*TestP2P, error) {
	ctx, cancel := context.WithCancel(ctx)

	// Generate a new private key pair for this host.
	priv, pub, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	libp2pOptions := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", ip.String(), port)), libp2p.UserAgent("HiveSim/0.1.0"),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer("/mplex/6.7.0", yamux.DefaultTransport),
		libp2p.DefaultMuxers,
		libp2p.Security(noise.ID, noise.New),
		libp2p.Ping(false),
		libp2p.Identity(priv),
	}

	h, err := libp2p.New(libp2pOptions...)
	if err != nil {
		return nil, err
	}

	ps, err := pubsub.NewGossipSub(ctx, h,
		pubsub.WithMessageSigning(false),
		pubsub.WithStrictSignatureVerification(false),
	)
	if err != nil {
		return nil, err
	}

	pk, err := ConvertFromInterfacePrivKey(priv)
	if err != nil {
		return nil, err
	}
	localNode, err := createLocalNode(pk, ip, int(port), int(port))
	if err != nil {
		return nil, err
	}

	return &TestP2P{
		Host:       h,
		PubSub:     ps,
		PrivateKey: priv,
		PublicKey:  pub,
		LocalNode:  localNode,
		MetaData: MetaData{
			SeqNumber: 0,
			AttNets:   make([]byte, 8),
		},

		state:  chainState,
		cancel: cancel,
		// BeaconAPITest: beaconAPITest,
	}, nil

}

func (p *TestP2P) Close() error {
	p.cancel()
	return p.Host.Close()
}

func (p *TestP2P) WaitForP2PConnection(ctx context.Context) error {
	// TODO: Actually wait for connection
	if len(p.Host.Network().Peers()) > 0 {
		return nil
	}
	return errors.New("no peers connected")
}

func (p *TestP2P) SetupStreams() error {
	// Prepare stream responses for the basic Req/Resp protocols.

	// Status
	protocolID := protocol.ID("/eth2/beacon_chain/req/status/1/" + encoder.ProtocolSuffixSSZSnappy)
	p.Host.SetStreamHandler(protocolID, func(s network.Stream) {
		// Read the incoming message into the appropriate struct.
		var out Status
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, &out); err != nil {
			logrus.WithError(err).Error("Failed to decode incoming message")
			return
		}
		// Log received data
		logrus.WithFields(logrus.Fields{
			"protocol":        s.Protocol(),
			"peer":            s.Conn().RemotePeer().String(),
			"fork_digest":     fmt.Sprintf("%x", out.ForkDigest),
			"finalized_root":  fmt.Sprintf("%x", out.FinalizedRoot),
			"finalized_epoch": fmt.Sprintf("%d", out.FinalizedEpoch),
			"head_root":       fmt.Sprintf("%x", out.HeadRoot),
			"head_slot":       fmt.Sprintf("%d", out.HeadSlot),
		}).Info("Received data")

		// Construct response
		p.state.Lock()
		resp := Status{
			ForkDigest:     p.state.CurrentForkDigest[:],
			FinalizedRoot:  p.state.FinalizedCheckpoint.Root[:],
			FinalizedEpoch: uint64(p.state.FinalizedCheckpoint.Epoch),
			HeadRoot:       p.state.CurrentHead.Root[:],
			HeadSlot:       uint64(p.state.CurrentSlot),
		}
		p.state.Unlock()

		// Log received data
		logrus.WithFields(logrus.Fields{
			"protocol":        s.Protocol(),
			"peer":            s.Conn().RemotePeer().String(),
			"fork_digest":     fmt.Sprintf("%x", resp.ForkDigest),
			"finalized_root":  fmt.Sprintf("%x", resp.FinalizedRoot),
			"finalized_epoch": fmt.Sprintf("%d", resp.FinalizedEpoch),
			"head_root":       fmt.Sprintf("%x", resp.HeadRoot),
			"head_slot":       fmt.Sprintf("%d", resp.HeadSlot),
		}).Info("Response data")

		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			logrus.WithError(err).Error("Failed to send status response")
			return
		}
		if n, err := sszNetworkEncoder.EncodeWithMaxLength(s, &resp); err != nil {
			logrus.WithError(err).Error("Failed to encode outgoing message")
			return
		} else {
			logrus.WithField("bytes", n).Info("Sent data")
		}
		if err := s.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close stream")
			return
		}
	})

	// Goodbye
	protocolID = protocol.ID("/eth2/beacon_chain/req/goodbye/1/" + encoder.ProtocolSuffixSSZSnappy)
	p.Host.SetStreamHandler(protocolID, func(s network.Stream) {
		// Read the incoming message into the appropriate struct.
		var out Goodbye
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, &out); err != nil {
			logrus.WithError(err).Error("Failed to decode incoming message")
			return
		}
		// Log received data
		logrus.WithFields(logrus.Fields{
			"protocol": s.Protocol(),
			"peer":     s.Conn().RemotePeer().String(),
			"reason":   fmt.Sprintf("%d", out),
		}).Info("Received data")

		// Construct response
		var resp Goodbye

		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			logrus.WithError(err).Error("Failed to send status response")
			return
		}
		if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, &resp); err != nil {
			logrus.WithError(err).Error("Failed to encode outgoing message")
			return
		}

		if err := s.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close stream")
			return
		}
	})

	// Ping
	protocolID = protocol.ID("/eth2/beacon_chain/req/ping/1/" + encoder.ProtocolSuffixSSZSnappy)
	p.Host.SetStreamHandler(protocolID, func(s network.Stream) {
		logrus.WithFields(logrus.Fields{
			"protocol": s.Protocol(),
			"peer":     s.Conn().RemotePeer().String(),
		}).Info("Got a new stream")
		// Read the incoming message into the appropriate struct.
		var out PingData
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, &out); err != nil {
			logrus.WithError(err).Error("Failed to decode incoming message")
			return
		}
		// Log received data
		logrus.WithFields(logrus.Fields{
			"protocol":  s.Protocol(),
			"peer":      s.Conn().RemotePeer().String(),
			"ping_data": fmt.Sprintf("%d", out),
		}).Info("Received data")

		// Construct response
		resp := PingData(p.MetaData.SeqNumber)
		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			logrus.WithError(err).Error("Failed to send status response")
			return
		}
		if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, &resp); err != nil {
			logrus.WithError(err).Error("Failed to encode outgoing message")
			return
		}

		if err := s.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close stream")
			return
		}
	})

	return nil
}
