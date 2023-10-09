package p2p

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/marioevz/blobber/common"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/muxer/mplex"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	"github.com/pkg/errors"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/sirupsen/logrus"

	"github.com/prysmaticlabs/prysm/v4/beacon-chain/p2p/encoder"
	"github.com/prysmaticlabs/prysm/v4/consensus-types/primitives"
)

var sszNetworkEncoder = encoder.SszNetworkEncoder{}

type Goodbye = primitives.SSZUint64
type PingData = primitives.SSZUint64

const (
	StatusProtocolID   = "/eth2/beacon_chain/req/status/1/" + encoder.ProtocolSuffixSSZSnappy
	GoodbyeProtocolID  = "/eth2/beacon_chain/req/goodbye/1/" + encoder.ProtocolSuffixSSZSnappy
	PingProtocolID     = "/eth2/beacon_chain/req/ping/1/" + encoder.ProtocolSuffixSSZSnappy
	MetaDataProtocolID = "/eth2/beacon_chain/req/metadata/2/" + encoder.ProtocolSuffixSSZSnappy
)

const pubsubQueueSize = 600

type TestP2P struct {
	Host       host.Host
	PubSub     *pubsub.PubSub
	PrivateKey crypto.PrivKey
	PublicKey  crypto.PubKey
	LocalNode  *enode.LocalNode

	ctx      context.Context
	cancel   context.CancelFunc
	MetaData *eth.MetaDataV1
	state    *common.Status
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

func NewTestP2P(ctx context.Context, ip net.IP, port int64, chainState *common.Status) (*TestP2P, error) {
	if chainState == nil {
		return nil, errors.New("chain state cannot be nil")
	}

	// Generate a new private key pair for this host.
	priv, pub, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		return nil, err
	}

	libp2pOptions := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", ip.String(), port)), libp2p.UserAgent("HiveSim/0.1.0"),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
		libp2p.DefaultMuxers,
		libp2p.Security(noise.ID, noise.New),
		libp2p.Ping(false),
		libp2p.Identity(priv),
	}

	h, err := libp2p.New(libp2pOptions...)
	if err != nil {
		return nil, err
	}

	ps, err := pubsub.NewGossipSub(context.Background(), h,
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		pubsub.WithNoAuthor(),
		pubsub.WithPeerOutboundQueueSize(pubsubQueueSize),
		pubsub.WithValidateQueueSize(pubsubQueueSize),
		pubsub.WithMaxMessageSize(10*1<<20), // 10 MiB
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

	ctx, cancel := context.WithCancel(ctx)
	testP2P := &TestP2P{
		Host:       h,
		PubSub:     ps,
		PrivateKey: priv,
		PublicKey:  pub,
		LocalNode:  localNode,
		MetaData: &eth.MetaDataV1{
			SeqNumber: 0,
			Attnets:   make([]byte, 8),
			Syncnets:  make([]byte, 1),
		},

		state: chainState,

		ctx:    ctx,
		cancel: cancel,
	}
	if err := testP2P.SetupStreams(); err != nil {
		testP2P.Close()
		return nil, err
	}
	return testP2P, nil
}

func (p *TestP2P) Connect(ctx context.Context, peer *BeaconClientPeer) error {
	peerAddrInfo, err := peer.GetPeerAddrInfo(ctx)
	if err != nil {
		return errors.Wrap(err, "could not get peer address info")
	}
	if err := p.Host.Connect(p.ctx, *peerAddrInfo); err != nil {
		return errors.Wrap(err, "could not connect to peer")
	}

	p.Host.Peerstore().AddProtocols(peerAddrInfo.ID, StatusProtocolID, GoodbyeProtocolID, PingProtocolID, MetaDataProtocolID)

	if err := p.SendInitialStatus(ctx, peerAddrInfo.ID); err != nil {
		return errors.Wrap(err, "could not send initial status")
	}
	return nil
}

func (p *TestP2P) SendInitialStatus(ctx context.Context, peer peer.ID) error {
	// Open stream
	peerInfo := p.Host.Peerstore().PeerInfo(peer)
	logrus.WithFields(logrus.Fields{
		"peer": peerInfo.ID.String(),
	}).Debug("Opening stream")
	s, err := p.Host.NewStream(ctx, peer, StatusProtocolID)
	if err != nil {
		return errors.Wrap(err, "failed to open stream")
	}

	// Log sent request
	p.state.Lock()
	defer p.state.Unlock()
	logrus.WithFields(logrus.Fields{
		"protocol":        s.Protocol(),
		"peer":            s.Conn().RemotePeer().String(),
		"fork_digest":     fmt.Sprintf("%x", p.state.ForkDigest),
		"finalized_root":  fmt.Sprintf("%x", p.state.FinalizedRoot),
		"finalized_epoch": fmt.Sprintf("%d", p.state.FinalizedEpoch),
		"head_root":       fmt.Sprintf("%x", p.state.HeadRoot),
		"head_slot":       fmt.Sprintf("%d", p.state.HeadSlot),
	}).Debug("Sending initial status")

	// Send request
	if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, p.state); err != nil {
		return errors.Wrap(err, "failed to encode outgoing message")
	}
	// Done sending request
	if err := s.CloseWrite(); err != nil {
		return errors.Wrap(err, "failed to close+write")
	}

	return nil
}

func (p *TestP2P) Close() error {
	p.cancel()
	return p.Host.Close()
}

func (p *TestP2P) WaitForP2PConnection(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
			if len(p.Host.Network().Peers()) > 0 {
				return nil
			}
		}
	}
}

func (p *TestP2P) SetupStreams() error {
	// Prepare stream responses for the basic Req/Resp protocols.

	// Status
	p.Host.SetStreamHandler(StatusProtocolID, func(s network.Stream) {
		// Read the incoming message into the appropriate struct.
		var out common.Status
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
		}).Debug("Received data")

		// Construct response
		p.state.Lock()
		defer p.state.Unlock()

		// Log received data
		logrus.WithFields(logrus.Fields{
			"protocol":        s.Protocol(),
			"peer":            s.Conn().RemotePeer().String(),
			"fork_digest":     fmt.Sprintf("%x", p.state.ForkDigest),
			"finalized_root":  fmt.Sprintf("%x", p.state.FinalizedRoot),
			"finalized_epoch": fmt.Sprintf("%d", p.state.FinalizedEpoch),
			"head_root":       fmt.Sprintf("%x", p.state.HeadRoot),
			"head_slot":       fmt.Sprintf("%d", p.state.HeadSlot),
		}).Debug("Response data")

		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			logrus.WithError(err).Error("Failed to send status response")
			return
		}
		if n, err := sszNetworkEncoder.EncodeWithMaxLength(s, p.state); err != nil {
			logrus.WithError(err).Error("Failed to encode outgoing message")
			return
		} else {
			logrus.WithField("bytes", n).Debug("Sent data")
		}
		if err := s.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close stream")
			return
		}
	})

	// Goodbye
	p.Host.SetStreamHandler(GoodbyeProtocolID, func(s network.Stream) {
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
		}).Debug("Received data")

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
	p.Host.SetStreamHandler(PingProtocolID, func(s network.Stream) {
		logrus.WithFields(logrus.Fields{
			"protocol": s.Protocol(),
			"peer":     s.Conn().RemotePeer().String(),
		}).Debug("Got a new stream")
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
		}).Debug("Received data")

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

	// MetaData
	p.Host.SetStreamHandler(MetaDataProtocolID, func(s network.Stream) {
		logrus.WithFields(logrus.Fields{
			"protocol": s.Protocol(),
			"peer":     s.Conn().RemotePeer().String(),
		}).Debug("Got a new stream")

		// Construct response
		resp := p.MetaData
		// Send response
		totalBytesWritten := 0
		if n, err := s.Write([]byte{0x00}); err != nil {
			logrus.WithError(err).Error("Failed to send status response")
			return
		} else {
			totalBytesWritten += n
		}
		if n, err := sszNetworkEncoder.EncodeWithMaxLength(s, resp); err != nil {
			logrus.WithError(err).Error("Failed to encode outgoing message")
			return
		} else {
			totalBytesWritten += n
		}

		logrus.WithField("bytes", totalBytesWritten).Debug("Sent data")

		if err := s.Close(); err != nil {
			logrus.WithError(err).Error("Failed to close stream")
			return
		}
	})

	return nil
}
