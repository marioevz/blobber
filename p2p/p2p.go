package p2p

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/pkg/errors"
	bitfield "github.com/prysmaticlabs/go-bitfield"

	"github.com/marioevz/blobber/logger"
)

var sszNetworkEncoder = SszNetworkEncoder{}

const (
	StatusProtocolID   = "/eth2/beacon_chain/req/status/1/" + ProtocolSuffixSSZSnappy
	GoodbyeProtocolID  = "/eth2/beacon_chain/req/goodbye/1/" + ProtocolSuffixSSZSnappy
	PingProtocolID     = "/eth2/beacon_chain/req/ping/1/" + ProtocolSuffixSSZSnappy
	MetaDataProtocolID = "/eth2/beacon_chain/req/metadata/2/" + ProtocolSuffixSSZSnappy

	// Connection timeout for direct peer messaging
	DirectConnectionTimeout = 10 * time.Second
)

const pubsubQueueSize = 600

// Metadata represents p2p metadata of a node
type Metadata struct {
	SeqNumber uint64
	Attnets   bitfield.Bitvector64
	Syncnets  bitfield.Bitvector4
}

// Goodbye is the goodbye reason code
type Goodbye uint64

// Ping is the ping sequence number
type Ping uint64

type TestP2P struct {
	InstanceID  uint64
	peerCounter atomic.Uint64

	// State objects
	ChainStatus  *Status
	lastTestPeer TestPeers
	testPeerUses int

	// Config
	ExternalIP             net.IP
	BeaconPortStart        int64
	MaxDevP2PSessionReuses int

	// Logger
	logger logger.Logger
}

type TestPeerIndex uint64

func (id TestPeerIndex) String() string {
	return fmt.Sprintf("%d", id)
}

func (id TestPeerIndex) Keys(instanceID uint64) (crypto.PrivKey, crypto.PubKey) {
	// Private keys are deterministic for testing purposes.
	privKeyBytes := make([]byte, 32)
	copy(privKeyBytes[:], []byte("blobber"))
	binary.BigEndian.PutUint64(privKeyBytes[16:24], instanceID)
	binary.BigEndian.PutUint64(privKeyBytes[24:], uint64(id))
	priv, err := crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	if err != nil {
		panic(err)
	}
	pub := priv.GetPublic()
	return priv, pub
}

func (id TestPeerIndex) PeerID(instanceID uint64) string {
	priv, _ := id.Keys(instanceID)
	peerID, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return peerID.String()
}

func (t *TestP2P) GetNextPeerIDs(count uint64) []string {
	ids := make([]string, count)
	startID := TestPeerIndex(t.peerCounter.Load() + 1)
	for i := uint64(0); i < count; i++ {
		ids[i] = startID.PeerID(t.InstanceID)
		startID += 1
	}
	return ids
}

type TestPeer struct {
	ID         TestPeerIndex
	Host       host.Host
	PubSub     *pubsub.PubSub
	PrivateKey crypto.PrivKey
	PublicKey  crypto.PubKey
	LocalNode  *enode.LocalNode

	ctx      context.Context
	cancel   context.CancelFunc
	MetaData *Metadata
	state    *Status

	// Topic management
	topicHandles       map[string]*pubsub.Topic
	topicSubscriptions map[string]*pubsub.Subscription

	// Connected beacon nodes tracking
	connectedBeaconNodes map[peer.ID]string // peer ID -> beacon node name
	connectedMutex       sync.RWMutex
	topicMutex           sync.RWMutex

	// Logger
	logger logger.Logger
}

type TestPeers []*TestPeer

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

func (t *TestP2P) GetTestPeer(ctx context.Context, count int) (TestPeers, error) {
	var testPeers TestPeers

	if t.logger != nil {
		t.logger.WithFields(map[string]interface{}{
			"count":          count,
			"has_last_peer":  t.lastTestPeer != nil,
			"test_peer_uses": t.testPeerUses,
			"max_reuses":     t.MaxDevP2PSessionReuses,
		}).Debug("GetTestPeer called")
	}

	if t.lastTestPeer != nil {
		// Check if we should reuse or if the count changed
		shouldReuse := t.MaxDevP2PSessionReuses == 0 || t.testPeerUses < t.MaxDevP2PSessionReuses
		sameCount := len(t.lastTestPeer) == count

		// Also check if peers are still connected
		allConnected := true
		if shouldReuse && sameCount {
			for _, tp := range t.lastTestPeer {
				peerCount := len(tp.Host.Network().Peers())
				if peerCount == 0 {
					if t.logger != nil {
						t.logger.WithFields(map[string]interface{}{
							"peer_id":    tp.Host.ID().String(),
							"peer_count": peerCount,
						}).Debug("Test peer has no connections, will create new peer")
					}
					allConnected = false
					break
				}
			}
		}

		if shouldReuse && sameCount && allConnected {
			testPeers = t.lastTestPeer
			t.testPeerUses++
		} else {
			// Close the last one
			_ = t.lastTestPeer.Close(context.Background())
			t.lastTestPeer = nil
			t.testPeerUses = 0
		}
	}

	if testPeers == nil {
		// Generate a new one
		testPeers = make(TestPeers, 0)
		for i := 0; i < count; i++ {
			testPeer, err := t.NewTestPeer(ctx, t.BeaconPortStart+int64(i))
			if err != nil {
				// close the ones we actually created
				_ = testPeers.Close(context.Background())
				return nil, errors.Wrap(err, "failed to create p2p")
			}
			testPeers = append(testPeers, testPeer)
		}
		t.lastTestPeer = testPeers
		t.testPeerUses = 1
	}

	return testPeers, nil
}

func (t *TestP2P) SetLogger(log logger.Logger) {
	t.logger = log
}

func (t *TestP2P) NewTestPeer(ctx context.Context, port int64) (*TestPeer, error) {
	if t.ChainStatus == nil {
		return nil, errors.New("chain state cannot be nil")
	}

	// Get the ID of this node.
	id := TestPeerIndex(t.peerCounter.Add(1))
	priv, pub := id.Keys(t.InstanceID)

	libp2pOptions := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/%s/tcp/%d", t.ExternalIP.String(), port)),
		libp2p.UserAgent("Blobber/0.1.0"),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer(mplex.ID, mplex.DefaultTransport),
		libp2p.DefaultMuxers,
		libp2p.Security(noise.ID, noise.New),
		libp2p.Ping(false),
		libp2p.Identity(priv),
		libp2p.ResourceManager(&network.NullResourceManager{}),
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
	localNode, err := createLocalNode(pk, t.ExternalIP, int(port), int(port))
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	testPeer := &TestPeer{
		ID:         id,
		Host:       h,
		PubSub:     ps,
		PrivateKey: priv,
		PublicKey:  pub,
		LocalNode:  localNode,
		MetaData: &Metadata{
			SeqNumber: 0,
			Attnets:   bitfield.Bitvector64{},
			Syncnets:  bitfield.Bitvector4{},
		},

		state: t.ChainStatus,

		ctx:                  ctx,
		cancel:               cancel,
		topicHandles:         make(map[string]*pubsub.Topic),
		topicSubscriptions:   make(map[string]*pubsub.Subscription),
		connectedBeaconNodes: make(map[peer.ID]string),
		logger:               t.logger,
	}
	if err := testPeer.SetupStreams(context.Background()); err != nil {
		_ = testPeer.Close(context.Background())
		return nil, err
	}
	return testPeer, nil
}

func (p *TestPeer) Connect(ctx context.Context, peer *BeaconClientPeer) error {
	peerAddrInfo, err := peer.GetPeerAddrInfo(ctx)
	if err != nil {
		return errors.Wrap(err, "could not get peer address info")
	}
	if connectedness := p.Host.Network().Connectedness(peerAddrInfo.ID); connectedness == network.Connected {
		// Already connected, nothing to do
		return nil
	}
	if err := p.Host.Connect(ctx, *peerAddrInfo); err != nil {
		return errors.Wrap(err, "could not connect to peer")
	}

	// Set up disconnect notification
	p.Host.Network().Notify(&network.NotifyBundle{
		DisconnectedF: func(n network.Network, c network.Conn) {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer":  c.RemotePeer().String(),
					"local": c.LocalPeer().String(),
				}).Debug("Peer disconnected")
			}
			// Remove from tracked connections
			p.connectedMutex.Lock()
			delete(p.connectedBeaconNodes, c.RemotePeer())
			p.connectedMutex.Unlock()
		},
	})

	_ = p.Host.Peerstore().AddProtocols(peerAddrInfo.ID, StatusProtocolID, GoodbyeProtocolID, PingProtocolID, MetaDataProtocolID)

	if err := p.SendInitialStatus(ctx, peerAddrInfo.ID); err != nil {
		return errors.Wrap(err, "could not send initial status")
	}

	// Log successful connection
	protocols, _ := p.Host.Peerstore().GetProtocols(peerAddrInfo.ID)
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"local_peer":  p.Host.ID().String(),
			"remote_peer": peerAddrInfo.ID.String(),
			"protocols":   protocols,
		}).Info("Successfully connected to beacon node peer")
	}

	// Track the connection
	p.connectedMutex.Lock()
	p.connectedBeaconNodes[peerAddrInfo.ID] = peerAddrInfo.ID.String()
	p.connectedMutex.Unlock()

	return nil
}

// GetConnectedBeaconPeers returns a list of all connected beacon node peer IDs
func (p *TestPeer) GetConnectedBeaconPeers() []peer.ID {
	p.connectedMutex.RLock()
	defer p.connectedMutex.RUnlock()

	peers := make([]peer.ID, 0, len(p.connectedBeaconNodes))
	for peerID := range p.connectedBeaconNodes {
		// Double-check the peer is still connected
		if p.Host.Network().Connectedness(peerID) == network.Connected {
			peers = append(peers, peerID)
		}
	}
	return peers
}

func (p *TestPeer) SendInitialStatus(ctx context.Context, peer peer.ID) error {
	// Open stream
	peerInfo := p.Host.Peerstore().PeerInfo(peer)
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"id":   p.ID,
			"peer": peerInfo.ID.String(),
		}).Debug("Opening stream")
	}
	s, err := p.Host.NewStream(ctx, peer, StatusProtocolID)
	if err != nil {
		return errors.Wrap(err, "failed to open stream")
	}

	// Log sent request
	p.state.Lock()
	defer p.state.Unlock()
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"id":              p.ID,
			"protocol":        s.Protocol(),
			"peer":            s.Conn().RemotePeer().String(),
			"fork_digest":     fmt.Sprintf("%x", p.state.ForkDigest),
			"finalized_root":  p.state.FinalizedRoot.String(),
			"finalized_epoch": fmt.Sprintf("%d", p.state.FinalizedEpoch),
			"head_root":       p.state.HeadRoot.String(),
			"head_slot":       fmt.Sprintf("%d", p.state.HeadSlot),
		}).Debug("Sending initial status")
	}

	// Send response code first
	if _, err := s.Write([]byte{0x00}); err != nil {
		return errors.Wrap(err, "failed to write response code")
	}
	// Send request
	if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(p.state.StatusData)); err != nil {
		return errors.Wrap(err, "failed to encode outgoing message")
	}
	// Done sending request
	if err := s.CloseWrite(); err != nil {
		return errors.Wrap(err, "failed to close+write")
	}

	// Read the status response from the peer
	// First read the response code
	responseByte := make([]byte, 1)
	if _, err := io.ReadFull(s, responseByte); err != nil {
		if p.logger != nil {
			p.logger.WithField("error", err).Warn("Failed to read response code")
		}
		// Don't fail here - some nodes might not respond properly
	} else if responseByte[0] != 0x00 {
		if p.logger != nil {
			p.logger.WithField("code", fmt.Sprintf("0x%02x", responseByte[0])).Warn("Received non-success response code")
		}
	} else {
		// Read the actual status message
		var status StatusData
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, &status); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Warn("Failed to decode status response from peer")
			}
		} else {
			// Check if fork digests match
			if status.ForkDigest != p.state.ForkDigest {
				if p.logger != nil {
					p.logger.WithFields(map[string]interface{}{
						"our_fork_digest":  fmt.Sprintf("%x", p.state.ForkDigest),
						"peer_fork_digest": fmt.Sprintf("%x", status.ForkDigest),
					}).Warn("Fork digest mismatch with peer")
				}
			}
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"our_fork_digest":      fmt.Sprintf("%x", p.state.ForkDigest),
					"peer_fork_digest":     fmt.Sprintf("%x", status.ForkDigest),
					"peer_finalized_root":  status.FinalizedRoot.String(),
					"peer_finalized_epoch": fmt.Sprintf("%d", status.FinalizedEpoch),
					"peer_head_root":       status.HeadRoot.String(),
					"peer_head_slot":       fmt.Sprintf("%d", status.HeadSlot),
				}).Debug("Received status response from peer")
			}
		}
	}

	// Close the stream properly
	if err := s.Close(); err != nil {
		if p.logger != nil {
			p.logger.WithField("error", err).Debug("Failed to close status stream")
		}
	}

	return nil
}

func (p *TestPeer) Close(ctx context.Context) error {
	// Close all topic handles
	p.topicMutex.Lock()
	// First cancel all subscriptions
	for topic, sub := range p.topicSubscriptions {
		sub.Cancel()
		if p.logger != nil {
			p.logger.WithField("topic", topic).Debug("Canceled topic subscription")
		}
	}
	// Wait a bit for subscription goroutines to exit
	time.Sleep(100 * time.Millisecond)
	// Now close topic handles
	for topic, handle := range p.topicHandles {
		if err := handle.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"error": err,
					"topic": topic,
				}).Error("Failed to close topic handle")
			}
		}
	}
	p.topicHandles = make(map[string]*pubsub.Topic)
	p.topicSubscriptions = make(map[string]*pubsub.Subscription)
	p.topicMutex.Unlock()

	// Send goodbye to each peer
	peers := p.Host.Network().Peers()
	if len(peers) > 0 {
		for i, peer := range peers {
			if err := p.Goodbye(p.ctx, peer); err != nil {
				if p.logger != nil {
					p.logger.WithField("error", err).Errorf("failed to send goodbye to peer %d", i)
				}
			}
		}
	}
	defer p.cancel()
	return p.Host.Close()
}

func (pl TestPeers) Close(ctx context.Context) error {
	for _, p := range pl {
		if err := p.Close(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (p *TestPeer) WaitForP2PConnection(ctx context.Context) error {
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

func (p *TestPeer) SetupStreams(ctx context.Context) error {
	// Prepare stream responses for the basic Req/Resp protocols.

	// Status
	if p.logger != nil {
		p.logger.Debug("Setting up status handler")
	}
	p.Host.SetStreamHandler(StatusProtocolID, func(s network.Stream) {
		defer func() {
			if p.logger != nil {
				p.logger.Debug("Finished responding to status request")
			}
		}()
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
			}).Debug("Got a new stream")
		}
		// Read the incoming message into the appropriate struct.
		var out StatusData
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, WrapSSZObject(&out)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to decode incoming message")
			}
			return
		}
		// Log received data
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":              p.ID,
				"protocol":        s.Protocol(),
				"peer":            s.Conn().RemotePeer().String(),
				"fork_digest":     fmt.Sprintf("%x", out.ForkDigest),
				"finalized_root":  out.FinalizedRoot.String(),
				"finalized_epoch": fmt.Sprintf("%d", out.FinalizedEpoch),
				"head_root":       out.HeadRoot.String(),
				"head_slot":       fmt.Sprintf("%d", out.HeadSlot),
			}).Debug("Received data")
		}

		// Construct response
		p.state.Lock()
		defer p.state.Unlock()

		// Log received data
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":              p.ID,
				"protocol":        s.Protocol(),
				"peer":            s.Conn().RemotePeer().String(),
				"fork_digest":     fmt.Sprintf("%x", p.state.ForkDigest),
				"finalized_root":  p.state.FinalizedRoot.String(),
				"finalized_epoch": fmt.Sprintf("%d", p.state.FinalizedEpoch),
				"head_root":       p.state.HeadRoot.String(),
				"head_slot":       fmt.Sprintf("%d", p.state.HeadSlot),
			}).Debug("Response data")
		}

		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to send status response")
			}
			return
		}
		if n, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(p.state.StatusData)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to encode outgoing message")
			}
			return
		} else {
			if p.logger != nil {
				p.logger.WithField("bytes", n).Debug("Sent data")
			}
		}
		// Try to close the stream, but don't worry if it fails (might already be closed)
		if err := s.Close(); err != nil {
			// Only log as debug since this often happens when peer closes first
			if p.logger != nil {
				p.logger.WithField("error", err).Debug("Stream close error (expected if peer closed first)")
			}
			return
		}
	})

	// Goodbye
	if p.logger != nil {
		p.logger.Debug("Setting up goodbye handler")
	}
	p.Host.SetStreamHandler(GoodbyeProtocolID, func(s network.Stream) {
		defer func() {
			if p.logger != nil {
				p.logger.Debug("Finished responding to goodbye request")
			}
		}()
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
			}).Debug("Got a new stream")
		}
		// Read the incoming message into the appropriate struct.
		var out Goodbye
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, WrapSSZObject(&out)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to decode incoming message")
			}
			return
		}
		// Log received data
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
				"reason":   fmt.Sprintf("%d", out),
			}).Debug("Received data")
		}

		// Construct response
		var resp Goodbye

		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to send status response")
			}
			return
		}
		if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(&resp)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to encode outgoing message")
			}
			return
		}

		if err := s.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to close stream")
			}
			return
		}
	})

	// Ping
	if p.logger != nil {
		p.logger.Debug("Setting up ping handler")
	}
	p.Host.SetStreamHandler(PingProtocolID, func(s network.Stream) {
		defer func() {
			if p.logger != nil {
				p.logger.Debug("Finished responding to ping request")
			}
		}()
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
			}).Debug("Got a new stream")
		}
		// Read the incoming message into the appropriate struct.
		var out Ping
		if err := sszNetworkEncoder.DecodeWithMaxLength(s, WrapSSZObject(&out)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to decode incoming message")
			}
			return
		}
		// Log received data
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":        p.ID,
				"protocol":  s.Protocol(),
				"peer":      s.Conn().RemotePeer().String(),
				"ping_data": fmt.Sprintf("%d", out),
			}).Debug("Received data")
		}

		// Construct response
		resp := Ping(p.MetaData.SeqNumber)
		// Send response
		if _, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to send status response")
			}
			return
		}
		if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(&resp)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to encode outgoing message")
			}
			return
		}

		if err := s.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to close stream")
			}
			return
		}
	})

	// MetaData
	if p.logger != nil {
		p.logger.Debug("Setting up metadata handler")
	}
	p.Host.SetStreamHandler(MetaDataProtocolID, func(s network.Stream) {
		defer func() {
			if p.logger != nil {
				p.logger.Debug("Finished responding to metadata request")
			}
		}()
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
			}).Debug("Got a new stream")
		}

		// Construct response
		resp := p.MetaData
		// Send response
		totalBytesWritten := 0
		if n, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to send status response")
			}
			return
		} else {
			totalBytesWritten += n
		}
		if n, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(resp)); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to encode outgoing message")
			}
			return
		} else {
			totalBytesWritten += n
		}

		if p.logger != nil {
			p.logger.WithField("bytes", totalBytesWritten).Debug("Sent data")
		}

		if err := s.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to close stream")
			}
			return
		}
	})

	// BeaconBlocksBy range handler
	if p.logger != nil {
		p.logger.Debug("Setting up beacon blocks by range handler")
	}
	p.Host.SetStreamHandler(BeaconBlockProtocolID, func(s network.Stream) {
		defer func() {
			if p.logger != nil {
				p.logger.Debug("Finished responding to beacon blocks by range request")
			}
		}()
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
			}).Debug("Got a new beacon blocks by range stream")
		}

		// Read the incoming beacon block data (we don't need to parse it for testing)
		data := make([]byte, 10*1024*1024) // 10MB buffer for beacon block data
		n, err := s.Read(data)
		if err != nil && err != io.EOF {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to read beacon block data")
			}
			return
		}

		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":        p.ID,
				"protocol":  s.Protocol(),
				"peer":      s.Conn().RemotePeer().String(),
				"data_size": n,
			}).Debug("Received beacon block data")
		}

		// Send acknowledgment response
		if _, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to send beacon block acknowledgment")
			}
			return
		}

		if err := s.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Debug("Beacon block stream close error")
			}
		}
	})

	// BlobSidecarsByRange handler
	if p.logger != nil {
		p.logger.Debug("Setting up blob sidecars by range handler")
	}
	p.Host.SetStreamHandler(BlobSidecarProtocolID, func(s network.Stream) {
		defer func() {
			if p.logger != nil {
				p.logger.Debug("Finished responding to blob sidecars by range request")
			}
		}()
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":       p.ID,
				"protocol": s.Protocol(),
				"peer":     s.Conn().RemotePeer().String(),
			}).Debug("Got a new blob sidecars by range stream")
		}

		// Read the incoming blob sidecar data (we don't need to parse it for testing)
		data := make([]byte, 150*1024*1024) // 150MB buffer for blob sidecar data (blobs can be large)
		n, err := s.Read(data)
		if err != nil && err != io.EOF {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to read blob sidecar data")
			}
			return
		}

		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"id":        p.ID,
				"protocol":  s.Protocol(),
				"peer":      s.Conn().RemotePeer().String(),
				"data_size": n,
			}).Debug("Received blob sidecar data")
		}

		// Send acknowledgment response
		if _, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Error("Failed to send blob sidecar acknowledgment")
			}
			return
		}

		if err := s.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithField("error", err).Debug("Blob sidecar stream close error")
			}
		}
	})

	return nil
}

// GetOrJoinTopic returns an existing topic handle or creates a new one
func (p *TestPeer) GetOrJoinTopic(topic string, opts ...pubsub.TopicOpt) (*pubsub.Topic, error) {
	p.topicMutex.Lock()
	defer p.topicMutex.Unlock()

	// Check if we already have this topic
	if handle, exists := p.topicHandles[topic]; exists {
		return handle, nil
	}

	// Join the topic
	handle, err := p.PubSub.Join(topic, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to join topic")
	}

	// Subscribe to the topic to join the gossip mesh
	// This is necessary for peers to see us in their topic peer list
	sub, err := handle.Subscribe()
	if err != nil {
		_ = handle.Close()
		return nil, errors.Wrap(err, "failed to subscribe to topic")
	}

	// We need to keep the subscription alive but we're not actually reading messages
	// Start a goroutine to consume messages (and discard them)
	go func() {
		ctx := p.ctx
		for {
			_, err := sub.Next(ctx)
			if err != nil {
				// Context cancelled or subscription closed
				return
			}
			// We're just discarding messages since we're only broadcasting
		}
	}()

	// Store the handle and subscription
	p.topicHandles[topic] = handle
	if p.topicSubscriptions == nil {
		p.topicSubscriptions = make(map[string]*pubsub.Subscription)
	}
	p.topicSubscriptions[topic] = sub

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"topic":         topic,
			"peer_id":       p.Host.ID().String(),
			"network_peers": len(p.Host.Network().Peers()),
		}).Debug("Successfully joined and subscribed to topic")
	}

	// Give the gossip mesh time to stabilize after subscription
	// We'll wait a bit here but PublishTopic will also wait for peers
	time.Sleep(500 * time.Millisecond)

	// Check if we have any peers in the topic after waiting
	peers := handle.ListPeers()
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"topic":      topic,
			"peer_count": len(peers),
			"peers":      peers,
		}).Info("Topic peers after subscription and wait")
	}

	return handle, nil
}

// ConnectToPeerTemporarily connects to a peer temporarily for direct messaging
func (p *TestPeer) ConnectToPeerTemporarily(ctx context.Context, peerAddr string) (peer.ID, error) {
	start := time.Now()
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_addr": peerAddr,
		}).Debug("Attempting temporary connection to peer")
	}

	// Parse multiaddr
	maddr, err := ma.NewMultiaddr(peerAddr)
	if err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_addr": peerAddr,
				"error":     err.Error(),
			}).Error("Failed to parse peer multiaddr")
		}
		return "", errors.Wrap(err, "failed to parse peer multiaddr")
	}

	// Extract peer ID from multiaddr
	addrInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_addr": peerAddr,
				"error":     err.Error(),
			}).Error("Failed to extract peer ID from multiaddr")
		}
		return "", errors.Wrap(err, "failed to extract peer ID from multiaddr")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_addr": peerAddr,
			"peer_id":   addrInfo.ID.String(),
		}).Debug("Extracted peer ID from multiaddr")
	}

	// Check if already connected
	if p.Host.Network().Connectedness(addrInfo.ID) == network.Connected {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id": addrInfo.ID.String(),
			}).Debug("Already connected to peer")
		}
		return addrInfo.ID, nil
	}

	// Connect with timeout
	connCtx, cancel := context.WithTimeout(ctx, DirectConnectionTimeout)
	defer cancel()

	if err := p.Host.Connect(connCtx, *addrInfo); err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_addr": peerAddr,
				"peer_id":   addrInfo.ID.String(),
				"error":     err.Error(),
			}).Error("Failed to connect to peer")
		}
		return "", errors.Wrap(err, "failed to connect to peer")
	}

	duration := time.Since(start)
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_addr":   peerAddr,
			"peer_id":     addrInfo.ID.String(),
			"duration_ms": duration.Milliseconds(),
		}).Info("Successfully connected to peer")
	}

	return addrInfo.ID, nil
}

// SendGoodbyeAndDisconnect sends a graceful goodbye message and disconnects from peer
func (p *TestPeer) SendGoodbyeAndDisconnect(ctx context.Context, peerID peer.ID, reason uint64) error {
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id": peerID.String(),
			"reason":  reason,
		}).Debug("Sending goodbye message to peer")
	}

	// Send goodbye message with timeout
	goodbyeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Open stream for goodbye
	s, err := p.Host.NewStream(goodbyeCtx, peerID, GoodbyeProtocolID)
	if err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id": peerID.String(),
				"error":   err.Error(),
			}).Warn("Failed to open goodbye stream (proceeding with disconnect)")
		}
		// Continue with disconnect even if goodbye fails
	} else {
		// Send goodbye message
		goodbyeMsg := Goodbye(reason)
		if _, err := s.Write([]byte{0x00}); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Warn("Failed to write goodbye response code")
			}
		} else if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(&goodbyeMsg)); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Warn("Failed to encode goodbye message")
			}
		} else {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"reason":  reason,
				}).Debug("Goodbye message sent successfully")
			}
		}

		// Close write side and try to read acknowledgment
		if err := s.CloseWrite(); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Debug("Failed to close write side of goodbye stream")
			}
		}

		// Try to read acknowledgment with timeout
		s.SetReadDeadline(time.Now().Add(1 * time.Second))
		respBuf := make([]byte, 1)
		if _, err := s.Read(respBuf); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Debug("No acknowledgment received for goodbye (expected)")
			}
		} else {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
				}).Debug("Goodbye acknowledgment received")
			}
		}

		// Close the stream
		if err := s.Close(); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Debug("Failed to close goodbye stream")
			}
		}
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id": peerID.String(),
		}).Debug("Closing all streams to peer")
	}

	// Close all streams to the peer
	connections := p.Host.Network().ConnsToPeer(peerID)
	for _, conn := range connections {
		streams := conn.GetStreams()
		for _, stream := range streams {
			if err := stream.Close(); err != nil {
				if p.logger != nil {
					p.logger.WithFields(map[string]interface{}{
						"peer_id":   peerID.String(),
						"stream_id": stream.ID(),
						"error":     err.Error(),
					}).Debug("Failed to close stream")
				}
			}
		}
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id": peerID.String(),
		}).Info("Disconnecting from peer")
	}

	// Disconnect from the peer
	if err := p.Host.Network().ClosePeer(peerID); err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id": peerID.String(),
				"error":   err.Error(),
			}).Warn("Failed to close peer connection")
		}
		return errors.Wrap(err, "failed to close peer connection")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id": peerID.String(),
		}).Debug("Peer disconnection complete")
	}

	return nil
}

func (p *TestPeer) Goodbye(ctx context.Context, peer peer.ID) error {
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	// Open stream
	s, err := p.Host.NewStream(ctx, peer, GoodbyeProtocolID)
	if err != nil {
		return errors.Wrap(err, "failed to open stream")
	}

	var resp Goodbye
	if _, err := s.Write([]byte{0x00}); err != nil {
		return errors.Wrap(err, "failed write response chunk byte")
	}
	if _, err := sszNetworkEncoder.EncodeWithMaxLength(s, WrapSSZObject(&resp)); err != nil {
		return errors.Wrap(err, "failed write goodbye message")
	}

	if err := s.CloseWrite(); err != nil {
		return errors.Wrap(err, "failed to close stream")
	}

	return nil
}
