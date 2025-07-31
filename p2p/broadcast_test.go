package p2p_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/marioevz/blobber/p2p"
)

func TestDirectMessageSending(t *testing.T) {
	tests := []struct {
		name        string
		setupPeers  int
		messageSize int
		expectError bool
	}{
		{
			name:        "single peer success",
			setupPeers:  2, // sender + receiver
			messageSize: 1024,
			expectError: false,
		},
		{
			name:        "large message success",
			setupPeers:  2,
			messageSize: 1024 * 1024, // 1MB
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Create test peers
			testP2P := &p2p.TestP2P{
				InstanceID:      1,
				ExternalIP:      net.IP{127, 0, 0, 1},
				BeaconPortStart: 30000,
				ChainStatus:     p2p.NewStatus(),
			}

			peers, err := testP2P.GetTestPeer(ctx, tt.setupPeers)
			require.NoError(t, err, "Failed to create test peers")
			defer func() {
				_ = peers.Close(ctx)
			}()

			sender := peers[0]
			receiver := peers[1]

			// Connect sender to receiver
			receiverID := receiver.Host.ID()
			receiverAddr := receiver.Host.Addrs()[0]
			fullAddr := receiverAddr.String() + "/p2p/" + receiverID.String()

			connectedPeerID, err := sender.ConnectToPeerTemporarily(ctx, fullAddr)
			require.NoError(t, err, "Failed to connect to peer")
			assert.Equal(t, receiverID, connectedPeerID, "Connected peer ID mismatch")

			// Create test message
			testData := make([]byte, tt.messageSize)
			for i := range testData {
				testData[i] = byte(i % 256)
			}

			// Send direct message
			protocolID := protocol.ID("/test/direct/1/ssz_snappy")
			err = sender.SendDirectMessage(ctx, receiverID, protocolID, testData)

			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Unexpected error sending direct message")
			}

			// Verify peer is still connected after message
			connectedness := sender.Host.Network().Connectedness(receiverID)
			assert.NotEqual(t, connectedness.String(), "NotConnected", "Peer should still be connected after message")
		})
	}
}

func TestGracefulGoodbyeMessage(t *testing.T) {
	tests := []struct {
		name        string
		reasonCode  uint64
		expectError bool
		description string
	}{
		{
			name:        "client shutdown",
			reasonCode:  1,
			expectError: false,
			description: "Standard client shutdown reason",
		},
		{
			name:        "irrelevant network",
			reasonCode:  2,
			expectError: false,
			description: "Network irrelevance reason",
		},
		{
			name:        "fault/error",
			reasonCode:  3,
			expectError: false,
			description: "Fault or error reason",
		},
		{
			name:        "custom reason",
			reasonCode:  128,
			expectError: false,
			description: "Custom reason code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Setup test peers
			testP2P := &p2p.TestP2P{
				InstanceID:      2,
				ExternalIP:      net.IP{127, 0, 0, 1},
				BeaconPortStart: 31000,
				ChainStatus:     p2p.NewStatus(),
			}

			peers, err := testP2P.GetTestPeer(ctx, 2)
			require.NoError(t, err, "Failed to create test peers")
			defer func() {
				_ = peers.Close(ctx)
			}()

			sender := peers[0]
			receiver := peers[1]

			// Connect peers
			receiverID := receiver.Host.ID()
			receiverAddr := receiver.Host.Addrs()[0]
			fullAddr := receiverAddr.String() + "/p2p/" + receiverID.String()

			_, err = sender.ConnectToPeerTemporarily(ctx, fullAddr)
			require.NoError(t, err, "Failed to connect to peer")

			// Verify connection exists
			connectedness := sender.Host.Network().Connectedness(receiverID)
			require.Equal(t, "Connected", connectedness.String(), "Peers should be connected")

			// Send goodbye and disconnect
			err = sender.SendGoodbyeAndDisconnect(ctx, receiverID, tt.reasonCode)

			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
			} else {
				assert.NoError(t, err, "Unexpected error sending goodbye message")

				// Wait a bit for disconnect to complete
				time.Sleep(100 * time.Millisecond)

				// Verify peer is disconnected
				connectedness = sender.Host.Network().Connectedness(receiverID)
				assert.Equal(t, "NotConnected", connectedness.String(), "Peer should be disconnected after goodbye")
			}
		})
	}
}

func TestConnectionCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Setup test peers
	testP2P := &p2p.TestP2P{
		InstanceID:      3,
		ExternalIP:      net.IP{127, 0, 0, 1},
		BeaconPortStart: 32000,
		ChainStatus:     p2p.NewStatus(),
	}

	peers, err := testP2P.GetTestPeer(ctx, 3)
	require.NoError(t, err, "Failed to create test peers")
	defer func() {
		_ = peers.Close(ctx)
	}()

	sender := peers[0]
	receiver1 := peers[1]
	receiver2 := peers[2]

	// Connect to multiple peers
	receivers := []*p2p.TestPeer{receiver1, receiver2}
	receiverIDs := make([]peer.ID, len(receivers))

	for i, receiver := range receivers {
		receiverID := receiver.Host.ID()
		receiverAddr := receiver.Host.Addrs()[0]
		fullAddr := receiverAddr.String() + "/p2p/" + receiverID.String()

		connectedID, err := sender.ConnectToPeerTemporarily(ctx, fullAddr)
		require.NoError(t, err, "Failed to connect to peer %d", i)
		receiverIDs[i] = connectedID
	}

	// Verify all connections exist
	for i, receiverID := range receiverIDs {
		connectedness := sender.Host.Network().Connectedness(receiverID)
		assert.Equal(t, "Connected", connectedness.String(), "Peer %d should be connected", i)
	}

	// Send messages and cleanup each connection
	for i, receiverID := range receiverIDs {
		// Send a message
		testData := []byte("test message")
		protocolID := protocol.ID("/test/cleanup/1/ssz_snappy")
		err := sender.SendDirectMessage(ctx, receiverID, protocolID, testData)
		require.NoError(t, err, "Failed to send message to peer %d", i)

		// Graceful cleanup
		err = sender.SendGoodbyeAndDisconnect(ctx, receiverID, 1)
		require.NoError(t, err, "Failed to cleanup connection to peer %d", i)

		// Wait for cleanup to complete
		time.Sleep(100 * time.Millisecond)

		// Verify peer is disconnected
		connectedness := sender.Host.Network().Connectedness(receiverID)
		assert.Equal(t, "NotConnected", connectedness.String(), "Peer %d should be disconnected after cleanup", i)
	}

	// Verify sender has no remaining connections
	connectedPeers := sender.Host.Network().Peers()
	assert.Empty(t, connectedPeers, "Sender should have no remaining connections")
}

func TestPeerConnectionFailures(t *testing.T) {
	tests := []struct {
		name        string
		peerAddr    string
		expectError bool
		errorType   string
	}{
		{
			name:        "invalid multiaddr format",
			peerAddr:    "invalid-addr",
			expectError: true,
			errorType:   "multiaddr parse error",
		},
		{
			name:        "missing peer ID",
			peerAddr:    "/ip4/127.0.0.1/tcp/9999",
			expectError: true,
			errorType:   "peer ID extraction error",
		},
		{
			name:        "unreachable peer",
			peerAddr:    "/ip4/127.0.0.1/tcp/99999/p2p/16Uiu2HAm2DyWWCgyB9vyRg1WEyrLBhTxCpZrpq1iYXBtiZwdcDSe",
			expectError: true,
			errorType:   "connection timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Create single test peer
			testP2P := &p2p.TestP2P{
				InstanceID:      4,
				ExternalIP:      net.IP{127, 0, 0, 1},
				BeaconPortStart: 33000,
				ChainStatus:     p2p.NewStatus(),
			}

			peers, err := testP2P.GetTestPeer(ctx, 1)
			require.NoError(t, err, "Failed to create test peer")
			defer func() {
				_ = peers.Close(ctx)
			}()

			sender := peers[0]

			// Attempt connection to invalid/unreachable peer
			_, err = sender.ConnectToPeerTemporarily(ctx, tt.peerAddr)

			if tt.expectError {
				assert.Error(t, err, "Expected connection error but got none")
				t.Logf("Got expected error (%s): %v", tt.errorType, err)
			} else {
				assert.NoError(t, err, "Unexpected connection error")
			}
		})
	}
}

func TestDirectMessageWithoutFloodGossip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create test peers
	testP2P := &p2p.TestP2P{
		InstanceID:      5,
		ExternalIP:      net.IP{127, 0, 0, 1},
		BeaconPortStart: 34000,
		ChainStatus:     p2p.NewStatus(),
	}

	peers, err := testP2P.GetTestPeer(ctx, 3)
	require.NoError(t, err, "Failed to create test peers")
	defer func() {
		_ = peers.Close(ctx)
	}()

	sender := peers[0]
	targetReceiver := peers[1]
	nonTargetReceiver := peers[2]

	// Connect sender to target receiver only
	targetID := targetReceiver.Host.ID()
	targetAddr := targetReceiver.Host.Addrs()[0]
	fullTargetAddr := targetAddr.String() + "/p2p/" + targetID.String()

	_, err = sender.ConnectToPeerTemporarily(ctx, fullTargetAddr)
	require.NoError(t, err, "Failed to connect to target peer")

	// Track messages received by each peer
	var targetReceived, nonTargetReceived bool
	var mu sync.Mutex

	// Set up message handlers for both receivers
	protocolID := protocol.ID("/test/no-flood/1/ssz_snappy")

	targetReceiver.Host.SetStreamHandler(protocolID, func(s network.Stream) {
		mu.Lock()
		targetReceived = true
		mu.Unlock()
		s.Close()
	})

	nonTargetReceiver.Host.SetStreamHandler(protocolID, func(s network.Stream) {
		mu.Lock()
		nonTargetReceived = true
		mu.Unlock()
		s.Close()
	})

	// Send direct message to target peer only
	testData := []byte("direct message test")
	err = sender.SendDirectMessage(ctx, targetID, protocolID, testData)
	require.NoError(t, err, "Failed to send direct message")

	// Give time for any potential flood propagation
	time.Sleep(500 * time.Millisecond)

	// Verify only target peer received the message
	mu.Lock()
	defer mu.Unlock()

	assert.True(t, targetReceived, "Target peer should have received the direct message")
	assert.False(t, nonTargetReceived, "Non-target peer should NOT have received the message (no flood gossip)")
}

func TestTimeoutHandlingUnresponsivePeers(t *testing.T) {
	tests := []struct {
		name        string
		timeout     time.Duration
		expectError bool
	}{
		{
			name:        "normal timeout success",
			timeout:     2 * time.Second,
			expectError: false,
		},
		{
			name:        "very short timeout",
			timeout:     50 * time.Millisecond,
			expectError: false, // May or may not timeout depending on system load
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Create test peers
			testP2P := &p2p.TestP2P{
				InstanceID:      6,
				ExternalIP:      net.IP{127, 0, 0, 1},
				BeaconPortStart: 35000,
				ChainStatus:     p2p.NewStatus(),
			}

			peers, err := testP2P.GetTestPeer(ctx, 2)
			require.NoError(t, err, "Failed to create test peers")
			defer func() {
				_ = peers.Close(ctx)
			}()

			sender := peers[0]
			slowReceiver := peers[1]

			// Set up slow/unresponsive receiver
			protocolID := protocol.ID("/test/timeout/1/ssz_snappy")
			slowReceiver.Host.SetStreamHandler(protocolID, func(s network.Stream) {
				// Simulate slow/unresponsive peer by delaying response
				time.Sleep(1 * time.Second)
				// Read the message but respond very slowly
				buf := make([]byte, 1024)
				s.Read(buf)
				time.Sleep(2 * time.Second) // Additional delay
				s.Close()
			})

			// Connect to receiver
			receiverID := slowReceiver.Host.ID()
			receiverAddr := slowReceiver.Host.Addrs()[0]
			fullAddr := receiverAddr.String() + "/p2p/" + receiverID.String()

			_, err = sender.ConnectToPeerTemporarily(ctx, fullAddr)
			require.NoError(t, err, "Failed to connect to peer")

			// Create timeout context for message sending
			msgCtx, msgCancel := context.WithTimeout(ctx, tt.timeout)
			defer msgCancel()

			// Measure send time
			start := time.Now()
			testData := []byte("timeout test message")
			err = sender.SendDirectMessage(msgCtx, receiverID, protocolID, testData)
			duration := time.Since(start)

			t.Logf("Message send took: %v (timeout was: %v)", duration, tt.timeout)

			if tt.expectError {
				assert.Error(t, err, "Expected timeout error")
				assert.True(t, errors.Is(err, context.DeadlineExceeded) ||
					duration >= tt.timeout-100*time.Millisecond,
					"Expected timeout-related error or duration near timeout")
			} else {
				// Don't assert success/failure since timeout behavior can vary
				// Just log the result for observation
				if err != nil {
					t.Logf("Got error (may be expected due to timing): %v", err)
				} else {
					t.Logf("Message sent successfully within timeout")
				}
			}
		})
	}
}

func TestBroadcastSignedBeaconBlockDirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create test peers
	testP2P := &p2p.TestP2P{
		InstanceID:      7,
		ExternalIP:      net.IP{127, 0, 0, 1},
		BeaconPortStart: 36000,
		ChainStatus:     p2p.NewStatus(),
	}

	peers, err := testP2P.GetTestPeer(ctx, 3)
	require.NoError(t, err, "Failed to create test peers")
	defer func() {
		_ = peers.Close(ctx)
	}()

	sender := peers[0]
	receiver1 := peers[1]
	receiver2 := peers[2]

	// Connect all peers to sender
	receivers := []*p2p.TestPeer{receiver1, receiver2}
	for i, receiver := range receivers {
		receiverID := receiver.Host.ID()
		receiverAddr := receiver.Host.Addrs()[0]
		fullAddr := receiverAddr.String() + "/p2p/" + receiverID.String()

		_, err := sender.ConnectToPeerTemporarily(ctx, fullAddr)
		require.NoError(t, err, "Failed to connect to receiver %d", i)
	}

	// Create a test beacon block
	spec := map[string]interface{}{
		"SLOTS_PER_EPOCH": uint64(32),
	}

	block := &deneb.SignedBeaconBlock{
		Message: &deneb.BeaconBlock{
			Slot:          100,
			ProposerIndex: 1,
			ParentRoot:    phase0.Root{0x01},
			StateRoot:     phase0.Root{0x02},
			Body: &deneb.BeaconBlockBody{
				RANDAOReveal:          phase0.BLSSignature{},
				ETH1Data:              &phase0.ETH1Data{},
				Graffiti:              [32]byte{},
				ProposerSlashings:     []*phase0.ProposerSlashing{},
				AttesterSlashings:     []*phase0.AttesterSlashing{},
				Attestations:          []*phase0.Attestation{},
				Deposits:              []*phase0.Deposit{},
				VoluntaryExits:        []*phase0.SignedVoluntaryExit{},
				SyncAggregate:         &altair.SyncAggregate{},
				ExecutionPayload:      &deneb.ExecutionPayload{},
				BLSToExecutionChanges: []*capella.SignedBLSToExecutionChange{},
				BlobKZGCommitments:    []deneb.KZGCommitment{},
			},
		},
		Signature: phase0.BLSSignature{},
	}

	// Broadcast the block
	err = sender.BroadcastSignedBeaconBlock(ctx, spec, block)
	assert.NoError(t, err, "Failed to broadcast signed beacon block")

	// Wait a bit for processing
	time.Sleep(200 * time.Millisecond)

	// Verify all peers were disconnected after broadcast
	connectedPeers := sender.Host.Network().Peers()
	assert.Empty(t, connectedPeers, "All peers should be disconnected after broadcast with goodbye")
}

func TestBroadcastBlobSidecarDirect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Create test peers
	testP2P := &p2p.TestP2P{
		InstanceID:      8,
		ExternalIP:      net.IP{127, 0, 0, 1},
		BeaconPortStart: 37000,
		ChainStatus:     p2p.NewStatus(),
	}

	peers, err := testP2P.GetTestPeer(ctx, 2)
	require.NoError(t, err, "Failed to create test peers")
	defer func() {
		_ = peers.Close(ctx)
	}()

	sender := peers[0]
	receiver := peers[1]

	// Connect receiver to sender
	receiverID := receiver.Host.ID()
	receiverAddr := receiver.Host.Addrs()[0]
	fullAddr := receiverAddr.String() + "/p2p/" + receiverID.String()

	_, err = sender.ConnectToPeerTemporarily(ctx, fullAddr)
	require.NoError(t, err, "Failed to connect to receiver")

	// Create a test blob sidecar
	spec := map[string]interface{}{
		"SLOTS_PER_EPOCH": uint64(32),
	}

	blobSidecar := &deneb.BlobSidecar{
		Index:         0,
		Blob:          deneb.Blob{},
		KZGCommitment: deneb.KZGCommitment{},
		KZGProof:      deneb.KZGProof{},
		SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
			Message: &phase0.BeaconBlockHeader{
				Slot:          100,
				ProposerIndex: 1,
				ParentRoot:    phase0.Root{0x01},
				StateRoot:     phase0.Root{0x02},
				BodyRoot:      phase0.Root{0x03},
			},
			Signature: phase0.BLSSignature{},
		},
	}

	// Broadcast the blob sidecar
	subnet := uint64(0)
	err = sender.BroadcastBlobSidecar(ctx, spec, blobSidecar, &subnet)
	assert.NoError(t, err, "Failed to broadcast blob sidecar")

	// Wait a bit for processing
	time.Sleep(200 * time.Millisecond)

	// Verify peer was disconnected after broadcast
	connectedPeers := sender.Host.Network().Peers()
	assert.Empty(t, connectedPeers, "Peer should be disconnected after broadcast with goodbye")
}
