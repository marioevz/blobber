package p2p

import (
	"context"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/pkg/errors"
)

const (
	// Ethereum P2P protocol IDs for direct messaging
	BeaconBlockProtocolID = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/" + "ssz_snappy"
	BlobSidecarProtocolID = "/eth2/beacon_chain/req/blob_sidecars_by_range/1/" + "ssz_snappy"

	// Message send timeout for direct peer messaging
	MessageSendTimeout = 5 * time.Second
)

// SendDirectMessage sends a message directly to a peer using req/resp protocol
func (p *TestPeer) SendDirectMessage(ctx context.Context, peerID peer.ID, protocolID protocol.ID, data []byte) error {
	start := time.Now()
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id":   peerID.String(),
			"protocol":  string(protocolID),
			"data_size": len(data),
		}).Debug("Opening stream for direct message send")
	}

	// Create timeout context for message sending
	msgCtx, cancel := context.WithTimeout(ctx, MessageSendTimeout)
	defer cancel()

	// Open stream with the specified protocol
	stream, err := p.Host.NewStream(msgCtx, peerID, protocolID)
	if err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id":  peerID.String(),
				"protocol": string(protocolID),
				"error":    err.Error(),
			}).Error("Failed to open stream for direct message")
		}
		return errors.Wrap(err, "failed to open stream for direct message")
	}
	defer stream.Close()

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id":  peerID.String(),
			"protocol": string(protocolID),
		}).Debug("Stream opened successfully")
	}

	// Send response code (success)
	if _, err := stream.Write([]byte{0x00}); err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id": peerID.String(),
				"error":   err.Error(),
			}).Error("Failed to write response code")
		}
		return errors.Wrap(err, "failed to write response code")
	}

	// Write the message data
	bytesWritten, err := stream.Write(data)
	if err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id":       peerID.String(),
				"bytes_written": bytesWritten,
				"error":         err.Error(),
			}).Error("Failed to write message data")
		}
		return errors.Wrap(err, "failed to write message data")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id":       peerID.String(),
			"bytes_written": bytesWritten,
		}).Debug("Message data written successfully")
	}

	// Close write side to signal end of message
	if err := stream.CloseWrite(); err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id": peerID.String(),
				"error":   err.Error(),
			}).Warn("Failed to close write side of stream")
		}
	}

	// Try to read acknowledgment (optional, don't fail if peer doesn't respond)
	respBuf := make([]byte, 1)
	stream.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := stream.Read(respBuf); err != nil {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id": peerID.String(),
				"error":   err.Error(),
			}).Debug("No acknowledgment received from peer (expected)")
		}
	} else {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_id":  peerID.String(),
				"response": fmt.Sprintf("0x%02x", respBuf[0]),
			}).Debug("Received acknowledgment from peer")
		}
	}

	duration := time.Since(start)
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"peer_id":     peerID.String(),
			"protocol":    string(protocolID),
			"duration_ms": duration.Milliseconds(),
		}).Debug("Direct message send completed")
	}

	return nil
}

// EncodeDirectMessage encodes a message for direct peer-to-peer transmission using SSZ
func EncodeDirectMessage(msg interface{}) ([]byte, error) {
	// Use SSZ network encoder for direct messages
	if sszMsg, ok := msg.(interface{ MarshalSSZ() ([]byte, error) }); ok {
		data, err := sszMsg.MarshalSSZ()
		if err != nil {
			return nil, errors.Wrap(err, "failed to marshal message to SSZ")
		}
		return data, nil
	}
	return nil, errors.New("message does not implement SSZ marshaling")
}

func (p *TestPeer) BroadcastSignedBeaconBlock(ctx context.Context, spec map[string]interface{}, signedBeaconBlock *deneb.SignedBeaconBlock) error {
	start := time.Now()

	// Get connected peers for direct messaging
	connectedPeers := p.Host.Network().Peers()
	if len(connectedPeers) == 0 {
		if p.logger != nil {
			p.logger.WithField("slot", signedBeaconBlock.Message.Slot).Warn("No connected peers for beacon block broadcast")
		}
		return errors.New("no connected peers available for broadcast")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"slot":       signedBeaconBlock.Message.Slot,
			"peer_count": len(connectedPeers),
		}).Info("Starting direct beacon block broadcast")
	}

	// Compute block root for logging
	blockRoot, err := signedBeaconBlock.Message.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "failed to compute block root")
	}

	// Encode the block for direct transmission
	data, err := EncodeDirectMessage(WrapSpecObject(spec, signedBeaconBlock))
	if err != nil {
		return errors.Wrap(err, "failed to encode signed beacon block for direct messaging")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"block_root":     fmt.Sprintf("%x", blockRoot),
			"state_root":     signedBeaconBlock.Message.StateRoot.String(),
			"slot":           signedBeaconBlock.Message.Slot,
			"signature":      signedBeaconBlock.Signature.String(),
			"encoded_size":   len(data),
			"blob_kzg_count": len(signedBeaconBlock.Message.Body.BlobKZGCommitments),
		}).Debug("Encoded beacon block for direct broadcast")
	}

	// Track success/failure counts
	successCount := 0
	failureCount := 0
	var lastError error

	// Send to each connected peer directly
	for i, peerID := range connectedPeers {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_index":  i + 1,
				"peer_id":     peerID.String(),
				"total_peers": len(connectedPeers),
			}).Debug("Sending beacon block to connected peer")
		}

		// Send beacon block via direct stream
		if err := p.SendDirectMessage(ctx, peerID, protocol.ID(BeaconBlockProtocolID), data); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Warn("Failed to send beacon block to peer")
			}
			failureCount++
			lastError = err
		} else {
			successCount++
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id":   peerID.String(),
					"data_size": len(data),
				}).Info("Successfully sent beacon block to peer")
			}
		}

		// Send graceful goodbye and disconnect
		if err := p.SendGoodbyeAndDisconnect(ctx, peerID, 1); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Warn("Failed to send goodbye and disconnect")
			}
		}
	}

	duration := time.Since(start)
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"slot":             signedBeaconBlock.Message.Slot,
			"successful_peers": successCount,
			"failed_peers":     failureCount,
			"total_peers":      len(connectedPeers),
			"duration_ms":      duration.Milliseconds(),
		}).Info("Beacon block direct broadcast completed")
	}

	// Return error only if all peers failed
	if successCount == 0 && failureCount > 0 {
		return errors.Wrap(lastError, "failed to broadcast beacon block to any peer")
	}

	return nil
}

func (p TestPeers) BroadcastSignedBeaconBlock(ctx context.Context, spec map[string]interface{}, signedBeaconBlockDeneb *deneb.SignedBeaconBlock) error {
	for _, p2p := range p {
		if err := p2p.BroadcastSignedBeaconBlock(ctx, spec, signedBeaconBlockDeneb); err != nil {
			return err
		}
	}
	return nil
}

func (p *TestPeer) BroadcastBlobSidecar(ctx context.Context, spec map[string]interface{}, blobSidecar *deneb.BlobSidecar, subnet *uint64) error {
	start := time.Now()
	if subnet == nil {
		// By default broadcast to the blob subnet of the index of the sidecar
		// According to the spec, blob subnet is calculated as:
		// subnet_id = blob_sidecar.index % BLOB_SIDECAR_SUBNET_COUNT
		// For now, BLOB_SIDECAR_SUBNET_COUNT == MAX_BLOBS_PER_BLOCK (6)
		// so using the index directly is correct
		index := uint64(blobSidecar.Index)
		subnet = &index
	}

	// Get connected peers for direct messaging
	connectedPeers := p.Host.Network().Peers()
	if len(connectedPeers) == 0 {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"index":  blobSidecar.Index,
				"subnet": *subnet,
				"slot":   blobSidecar.SignedBlockHeader.Message.Slot,
			}).Warn("No connected peers for blob sidecar broadcast")
		}
		return errors.New("no connected peers available for broadcast")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"index":      blobSidecar.Index,
			"subnet":     *subnet,
			"slot":       blobSidecar.SignedBlockHeader.Message.Slot,
			"peer_count": len(connectedPeers),
		}).Info("Starting direct blob sidecar broadcast")
	}

	// Compute block root for logging
	blockRoot, err := blobSidecar.SignedBlockHeader.Message.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "failed to compute block root")
	}

	// Encode the blob sidecar for direct transmission
	data, err := EncodeDirectMessage(WrapSpecObject(spec, blobSidecar))
	if err != nil {
		return errors.Wrap(err, "failed to encode blob sidecar for direct messaging")
	}

	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"block_root":     fmt.Sprintf("%x", blockRoot),
			"index":          blobSidecar.Index,
			"slot":           blobSidecar.SignedBlockHeader.Message.Slot,
			"kzg_commitment": blobSidecar.KZGCommitment.String(),
			"encoded_size":   len(data),
		}).Debug("Encoded blob sidecar for direct broadcast")
	}

	// Track success/failure counts
	successCount := 0
	failureCount := 0
	var lastError error

	// Send to each connected peer directly
	for i, peerID := range connectedPeers {
		if p.logger != nil {
			p.logger.WithFields(map[string]interface{}{
				"peer_index":  i + 1,
				"peer_id":     peerID.String(),
				"total_peers": len(connectedPeers),
				"subnet":      *subnet,
			}).Debug("Sending blob sidecar to connected peer")
		}

		// Send blob sidecar via direct stream
		if err := p.SendDirectMessage(ctx, peerID, protocol.ID(BlobSidecarProtocolID), data); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Warn("Failed to send blob sidecar to peer")
			}
			failureCount++
			lastError = err
		} else {
			successCount++
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id":   peerID.String(),
					"data_size": len(data),
				}).Info("Successfully sent blob sidecar to peer")
			}
		}

		// Send graceful goodbye and disconnect
		if err := p.SendGoodbyeAndDisconnect(ctx, peerID, 1); err != nil {
			if p.logger != nil {
				p.logger.WithFields(map[string]interface{}{
					"peer_id": peerID.String(),
					"error":   err.Error(),
				}).Warn("Failed to send goodbye and disconnect")
			}
		}
	}

	duration := time.Since(start)
	if p.logger != nil {
		p.logger.WithFields(map[string]interface{}{
			"index":            blobSidecar.Index,
			"subnet":           *subnet,
			"slot":             blobSidecar.SignedBlockHeader.Message.Slot,
			"successful_peers": successCount,
			"failed_peers":     failureCount,
			"total_peers":      len(connectedPeers),
			"duration_ms":      duration.Milliseconds(),
		}).Info("Blob sidecar direct broadcast completed")
	}

	// Return error only if all peers failed
	if successCount == 0 && failureCount > 0 {
		return errors.Wrap(lastError, "failed to broadcast blob sidecar to any peer")
	}

	return nil
}

func (p *TestPeer) BroadcastBlobSidecars(ctx context.Context, spec map[string]interface{}, blobSidecars ...*deneb.BlobSidecar) error {
	for _, blobSidecar := range blobSidecars {
		if err := p.BroadcastBlobSidecar(ctx, spec, blobSidecar, nil); err != nil {
			return err
		}
	}
	return nil
}

func (p TestPeers) BroadcastBlobSidecar(ctx context.Context, spec map[string]interface{}, blobSidecar *deneb.BlobSidecar, subnet *uint64) error {
	for _, p2p := range p {
		if err := p2p.BroadcastBlobSidecar(ctx, spec, blobSidecar, subnet); err != nil {
			return err
		}
	}
	return nil
}

func (p TestPeers) BroadcastBlobSidecars(ctx context.Context, spec map[string]interface{}, blobSidecars ...*deneb.BlobSidecar) error {
	for _, p2p := range p {
		if err := p2p.BroadcastBlobSidecars(ctx, spec, blobSidecars...); err != nil {
			return err
		}
	}
	return nil
}

// Log removal of flood gossip mechanisms
func init() {
	// Remove flood gossip/pubsub logic - replaced with direct peer messaging
	// Old topic-based broadcasting has been replaced with req/resp protocol streams
}
