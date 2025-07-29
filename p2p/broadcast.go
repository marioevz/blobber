package p2p

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/golang/snappy"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/marioevz/blobber/logger"
	"github.com/pkg/errors"
	fastssz "github.com/prysmaticlabs/fastssz"
)

var (
	MESSAGE_DOMAIN_INVALID_SNAPPY = [4]byte{0x00, 0x00, 0x00, 0x00}
	MESSAGE_DOMAIN_VALID_SNAPPY   = [4]byte{0x01, 0x00, 0x00, 0x00}
)

func PublishTopic(ctx context.Context, log logger.Logger, topicHandle *pubsub.Topic, data []byte, opts ...pubsub.PubOpt) error {
	// Publish the message to the topic, retrying until we have peers to send the message to
	// or the context is cancelled
	start := time.Now()
	lastLogTime := time.Now()
	waitTime := 1 * time.Second // Wait briefly for peers, but beacon nodes might not subscribe without validators

	for {
		topicPeers := topicHandle.ListPeers()
		if len(topicPeers) > 0 {
			// Log list of peers we are sending the message to
			debugFields := map[string]interface{}{
				"topic":       topicHandle.String(),
				"data-length": len(data),
				"peer_count":  len(topicPeers),
			}
			for i, peer := range topicPeers {
				debugFields[fmt.Sprintf("peer_%d", i)] = peer.String()
			}
			log.WithFields(debugFields).Debug("sending message to peers")
			return topicHandle.Publish(ctx, data, opts...)
		}

		// Log every 100ms if we're still waiting
		if time.Since(lastLogTime) > 100*time.Millisecond {
			log.WithFields(map[string]interface{}{
				"topic":            topicHandle.String(),
				"waiting_duration": time.Since(start).String(),
				"topic_peers":      len(topicPeers),
			}).Debug("Still waiting for peers to appear in topic")
			lastLogTime = time.Now()
		}

		// If we've waited long enough, return an error
		// Beacon nodes might not subscribe to topics unless they have validators
		if time.Since(start) > waitTime {
			return errors.Errorf("no peers subscribed to topic %s after waiting %s - beacon nodes may not subscribe without active validators", topicHandle.String(), time.Since(start).String())
		}

		select {
		case <-ctx.Done():
			return errors.Wrapf(ctx.Err(), "topic list of peers was always empty for topic %s, waited for %s", topicHandle.String(), time.Since(start))
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func EncodeGossip(topic string, msg fastssz.Marshaler) ([]byte, []byte, error) {
	// Returns the encoded message and the (altair) message-id
	s := sha256.New()
	s.Write(MESSAGE_DOMAIN_VALID_SNAPPY[:])

	topicLength := make([]byte, 8)
	binary.LittleEndian.PutUint64(topicLength, uint64(len(topic)))
	s.Write(topicLength)

	s.Write([]byte(topic))

	b, err := msg.MarshalSSZ()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to ssz-encode gossip message")
	}
	s.Write(b)

	b = snappy.Encode(nil /*dst*/, b)
	return b, s.Sum(nil)[:20], nil
}

func (p *TestPeer) BroadcastSignedBeaconBlock(ctx context.Context, spec map[string]interface{}, signedBeaconBlock *deneb.SignedBeaconBlock) error {
	// Use a longer timeout to account for topic subscription and mesh formation
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// First check if we're connected
	connCheckCtx, connCancel := context.WithTimeout(ctx, time.Second)
	defer connCancel()
	if err := p.WaitForP2PConnection(connCheckCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	topic := signedBeaconBlockToTopic(p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())

	p.logger.WithFields(map[string]interface{}{
		"topic":           topic,
		"fork_digest":     fmt.Sprintf("%x", p.state.GetForkDigest()),
		"protocol_suffix": sszNetworkEncoder.ProtocolSuffix(),
	}).Debug("Broadcasting to beacon block topic")

	buf, messageID, err := EncodeGossip(topic, WrapSpecObject(spec, signedBeaconBlock))
	if err != nil {
		return errors.Wrap(err, "failed to encode signed beacon block deneb")
	}

	topicHandle, err := p.GetOrJoinTopic(topic, pubsub.WithTopicMessageIdFn(func(_ *pb.Message) string {
		return string(messageID)
	}))
	if err != nil {
		return errors.Wrap(err, "failed to get or join topic")
	}
	// Don't close the topic handle here - it's managed by TestPeer now
	blockRoot, err := signedBeaconBlock.Message.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "failed to compute block root")
	}
	debugFields := map[string]interface{}{
		"id":         p.ID,
		"topic":      topic,
		"block_root": fmt.Sprintf("%x", blockRoot),
		"state_root": signedBeaconBlock.Message.StateRoot.String(),
		"slot":       signedBeaconBlock.Message.Slot,
		"signature":  signedBeaconBlock.Signature.String(),
		"message_id": fmt.Sprintf("%x", messageID),
	}

	for i, blobKzg := range signedBeaconBlock.Message.Body.BlobKZGCommitments {
		debugFields[fmt.Sprintf("blob_kzg_commitment_%d", i)] = blobKzg.String()
	}

	p.logger.WithFields(debugFields).Debug("Broadcasting signed beacon block deneb")

	if err := PublishTopic(timeoutCtx, p.logger, topicHandle, buf); err != nil {
		debugFields := map[string]interface{}{}
		for i, peer := range p.Host.Network().Peers() {
			debugFields[fmt.Sprintf("peer_%d", i)] = peer.String()
		}
		p.logger.WithFields(debugFields).Debug("connected network peers")
		return errors.Wrap(err, "failed to publish topic")
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
	// Use a longer timeout to account for topic subscription and mesh formation
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// First check if we're connected
	connCheckCtx, connCancel := context.WithTimeout(ctx, time.Second)
	defer connCancel()
	if err := p.WaitForP2PConnection(connCheckCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	if subnet == nil {
		// By default broadcast to the blob subnet of the index of the sidecar
		// According to the spec, blob subnet is calculated as:
		// subnet_id = blob_sidecar.index % BLOB_SIDECAR_SUBNET_COUNT
		// For now, BLOB_SIDECAR_SUBNET_COUNT == MAX_BLOBS_PER_BLOCK (6)
		// so using the index directly is correct
		index := uint64(blobSidecar.Index)
		subnet = &index
	}

	topic := blobSubnetToTopic(*subnet, p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())

	buf, messageID, err := EncodeGossip(topic, WrapSpecObject(spec, blobSidecar))
	if err != nil {
		return errors.Wrap(err, "failed to encode signed blob sidecar")
	}

	topicHandle, err := p.GetOrJoinTopic(topic, pubsub.WithTopicMessageIdFn(func(_ *pb.Message) string {
		return string(messageID)
	}))
	if err != nil {
		return errors.Wrap(err, "failed to get or join topic")
	}
	// Don't close the topic handle here - it's managed by TestPeer now

	blockRoot, err := blobSidecar.SignedBlockHeader.Message.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "failed to compute block root")
	}
	p.logger.WithFields(map[string]interface{}{
		"id":             p.ID,
		"topic":          topic,
		"block_root":     fmt.Sprintf("%x", blockRoot),
		"index":          blobSidecar.Index,
		"slot":           blobSidecar.SignedBlockHeader.Message.Slot,
		"kzg_commitment": blobSidecar.KZGCommitment.String(),
		"message_id":     fmt.Sprintf("%x", messageID),
	}).Debug("Broadcasting blob sidecar with signed block header")

	if err := PublishTopic(timeoutCtx, p.logger, topicHandle, buf); err != nil {
		debugFields := map[string]interface{}{}
		for i, peer := range p.Host.Network().Peers() {
			debugFields[fmt.Sprintf("peer_%d", i)] = peer.String()
		}
		p.logger.WithFields(debugFields).Debug("connected network peers")
		return errors.Wrap(err, "failed to publish topic")
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

func signedBeaconBlockToTopic(forkDigest [4]byte, protocolSuffix string) string {
	return fmt.Sprintf("/eth2/%x/beacon_block", forkDigest) + protocolSuffix
}

func blobSubnetToTopic(subnet uint64, forkDigest [4]byte, protocolSuffix string) string {
	return fmt.Sprintf("/eth2/%x/blob_sidecar_%d", forkDigest, subnet) + protocolSuffix
}
