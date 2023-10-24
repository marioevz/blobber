package p2p

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/golang/snappy"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/pkg/errors"
	fastssz "github.com/prysmaticlabs/fastssz"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/sirupsen/logrus"
)

var (
	MESSAGE_DOMAIN_INVALID_SNAPPY = [4]byte{0x00, 0x00, 0x00, 0x00}
	MESSAGE_DOMAIN_VALID_SNAPPY   = [4]byte{0x01, 0x00, 0x00, 0x00}
)

func PublishTopic(ctx context.Context, topicHandle *pubsub.Topic, data []byte, opts ...pubsub.PubOpt) error {
	for {
		if len(topicHandle.ListPeers()) > 0 {
			// Log list of peers we are sending the message to
			peerIDs := make([]string, len(topicHandle.ListPeers()))
			for i, peer := range topicHandle.ListPeers() {
				peerIDs[i] = peer.String()
			}
			logrus.WithFields(logrus.Fields{
				"topic":       topicHandle.String(),
				"peers":       peerIDs,
				"data-length": len(data),
			}).Debug("sending message to peers")

			return topicHandle.Publish(ctx, data, opts...)
		}
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "topic list of peers was always empty")
		case <-time.After(1 * time.Millisecond):
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

func (p *TestPeer) BroadcastSignedBeaconBlockDeneb(signedBeaconBlockDeneb *eth.SignedBeaconBlockDeneb) error {
	timeoutCtx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	if err := p.WaitForP2PConnection(timeoutCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	topic := signedBeaconBlockToTopic(p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())

	buf, messageID, err := EncodeGossip(topic, signedBeaconBlockDeneb)
	if err != nil {
		return errors.Wrap(err, "failed to encode signed beacon block deneb")
	}

	topicHandle, err := p.PubSub.Join(topic, pubsub.WithTopicMessageIdFn(func(_ *pb.Message) string {
		return string(messageID)
	}))
	if err != nil {
		return errors.Wrap(err, "failed to join topic")
	}
	blockRoot, err := signedBeaconBlockDeneb.Block.HashTreeRoot()
	if err != nil {
		return errors.Wrap(err, "failed to get block hash tree root")
	}
	debugFields := logrus.Fields{
		"id":         p.ID,
		"topic":      topic,
		"block_root": fmt.Sprintf("%x", blockRoot),
		"slot":       signedBeaconBlockDeneb.Block.Slot,
		"signature":  fmt.Sprintf("%x", signedBeaconBlockDeneb.Signature),
		"message_id": fmt.Sprintf("%x", messageID),
	}

	for i, blobKzg := range signedBeaconBlockDeneb.Block.Body.BlobKzgCommitments {
		debugFields[fmt.Sprintf("blob_kzg_commitment_%d", i)] = fmt.Sprintf("%x", blobKzg)
	}

	logrus.WithFields(debugFields).Debug("Broadcasting signed beacon block deneb")

	if err := PublishTopic(timeoutCtx, topicHandle, buf); err != nil {
		return errors.Wrap(err, "failed to publish topic")
	}
	return topicHandle.Close()
}

func (p TestPeers) BroadcastSignedBeaconBlockDeneb(signedBeaconBlockDeneb *eth.SignedBeaconBlockDeneb) error {
	for _, p2p := range p {
		if err := p2p.BroadcastSignedBeaconBlockDeneb(signedBeaconBlockDeneb); err != nil {
			return err
		}
	}
	return nil
}

func (p *TestPeer) BroadcastSignedBlobSidecar(signedBlobSidecar *eth.SignedBlobSidecar, subnet *uint64) error {
	timeoutCtx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	if err := p.WaitForP2PConnection(timeoutCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	if subnet == nil {
		// By default broadcast to the blob subnet of the index of the sidecar
		// TODO: This is not entirely correct, this is only correct because the
		//       subnet count is equal to the max blob sidecar count.
		subnet = &signedBlobSidecar.Message.Index
	}

	topic := blobSubnetToTopic(*subnet, p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())

	buf, messageID, err := EncodeGossip(topic, signedBlobSidecar)
	if err != nil {
		return errors.Wrap(err, "failed to encode signed blob sidecar")
	}

	topicHandle, err := p.PubSub.Join(topic, pubsub.WithTopicMessageIdFn(func(_ *pb.Message) string {
		return string(messageID)
	}))
	if err != nil {
		return errors.Wrap(err, "failed to join topic")
	}
	logrus.WithFields(logrus.Fields{
		"id":             p.ID,
		"topic":          topic,
		"block_root":     fmt.Sprintf("%x", signedBlobSidecar.Message.BlockRoot),
		"index":          signedBlobSidecar.Message.Index,
		"slot":           signedBlobSidecar.Message.Slot,
		"kzg_commitment": fmt.Sprintf("%x", signedBlobSidecar.Message.KzgCommitment),
		"signature":      fmt.Sprintf("%x", signedBlobSidecar.Signature),
		"message_id":     fmt.Sprintf("%x", messageID),
	}).Debug("Broadcasting signed blob sidecar")

	if err := PublishTopic(timeoutCtx, topicHandle, buf); err != nil {
		return errors.Wrap(err, "failed to publish topic")
	}
	return topicHandle.Close()
}

func (p *TestPeer) BroadcastSignedBlobSidecars(signedBlobSidecars []*eth.SignedBlobSidecar) error {
	for _, signedBlobSidecar := range signedBlobSidecars {
		if err := p.BroadcastSignedBlobSidecar(signedBlobSidecar, nil); err != nil {
			return err
		}
	}
	return nil
}

func (p TestPeers) BroadcastSignedBlobSidecar(signedBlobSidecar *eth.SignedBlobSidecar, subnet *uint64) error {
	for _, p2p := range p {
		if err := p2p.BroadcastSignedBlobSidecar(signedBlobSidecar, subnet); err != nil {
			return err
		}
	}
	return nil
}

func (p TestPeers) BroadcastSignedBlobSidecars(signedBlobSidecars []*eth.SignedBlobSidecar) error {
	for _, p2p := range p {
		if err := p2p.BroadcastSignedBlobSidecars(signedBlobSidecars); err != nil {
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
