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
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/tree"
	fastssz "github.com/prysmaticlabs/fastssz"
	"github.com/sirupsen/logrus"
)

var (
	MESSAGE_DOMAIN_INVALID_SNAPPY = [4]byte{0x00, 0x00, 0x00, 0x00}
	MESSAGE_DOMAIN_VALID_SNAPPY   = [4]byte{0x01, 0x00, 0x00, 0x00}
)

func PublishTopic(ctx context.Context, topicHandle *pubsub.Topic, data []byte, opts ...pubsub.PubOpt) error {
	// Publish the message to the topic, retrying until we have peers to send the message to
	// or the context is cancelled
	start := time.Now()
	for {
		if len(topicHandle.ListPeers()) > 0 {
			// Log list of peers we are sending the message to
			debugFields := logrus.Fields{
				"topic":       topicHandle.String(),
				"data-length": len(data),
			}
			for i, peer := range topicHandle.ListPeers() {
				debugFields[fmt.Sprintf("peer_%d", i)] = peer.String()
			}
			logrus.WithFields(debugFields).Debug("sending message to peers")
			return topicHandle.Publish(ctx, data, opts...)
		}
		select {
		case <-ctx.Done():
			return errors.Wrapf(ctx.Err(), "topic list of peers was always empty, waited for %s", time.Since(start))
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

func (p *TestPeer) BroadcastSignedBeaconBlock(spec *common.Spec, signedBeaconBlock *deneb.SignedBeaconBlock) error {
	timeoutCtx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	if err := p.WaitForP2PConnection(timeoutCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	topic := signedBeaconBlockToTopic(p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())

	buf, messageID, err := EncodeGossip(topic, WrapSpecObject(spec, signedBeaconBlock))
	if err != nil {
		return errors.Wrap(err, "failed to encode signed beacon block deneb")
	}

	topicHandle, err := p.PubSub.Join(topic, pubsub.WithTopicMessageIdFn(func(_ *pb.Message) string {
		return string(messageID)
	}))
	if err != nil {
		return errors.Wrap(err, "failed to join topic")
	}
	defer topicHandle.Close()
	blockRoot := signedBeaconBlock.Message.HashTreeRoot(spec, tree.GetHashFn())
	debugFields := logrus.Fields{
		"id":         p.ID,
		"topic":      topic,
		"block_root": blockRoot.String(),
		"state_root": signedBeaconBlock.Message.StateRoot.String(),
		"slot":       signedBeaconBlock.Message.Slot,
		"signature":  signedBeaconBlock.Signature.String(),
		"message_id": fmt.Sprintf("%x", messageID),
	}

	for i, blobKzg := range signedBeaconBlock.Message.Body.BlobKZGCommitments {
		debugFields[fmt.Sprintf("blob_kzg_commitment_%d", i)] = blobKzg.String()
	}

	logrus.WithFields(debugFields).Debug("Broadcasting signed beacon block deneb")

	if err := PublishTopic(timeoutCtx, topicHandle, buf); err != nil {
		debugFields := logrus.Fields{}
		for i, peer := range p.Host.Network().Peers() {
			debugFields[fmt.Sprintf("peer_%d", i)] = peer.String()
		}
		logrus.WithFields(debugFields).Debug("connected network peers")
		return errors.Wrap(err, "failed to publish topic")
	}
	return nil
}

func (p TestPeers) BroadcastSignedBeaconBlock(spec *common.Spec, signedBeaconBlockDeneb *deneb.SignedBeaconBlock) error {
	for _, p2p := range p {
		if err := p2p.BroadcastSignedBeaconBlock(spec, signedBeaconBlockDeneb); err != nil {
			return err
		}
	}
	return nil
}

func (p *TestPeer) BroadcastBlobSidecar(spec *common.Spec, blobSidecar *deneb.BlobSidecar, subnet *uint64) error {
	timeoutCtx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	if err := p.WaitForP2PConnection(timeoutCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	if subnet == nil {
		// By default broadcast to the blob subnet of the index of the sidecar
		// TODO: This is not entirely correct, this is only correct because the
		//       subnet count is equal to the max blob sidecar count.
		index := uint64(blobSidecar.Index)
		subnet = &index
	}

	topic := blobSubnetToTopic(*subnet, p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())

	buf, messageID, err := EncodeGossip(topic, WrapSpecObject(spec, blobSidecar))
	if err != nil {
		return errors.Wrap(err, "failed to encode signed blob sidecar")
	}

	topicHandle, err := p.PubSub.Join(topic, pubsub.WithTopicMessageIdFn(func(_ *pb.Message) string {
		return string(messageID)
	}))
	if err != nil {
		return errors.Wrap(err, "failed to join topic")
	}
	defer topicHandle.Close()

	blockRoot := blobSidecar.SignedBlockHeader.Message.HashTreeRoot(tree.GetHashFn())
	logrus.WithFields(logrus.Fields{
		"id":             p.ID,
		"topic":          topic,
		"block_root":     blockRoot.String(),
		"index":          blobSidecar.Index,
		"slot":           blobSidecar.SignedBlockHeader.Message.Slot,
		"kzg_commitment": blobSidecar.KZGCommitment.String(),
		"message_id":     fmt.Sprintf("%x", messageID),
	}).Debug("Broadcasting blob sidecar with signed block header")

	if err := PublishTopic(timeoutCtx, topicHandle, buf); err != nil {
		debugFields := logrus.Fields{}
		for i, peer := range p.Host.Network().Peers() {
			debugFields[fmt.Sprintf("peer_%d", i)] = peer.String()
		}
		logrus.WithFields(debugFields).Debug("connected network peers")
		return errors.Wrap(err, "failed to publish topic")
	}
	return nil
}

func (p *TestPeer) BroadcastBlobSidecars(spec *common.Spec, blobSidecars ...*deneb.BlobSidecar) error {
	for _, blobSidecar := range blobSidecars {
		if err := p.BroadcastBlobSidecar(spec, blobSidecar, nil); err != nil {
			return err
		}
	}
	return nil
}

func (p TestPeers) BroadcastBlobSidecar(spec *common.Spec, blobSidecar *deneb.BlobSidecar, subnet *uint64) error {
	for _, p2p := range p {
		if err := p2p.BroadcastBlobSidecar(spec, blobSidecar, subnet); err != nil {
			return err
		}
	}
	return nil
}

func (p TestPeers) BroadcastBlobSidecars(spec *common.Spec, blobSidecars ...*deneb.BlobSidecar) error {
	for _, p2p := range p {
		if err := p2p.BroadcastBlobSidecars(spec, blobSidecars...); err != nil {
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
