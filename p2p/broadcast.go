package p2p

import (
	"bytes"
	"context"
	"fmt"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/pkg/errors"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/sirupsen/logrus"
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
			return ctx.Err()
		case <-time.After(1 * time.Millisecond):
		}
	}
}

func (p *TestP2P) BroadcastSignedBeaconBlockDeneb(signedBeaconBlockDeneb *eth.SignedBeaconBlockDeneb) error {
	timeoutCtx, cancel := context.WithTimeout(p.ctx, time.Second)
	defer cancel()
	if err := p.WaitForP2PConnection(timeoutCtx); err != nil {
		return errors.Wrap(err, "failed to wait for p2p connection")
	}

	buf := new(bytes.Buffer)
	if _, err := sszNetworkEncoder.EncodeGossip(buf, signedBeaconBlockDeneb); err != nil {
		return errors.Wrap(err, "failed to encode signed blob sidecar")
	}
	topic := signedBeaconBlockToTopic(p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())
	topicHandle, err := p.PubSub.Join(topic)
	if err != nil {
		return errors.Wrap(err, "failed to join topic")
	}
	logrus.WithFields(logrus.Fields{
		"topic": topic,
	}).Debug("BroadcastSignedBeaconBlockDeneb")

	if err := PublishTopic(timeoutCtx, topicHandle, buf.Bytes()); err != nil {
		return errors.Wrap(err, "failed to publish topic")
	}
	return nil
}

func (p *TestP2P) BroadcastSignedBlobSidecar(signedBlobSidecar *eth.SignedBlobSidecar, subnet *uint64) error {
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

	buf := new(bytes.Buffer)
	if _, err := sszNetworkEncoder.EncodeGossip(buf, signedBlobSidecar); err != nil {
		return errors.Wrap(err, "failed to encode signed blob sidecar")
	}
	topic := blobSubnetToTopic(*subnet, p.state.GetForkDigest(), sszNetworkEncoder.ProtocolSuffix())
	topicHandle, err := p.PubSub.Join(topic)
	if err != nil {
		return errors.Wrap(err, "failed to join topic")
	}
	logrus.WithFields(logrus.Fields{
		"topic": topic,
	}).Debug("BroadcastSignedBlobSidecar")

	if err := PublishTopic(timeoutCtx, topicHandle, buf.Bytes()); err != nil {
		return errors.Wrap(err, "failed to publish topic")
	}
	return nil
}

func signedBeaconBlockToTopic(forkDigest [4]byte, protocolSuffix string) string {
	return fmt.Sprintf("/eth2/%x/beacon_block", forkDigest) + protocolSuffix
}

func blobSubnetToTopic(subnet uint64, forkDigest [4]byte, protocolSuffix string) string {
	return fmt.Sprintf("/eth2/%x/blob_sidecar_%d", forkDigest, subnet) + protocolSuffix
}
