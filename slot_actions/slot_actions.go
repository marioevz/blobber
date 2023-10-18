package slot_actions

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	math_rand "math/rand"
	"sync"
	"time"

	"github.com/marioevz/blobber/kzg"
	"github.com/marioevz/blobber/p2p"
	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/sirupsen/logrus"
)

const MAX_BLOBS_PER_BLOCK = 6

type SlotAction interface {
	GetTestPeerCount() int
	Execute(
		testPeers p2p.TestPeers,
		beaconBlock *eth.BeaconBlockDeneb,
		beaconBlockDomain beacon_common.BLSDomain,
		blobSidecars []*eth.BlobSidecar,
		blobSidecarDomain beacon_common.BLSDomain,
		proposerKey *[32]byte,
	) (bool, error)
}

func SignBlock(block *eth.BeaconBlockDeneb, beaconBlockDomain beacon_common.BLSDomain, proposerKey *[32]byte) (*eth.SignedBeaconBlockDeneb, error) {
	blockHTR, err := block.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block hash tree root")
	}

	signingRoot := beacon_common.ComputeSigningRoot(
		tree.Root(blockHTR),
		beaconBlockDomain,
	)

	sk := new(blsu.SecretKey)
	sk.Deserialize(proposerKey)
	signature := blsu.Sign(sk, signingRoot[:]).Serialize()
	signedBlock := eth.SignedBeaconBlockDeneb{}
	signedBlock.Block = block
	signedBlock.Signature = signature[:]
	return &signedBlock, nil
}

func SignBlob(blob *eth.BlobSidecar, blobSidecarDomain beacon_common.BLSDomain, proposerKey *[32]byte) (*eth.SignedBlobSidecar, error) {
	blobHTR, err := blob.HashTreeRoot()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get block hash tree root")
	}

	signingRoot := beacon_common.ComputeSigningRoot(
		tree.Root(blobHTR),
		blobSidecarDomain,
	)

	sk := new(blsu.SecretKey)
	sk.Deserialize(proposerKey)
	signature := blsu.Sign(sk, signingRoot[:]).Serialize()
	signedBlob := eth.SignedBlobSidecar{}
	signedBlob.Message = blob
	signedBlob.Signature = signature[:]
	return &signedBlob, nil
}

func SignBlobs(blobs []*eth.BlobSidecar, blobSidecarDomain beacon_common.BLSDomain, proposerKey *[32]byte) ([]*eth.SignedBlobSidecar, error) {
	signedBlobs := make([]*eth.SignedBlobSidecar, len(blobs))
	for i, blob := range blobs {
		signedBlob, err := SignBlob(blob, blobSidecarDomain, proposerKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign blob")
		}
		signedBlobs[i] = signedBlob
	}
	return signedBlobs, nil
}

func UnmarshallSlotAction(data []byte) (SlotAction, error) {
	if len(data) == 0 {
		return nil, nil
	}

	type actionName struct {
		Name string `json:"name"`
	}
	var actionNameObj actionName
	if err := json.Unmarshal(data, &actionNameObj); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall slot action name")
	}

	var action SlotAction
	switch actionNameObj.Name {
	case "default":
		action = &Default{}
	case "broadcast_blobs_before_block":
		action = &BroadcastBlobsBeforeBlock{}
	case "blob_gossip_delay":
		action = &BlobGossipDelay{}
	case "extra_blobs":
		action = &ExtraBlobs{}
	case "conflicting_blobs":
		action = &ConflictingBlobs{}
	default:
		return nil, fmt.Errorf("unknown slot action name: %s", actionNameObj.Name)
	}

	if err := json.Unmarshal(data, &action); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshall slot action")
	}
	return action, nil
}

type Default struct{}

func (s Default) GetTestPeerCount() int {
	// By default we only create 1 test p2p and it's connected to all peers
	return 1
}

func (s Default) Execute(
	testPeers p2p.TestPeers,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	// Sign block and blobs
	signedBlock, err := SignBlock(beaconBlock, beaconBlockDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Broadcast the block
	if err := testPeers.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Broadcast the blobs
	for _, signedBlob := range signedBlobs {
		if err := testPeers.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	return true, nil
}

type BroadcastBlobsBeforeBlock struct {
	Default
}

func (s BroadcastBlobsBeforeBlock) Execute(
	testPeers p2p.TestPeers,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	// Sign block and blobs
	signedBlock, err := SignBlock(beaconBlock, beaconBlockDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Broadcast the blobs
	for _, signedBlob := range signedBlobs {
		if err := testPeers.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	// Broadcast the block
	if err := testPeers.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}

type BlobGossipDelay struct {
	Default
	DelayMilliseconds int `json:"delay_milliseconds"`
}

func (s BlobGossipDelay) Execute(
	testPeers p2p.TestPeers,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	// Sign block and blobs
	signedBlock, err := SignBlock(beaconBlock, beaconBlockDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Broadcast the block
	if err := testPeers.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Insert a delay before gossiping the blobs
	time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)

	// Broadcast the blobs
	for _, signedBlob := range signedBlobs {
		if err := testPeers.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	return true, nil
}

// Things to try:
// - Broadcast another blob with valid kzg or invalid kzg
// - Broadcast before or after the valid blob list
// - Broadcast the blobs before or after the block
type ExtraBlobs struct {
	Default
	IncorrectKZGCommitment  bool `json:"incorrect_kzg_commitment"`
	IncorrectKZGProof       bool `json:"incorrect_kzg_proof"`
	IncorrectBlockRoot      bool `json:"incorrect_block_root"`
	IncorrectSignature      bool `json:"incorrect_signature"`
	DelayMilliseconds       int  `json:"delay_milliseconds"`
	BroadcastBlockFirst     bool `json:"broadcast_block_last"`
	BroadcastExtraBlobFirst bool `json:"broadcast_extra_blob_last"`
}

func FillSidecarWithRandomBlob(sidecar *eth.BlobSidecar) error {
	blob, kgzCommitment, kzgProof, err := kzg.RandomBlob()
	if err != nil {
		return errors.Wrap(err, "failed to generate random blob")
	}
	sidecar.Blob = blob[:]
	sidecar.KzgCommitment = kgzCommitment[:]
	sidecar.KzgProof = kzgProof[:]
	return nil
}

func (s ExtraBlobs) Execute(
	testPeers p2p.TestPeers,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	// Sign block and blobs
	signedBlock, err := SignBlock(beaconBlock, beaconBlockDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Generate the extra blob sidecar
	extraBlobSidecar := &eth.BlobSidecar{
		Slot:            beaconBlock.Slot,
		BlockParentRoot: beaconBlock.ParentRoot[:],
		ProposerIndex:   beaconBlock.ProposerIndex,
	}

	if s.IncorrectBlockRoot {
		extraBlobSidecar.BlockRoot = make([]byte, 32)
		rand.Read(extraBlobSidecar.BlockRoot)
	} else {
		blockRoot, err := beaconBlock.HashTreeRoot()
		if err != nil {
			return false, errors.Wrap(err, "failed to get block hash tree root")
		}
		extraBlobSidecar.BlockRoot = blockRoot[:]
	}

	if err := FillSidecarWithRandomBlob(extraBlobSidecar); err != nil {
		return false, errors.Wrap(err, "failed to fill extra blob sidecar")
	}

	if s.IncorrectKZGCommitment {
		fields := logrus.Fields{
			"correct": fmt.Sprintf("%x", extraBlobSidecar.KzgCommitment),
		}
		rand.Read(extraBlobSidecar.KzgCommitment)
		fields["corrupted"] = fmt.Sprintf("%x", extraBlobSidecar.KzgCommitment)
		logrus.WithFields(fields).Debug("Corrupted blob sidecar kzg commitment")
	}

	if s.IncorrectKZGProof {
		fields := logrus.Fields{
			"correct": fmt.Sprintf("%x", extraBlobSidecar.KzgProof),
		}
		rand.Read(extraBlobSidecar.KzgProof)
		fields["corrupted"] = fmt.Sprintf("%x", extraBlobSidecar.KzgProof)
		logrus.WithFields(fields).Debug("Corrupted blob sidecar kzg proof")
	}

	// Sign the blob
	signedExtraBlob, err := SignBlob(extraBlobSidecar, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign extra blob")
	}

	if s.IncorrectSignature {
		fields := logrus.Fields{
			"correct": fmt.Sprintf("%x", signedExtraBlob.Signature),
		}
		rand.Read(signedExtraBlob.Signature)
		fields["corrupted"] = fmt.Sprintf("%x", signedExtraBlob.Signature)
		logrus.WithFields(fields).Debug("Corrupted blob sidecar signature")
	}

	logrus.WithFields(
		logrus.Fields{
			"blockRoot":       fmt.Sprintf("%x", extraBlobSidecar.BlockRoot),
			"blockParentRoot": fmt.Sprintf("%x", extraBlobSidecar.BlockParentRoot),
			"slot":            extraBlobSidecar.Slot,
			"proposerIndex":   extraBlobSidecar.ProposerIndex,
			"kzgCommitment":   fmt.Sprintf("%x", extraBlobSidecar.KzgCommitment),
			"kzgProof":        fmt.Sprintf("%x", extraBlobSidecar.KzgProof),
		},
	).Debug("Extra blob")

	if s.BroadcastBlockFirst {
		// Broadcast the block
		if err := testPeers.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed beacon block")
		}
	}

	if s.BroadcastExtraBlobFirst {
		// Broadcast the extra blob
		if err := testPeers.BroadcastSignedBlobSidecar(signedExtraBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast extra signed blob sidecar")
		}

		// Insert a delay before gossiping the blobs
		time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)
	}

	// Broadcast the correct blobs
	for _, signedBlob := range signedBlobs {
		if err := testPeers.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	if !s.BroadcastExtraBlobFirst {
		// Insert a delay before gossiping the blobs
		time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)

		// Broadcast the extra blob
		if err := testPeers.BroadcastSignedBlobSidecar(signedExtraBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast extra signed blob sidecar")
		}
	}

	if !s.BroadcastBlockFirst {
		// Broadcast the block
		if err := testPeers.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed beacon block")
		}
	}

	return true, nil
}

type ConflictingBlobs struct {
	Default
	ConflictingBlobsCount       int  `json:"conflicting_blobs_count"`
	RandomConflictingBlobsCount bool `json:"random_conflicting_blobs_count"`
	AlternateBlobRecipients     bool `json:"alternate_blob_recipients"`
}

func (s ConflictingBlobs) GetTestPeerCount() int {
	// We are going to send two conflicting blobs through two different test p2p connections
	return 2
}

func (s ConflictingBlobs) GetConflictingBlobsCount() int {
	if s.RandomConflictingBlobsCount {
		return math_rand.Intn(MAX_BLOBS_PER_BLOCK-1) + 1
	}
	if s.ConflictingBlobsCount > 0 {
		return s.ConflictingBlobsCount
	}
	return 1
}

func (s ConflictingBlobs) Execute(
	testPeers p2p.TestPeers,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	if len(testPeers) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testPeers))
	}

	// Sign block and blobs
	signedBlock, err := SignBlock(beaconBlock, beaconBlockDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Generate the extra blob sidecars
	blockRoot, err := beaconBlock.HashTreeRoot()
	if err != nil {
		return false, errors.Wrap(err, "failed to get block hash tree root")
	}

	conflictingBlobsCount := s.GetConflictingBlobsCount()

	// Create the second list of sidecars
	secondBlobSidecarsLength := len(signedBlobs)
	if secondBlobSidecarsLength < conflictingBlobsCount {
		secondBlobSidecarsLength = conflictingBlobsCount
	}
	secondBlobSidecars := make([]*eth.SignedBlobSidecar, secondBlobSidecarsLength)

	for i := 0; i < secondBlobSidecarsLength; i++ {
		if i < conflictingBlobsCount {
			conflictingBlobSidecar := &eth.BlobSidecar{
				BlockRoot:       blockRoot[:],
				Index:           uint64(i),
				Slot:            beaconBlock.Slot,
				BlockParentRoot: beaconBlock.ParentRoot[:],
				ProposerIndex:   beaconBlock.ProposerIndex,
			}

			if err := FillSidecarWithRandomBlob(conflictingBlobSidecar); err != nil {
				return false, errors.Wrap(err, "failed to fill extra blob sidecar")
			}
			// Sign the blob
			secondBlobSidecars[i], err = SignBlob(conflictingBlobSidecar, blobSidecarDomain, proposerKey)
			if err != nil {
				return false, errors.Wrap(err, "failed to sign extra blob")
			}
		} else {
			secondBlobSidecars[i] = signedBlobs[i]
		}
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, 2)

	// Broadcast the first list of blobs
	broadcastBlobs := func(testPeer *p2p.TestPeer, signedBlobs []*eth.SignedBlobSidecar) {
		defer wg.Done()
		for _, signedBlob := range signedBlobs {
			if err := testPeer.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
				errs <- err
				return
			}
		}
	}

	changeOrder := false
	if s.AlternateBlobRecipients {
		changeOrder = beaconBlock.Slot%2 == 0
	}

	wg.Add(2)
	if changeOrder {
		go broadcastBlobs(testPeers[0], secondBlobSidecars)
		go broadcastBlobs(testPeers[1], signedBlobs)
	} else {
		go broadcastBlobs(testPeers[0], signedBlobs)
		go broadcastBlobs(testPeers[1], secondBlobSidecars)
	}
	wg.Wait()

	select {
	case err := <-errs:
		return false, errors.Wrap(err, "failed to broadcast blob sidecars")
	default:
	}

	// Broadcast the block
	if err := testPeers.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}
