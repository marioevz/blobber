package slot_actions

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
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

type SlotAction interface {
	GetTestP2PCount() int
	Execute(
		testP2Ps p2p.TestP2Ps,
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

func (s Default) GetTestP2PCount() int {
	// By default we only create 1 test p2p and it's connected to all peers
	return 1
}

func (s Default) Execute(
	testP2Ps p2p.TestP2Ps,
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
	if err := testP2Ps.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Broadcast the blobs
	for _, signedBlob := range signedBlobs {
		if err := testP2Ps.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	return true, nil
}

type BroadcastBlobsBeforeBlock struct {
	Default
}

func (s BroadcastBlobsBeforeBlock) Execute(
	testP2Ps p2p.TestP2Ps,
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
		if err := testP2Ps.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	// Broadcast the block
	if err := testP2Ps.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}

type BlobGossipDelay struct {
	Default
	DelayMilliseconds int `json:"delay_milliseconds"`
}

func (s BlobGossipDelay) Execute(
	testP2Ps p2p.TestP2Ps,
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
	if err := testP2Ps.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	// Insert a delay before gossiping the blobs
	time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)

	// Broadcast the blobs
	for _, signedBlob := range signedBlobs {
		if err := testP2Ps.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
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
	testP2Ps p2p.TestP2Ps,
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
		if err := testP2Ps.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed beacon block")
		}
	}

	if s.BroadcastExtraBlobFirst {
		// Broadcast the extra blob
		if err := testP2Ps.BroadcastSignedBlobSidecar(signedExtraBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast extra signed blob sidecar")
		}

		// Insert a delay before gossiping the blobs
		time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)
	}

	// Broadcast the correct blobs
	for _, signedBlob := range signedBlobs {
		if err := testP2Ps.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	if !s.BroadcastExtraBlobFirst {
		// Insert a delay before gossiping the blobs
		time.Sleep(time.Duration(s.DelayMilliseconds) * time.Millisecond)

		// Broadcast the extra blob
		if err := testP2Ps.BroadcastSignedBlobSidecar(signedExtraBlob, nil); err != nil {
			return false, errors.Wrap(err, "failed to broadcast extra signed blob sidecar")
		}
	}

	if !s.BroadcastBlockFirst {
		// Broadcast the block
		if err := testP2Ps.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
			return false, errors.Wrap(err, "failed to broadcast signed beacon block")
		}
	}

	return true, nil
}

type ConflictingBlobs struct {
	Default
}

func (s ConflictingBlobs) GetTestP2PCount() int {
	// We are going to send two conflicting blobs through two different test p2p connections
	return 2
}

func (s ConflictingBlobs) Execute(
	testP2Ps p2p.TestP2Ps,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	if len(testP2Ps) != 2 {
		return false, fmt.Errorf("expected 2 test p2p connections, got %d", len(testP2Ps))
	}
	if len(blobSidecars) < 1 {
		return false, fmt.Errorf("expected at least 1 blob sidecar, got %d", len(blobSidecars))
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

	// Generate the extra blob sidecar
	conflictingBlobSidecar := &eth.BlobSidecar{
		BlockRoot:       signedBlobs[0].Message.BlockRoot,
		Index:           0,
		Slot:            beaconBlock.Slot,
		BlockParentRoot: beaconBlock.ParentRoot[:],
		ProposerIndex:   beaconBlock.ProposerIndex,
	}

	if err := FillSidecarWithRandomBlob(conflictingBlobSidecar); err != nil {
		return false, errors.Wrap(err, "failed to fill extra blob sidecar")
	}
	// Sign the blob
	signedConflictingBlob, err := SignBlob(conflictingBlobSidecar, blobSidecarDomain, proposerKey)
	if err != nil {
		return false, errors.Wrap(err, "failed to sign extra blob")
	}

	// Create the second list of sidecars
	secondBlobSidecars := make([]*eth.SignedBlobSidecar, len(signedBlobs))
	for i, signedBlobSidecar := range signedBlobs {
		if i == 0 {
			secondBlobSidecars[i] = signedConflictingBlob
		} else {
			secondBlobSidecars[i] = signedBlobSidecar
		}
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, 2)
	wg.Add(2)

	// Broadcast the first list of blobs
	go func() {
		defer wg.Done()
		for _, signedBlob := range signedBlobs {
			if err := testP2Ps[0].BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
				errs <- err
				return
			}
		}
	}()

	// Broadcast the second list of blobs
	go func() {
		defer wg.Done()
		for _, signedBlob := range secondBlobSidecars {
			if err := testP2Ps[1].BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
				errs <- err
				return
			}
		}
	}()

	wg.Wait()

	select {
	case err := <-errs:
		return false, errors.Wrap(err, "failed to broadcast blob sidecars")
	default:
	}

	// Broadcast the block
	if err := testP2Ps.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}
