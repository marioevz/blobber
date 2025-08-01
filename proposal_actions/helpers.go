package proposal_actions

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/sirupsen/logrus"
)

func VerifySignature(domain phase0.Domain, root phase0.Root, pubKey *blsu.Pubkey, signature phase0.BLSSignature) (bool, error) {
	// Compute signing root
	signingData := &phase0.SigningData{
		ObjectRoot: root,
		Domain:     domain,
	}
	signingRoot, err := signingData.HashTreeRoot()
	if err != nil {
		return false, err
	}
	// BLSSignature in go-eth2-client is a [96]byte array
	// Convert to blsu.Signature
	sig := new(blsu.Signature)
	var sigArray [96]byte
	copy(sigArray[:], signature[:])
	if err := sig.Deserialize(&sigArray); err != nil {
		return false, err
	}
	return blsu.Verify(pubKey, signingRoot[:], sig), nil
}

func SignBlockContents(spec map[string]interface{}, blockContents *apiv1deneb.BlockContents, beaconBlockDomain phase0.Domain, validatorKey *keys.ValidatorKey) (*apiv1deneb.SignedBlockContents, error) {
	blockRoot, err := blockContents.Block.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	// Compute signing root
	signingData := &phase0.SigningData{
		ObjectRoot: blockRoot,
		Domain:     beaconBlockDomain,
	}
	signingRoot, err := signingData.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	signatureBytes := blsu.Sign(validatorKey.ValidatorSecretKey, signingRoot[:]).Serialize()
	var signature phase0.BLSSignature
	copy(signature[:], signatureBytes[:])
	return &apiv1deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message:   blockContents.Block,
			Signature: signature,
		},
		KZGProofs: blockContents.KZGProofs,
		Blobs:     blockContents.Blobs,
	}, nil
}

func CreatedSignedBlockSidecarsBundle(
	spec map[string]interface{},
	beaconBlockContents *apiv1deneb.BlockContents,
	beaconBlockDomain phase0.Domain,
	validatorKey *keys.ValidatorKey,
) (*SignedBlockSidecarsBundle, error) {
	signedBlockContents, err := SignBlockContents(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign block")
	}
	blobSidecars, err := GenerateSidecars(spec, signedBlockContents)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate blob sidecars")
	}
	return &SignedBlockSidecarsBundle{
		SignedBlock:  signedBlockContents.SignedBlock,
		BlobSidecars: blobSidecars,
	}, nil
}

func CreateSignEquivocatingBlock(
	spec map[string]interface{},
	beaconBlockContents *apiv1deneb.BlockContents,
	beaconBlockDomain phase0.Domain,
	validatorKey *keys.ValidatorKey,
) ([]*SignedBlockSidecarsBundle, error) {
	// Create an equivocating block by modifying the graffiti of the block
	equivocatingBlockContents, err := CopyBlockContents(beaconBlockContents)
	if err != nil {
		return nil, errors.Wrap(err, "failed to copy block contents")
	}

	// Modify the graffiti to generate a different block
	graffitiModifier := &GraffitiModifier{
		NewGraffiti: "Equiv",
	}
	if err := graffitiModifier.ModifyBlock(spec, equivocatingBlockContents.Block); err != nil {
		return nil, errors.Wrap(err, "failed to modify block")
	}
	beaconRoot, _ := beaconBlockContents.Block.HashTreeRoot()
	equivRoot, _ := equivocatingBlockContents.Block.HashTreeRoot()
	logrus.WithFields(
		logrus.Fields{
			"beacon_block_root": fmt.Sprintf("%x", beaconRoot),
			"equiv_block_root":  fmt.Sprintf("%x", equivRoot),
		},
	).Debug("created equivocating block")

	beaconBlocksContents := []*apiv1deneb.BlockContents{
		beaconBlockContents,
		equivocatingBlockContents,
	}

	// Sign the blocks and generate the sidecars
	signedBlockBlobsBundles := make([]*SignedBlockSidecarsBundle, len(beaconBlocksContents))
	for i, blockContents := range beaconBlocksContents {
		signedBlockContents, err := SignBlockContents(spec, blockContents, beaconBlockDomain, validatorKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to sign block")
		}
		blobSidecars, err := GenerateSidecars(spec, signedBlockContents)
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate blob sidecars")
		}
		signedBlockBlobsBundles[i] = &SignedBlockSidecarsBundle{
			SignedBlock:  signedBlockContents.SignedBlock,
			BlobSidecars: blobSidecars,
		}
	}
	return signedBlockBlobsBundles, nil
}

func CopyInclusionProofs(proof deneb.KZGCommitmentInclusionProof) deneb.KZGCommitmentInclusionProof {
	// KZGCommitmentInclusionProof is a fixed-size array in go-eth2-client
	var copiedProof deneb.KZGCommitmentInclusionProof
	copy(copiedProof[:], proof[:])
	return copiedProof
}

func CopyBlobSidecars(blobs []*deneb.BlobSidecar) ([]*deneb.BlobSidecar, error) {
	copiedBlobs := make([]*deneb.BlobSidecar, len(blobs))
	for i, blob := range blobs {
		copiedBlob := &deneb.BlobSidecar{
			Index:                       blob.Index,
			KZGCommitment:               blob.KZGCommitment,
			KZGProof:                    blob.KZGProof,
			SignedBlockHeader:           blob.SignedBlockHeader,
			KZGCommitmentInclusionProof: CopyInclusionProofs(blob.KZGCommitmentInclusionProof),
		}
		// Blob is a fixed-size array in go-eth2-client
		copy(copiedBlob.Blob[:], blob.Blob[:])
		copiedBlobs[i] = copiedBlob
	}
	return copiedBlobs, nil
}

func CopyBlobs(blobs []deneb.Blob) ([]deneb.Blob, error) {
	copiedBlobs := make([]deneb.Blob, len(blobs))
	for i, blob := range blobs {
		// Blob is a fixed-size array, just copy it
		var copiedBlob deneb.Blob
		copy(copiedBlob[:], blob[:])
		copiedBlobs[i] = copiedBlob
	}
	return copiedBlobs, nil
}

func CopyBlockContents(bc *apiv1deneb.BlockContents) (*apiv1deneb.BlockContents, error) {
	if bc.Block == nil {
		return nil, errors.New("block contents block is nil")
	}

	// Deep copy the block
	copiedBlock := &deneb.BeaconBlock{
		Slot:          bc.Block.Slot,
		ProposerIndex: bc.Block.ProposerIndex,
		ParentRoot:    bc.Block.ParentRoot,
		StateRoot:     bc.Block.StateRoot,
		Body:          nil, // Will be set below
	}

	// Deep copy the block body
	if bc.Block.Body != nil {
		body := bc.Block.Body
		copiedBody := &deneb.BeaconBlockBody{
			RANDAOReveal:          body.RANDAOReveal,
			ETH1Data:              body.ETH1Data,
			Graffiti:              body.Graffiti,
			ProposerSlashings:     body.ProposerSlashings,
			AttesterSlashings:     body.AttesterSlashings,
			Attestations:          body.Attestations,
			Deposits:              body.Deposits,
			VoluntaryExits:        body.VoluntaryExits,
			SyncAggregate:         body.SyncAggregate,
			ExecutionPayload:      body.ExecutionPayload,
			BLSToExecutionChanges: body.BLSToExecutionChanges,
			BlobKZGCommitments:    body.BlobKZGCommitments,
		}
		copiedBlock.Body = copiedBody
	}

	// Copy KZG proofs
	copiedKZGProofs := make([]deneb.KZGProof, len(bc.KZGProofs))
	copy(copiedKZGProofs, bc.KZGProofs)

	copiedBlockContents := &apiv1deneb.BlockContents{
		Block:     copiedBlock,
		KZGProofs: copiedKZGProofs,
		Blobs:     nil,
	}

	copiedBlobs, err := CopyBlobs(bc.Blobs)
	if err != nil {
		return nil, err
	}
	copiedBlockContents.Blobs = copiedBlobs
	return copiedBlockContents, nil
}

func MultiPeerBlobBroadcast(spec map[string]interface{}, peers p2p.TestPeers, blobsLists ...[]*deneb.BlobSidecar) error {
	if len(peers) != len(blobsLists) {
		return errors.New("peers and blobsLists must have the same length")
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, len(peers))

	broadcastBlobs := func(testPeer *p2p.TestPeer, blobs []*deneb.BlobSidecar) {
		defer wg.Done()
		for i, blob := range blobs {
			// Disconnect after the last blob
			disconnectAfter := (i == len(blobs)-1)
			if err := testPeer.BroadcastBlobSidecarWithConfig(context.Background(), spec, blob, nil, disconnectAfter); err != nil {
				errs <- errors.Wrapf(err, "failed to broadcast signed blob %d", i)
				return
			}
		}
	}

	for i, testPeer := range peers {
		wg.Add(1)
		go broadcastBlobs(testPeer, blobsLists[i])
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		return err
	}

	return nil
}

type SignedBlockSidecarsBundle struct {
	SignedBlock  *deneb.SignedBeaconBlock
	BlobSidecars []*deneb.BlobSidecar
}

type BundleBroadcaster struct {
	Spec  map[string]interface{}
	Peers p2p.TestPeers
	// Delay in milliseconds between broadcast of blocks and blob sidecars
	DelayMilliseconds int
	// Delay in milliseconds between broadcast to different peers
	PeerBroadcastDelayMilliseconds int
	// If true, broadcast blobs first, then blocks
	BlobsFirst bool
}

func (b BundleBroadcaster) Broadcast(bundles ...*SignedBlockSidecarsBundle) error {
	if len(b.Peers) != len(bundles) {
		return errors.New("peers and bundles must have the same length")
	}

	// If there's a delay configured, apply it BEFORE establishing any P2P connections
	// This ensures we don't hold connections open during the delay period
	if b.DelayMilliseconds > 0 {
		time.Sleep(time.Duration(b.DelayMilliseconds) * time.Millisecond)
	}

	broadcastBlobs := func(testPeer *p2p.TestPeer, blobs []*deneb.BlobSidecar, isLast bool) error {
		for i, blob := range blobs {
			// Only disconnect after the last blob if this is the last broadcast
			disconnectAfter := isLast && (i == len(blobs)-1)
			if err := testPeer.BroadcastBlobSidecarWithConfig(context.Background(), b.Spec, blob, nil, disconnectAfter); err != nil {
				return errors.Wrapf(err, "failed to broadcast signed blob %d", i)
			}
		}
		return nil
	}

	broadcastBlock := func(testPeer *p2p.TestPeer, signedBlock *deneb.SignedBeaconBlock, shouldDisconnect bool) error {
		if err := testPeer.BroadcastSignedBeaconBlockWithConfig(context.Background(), b.Spec, signedBlock, shouldDisconnect); err != nil {
			return errors.Wrap(err, "failed to broadcast signed block")
		}
		return nil
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, len(b.Peers))

	broadcastBundle := func(testPeer *p2p.TestPeer, bundle *SignedBlockSidecarsBundle) {
		defer wg.Done()
		if b.BlobsFirst {
			// Don't disconnect after blobs since we need to broadcast block next
			if err := broadcastBlobs(testPeer, bundle.BlobSidecars, false); err != nil {
				errs <- err
				return
			}
			// Disconnect after block since it's the last broadcast
			if err := broadcastBlock(testPeer, bundle.SignedBlock, true); err != nil {
				errs <- err
				return
			}
		} else {
			// Don't disconnect after block since we need to broadcast blobs next
			if err := broadcastBlock(testPeer, bundle.SignedBlock, false); err != nil {
				errs <- err
				return
			}
			// Disconnect after blobs since it's the last broadcast
			if err := broadcastBlobs(testPeer, bundle.BlobSidecars, true); err != nil {
				errs <- err
				return
			}
		}
	}

	for i, testPeer := range b.Peers {
		wg.Add(1)
		go broadcastBundle(testPeer, bundles[i])
		if b.PeerBroadcastDelayMilliseconds > 0 {
			time.Sleep(time.Duration(b.PeerBroadcastDelayMilliseconds) * time.Millisecond)
		}
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		return err
	}

	return nil
}

type BlockModifier interface {
	ModifyBlock(spec map[string]interface{}, block interface{}) error
}

type GraffitiModifier struct {
	NewGraffiti string
	Append      bool
}

func TextToRoot(s string) (root phase0.Root, err error) {
	if len([]byte(s)) > len(root) {
		err = fmt.Errorf("text is too long to fit in a root: %s", s)
		return
	}
	copy(root[:], []byte(s))
	return
}

func RootToText(root phase0.Root) (string, error) {
	i := bytes.Index(root[:], []byte{0})
	return string(root[:i]), nil
}

func (gm *GraffitiModifier) ModifyBlock(spec map[string]interface{}, block interface{}) error {
	var prefix string
	if gm.Append {
		var err error
		switch b := block.(type) {
		case *deneb.BeaconBlock:
			prefix, err = RootToText(b.Body.Graffiti)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("block has incorrect type: %T", block)
		}
		prefix += " - "
	}

	newRoot, err := TextToRoot(prefix + gm.NewGraffiti)
	if err != nil {
		return err
	}
	switch b := block.(type) {
	case *deneb.BeaconBlock:
		if bytes.Equal(b.Body.Graffiti[:], newRoot[:]) {
			return fmt.Errorf("new graffiti and old graffiti are the same: %s", newRoot.String())
		}
		b.Body.Graffiti = newRoot
	default:
		return fmt.Errorf("block has incorrect type: %T", block)
	}
	return nil
}
