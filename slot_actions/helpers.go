package slot_actions

import (
	"bytes"
	"sync"
	"time"

	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/tree"
)

func VerifySignature(domain common.BLSDomain, root common.Root, pubKey *blsu.Pubkey, signature common.BLSSignature) (bool, error) {
	signingRoot := common.ComputeSigningRoot(root, domain)
	s, err := signature.Signature()
	if err != nil {
		return false, err
	}
	return blsu.Verify(pubKey, signingRoot[:], s), nil
}

func SignBlockContents(spec *common.Spec, blockContents *deneb.BlockContents, beaconBlockDomain common.BLSDomain, validatorKey *keys.ValidatorKey) (*deneb.SignedBlockContents, error) {
	signingRoot := common.ComputeSigningRoot(
		blockContents.Block.HashTreeRoot(spec, tree.GetHashFn()),
		beaconBlockDomain,
	)
	signature := blsu.Sign(validatorKey.ValidatorSecretKey, signingRoot[:]).Serialize()
	return &deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message:   *blockContents.Block,
			Signature: signature,
		},
		KZGProofs: blockContents.KZGProofs,
		Blobs:     blockContents.Blobs,
	}, nil
}

func CreatedSignedBlockSidecarsBundle(
	spec *common.Spec,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain common.BLSDomain,
	validatorKey *keys.ValidatorKey,
) (*SignedBlockSidecarsBundle, error) {
	signedBlockContents, err := SignBlockContents(spec, beaconBlockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sign block")
	}
	blobSidecars, err := signedBlockContents.GenerateSidecars(spec, tree.GetHashFn())
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate blob sidecars")
	}
	return &SignedBlockSidecarsBundle{
		SignedBlock:  signedBlockContents.SignedBlock,
		BlobSidecars: blobSidecars,
	}, nil
}

func CreateSignEquivocatingBlock(
	spec *common.Spec,
	beaconBlockContents *deneb.BlockContents,
	beaconBlockDomain common.BLSDomain,
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
		Append:      true,
	}
	graffitiModifier.ModifyBlock(spec, equivocatingBlockContents.Block)

	beaconBlocksContents := []*deneb.BlockContents{
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
		blobSidecars, err := signedBlockContents.GenerateSidecars(spec, tree.GetHashFn())
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
	copiedProof := make(deneb.KZGCommitmentInclusionProof, len(proof))
	copy(copiedProof, proof)
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
		copiedBlob.Blob = make([]byte, len(blob.Blob))
		copy(copiedBlob.Blob[:], blob.Blob[:])
		copiedBlobs[i] = copiedBlob
	}
	return copiedBlobs, nil
}

func CopyBlobs(blobs []deneb.Blob) ([]deneb.Blob, error) {
	copiedBlobs := make([]deneb.Blob, len(blobs))
	for i, blob := range blobs {
		copiedBlob := make([]byte, len(blob))
		copy(copiedBlob[:], blob[:])
		copiedBlobs[i] = copiedBlob
	}
	return copiedBlobs, nil
}

func CopyBlockContents(bc *deneb.BlockContents) (*deneb.BlockContents, error) {
	if bc.Block == nil {
		return nil, errors.New("block contents block is nil")
	}
	copiedBlock := *bc.Block
	copiedBlockContents := &deneb.BlockContents{
		Block:     &copiedBlock,
		KZGProofs: bc.KZGProofs,
		Blobs:     nil,
	}
	copiedBlobs, err := CopyBlobs(bc.Blobs)
	if err != nil {
		return nil, err
	}
	copiedBlockContents.Blobs = copiedBlobs
	return copiedBlockContents, nil
}

func MultiPeerBlobBroadcast(spec *common.Spec, peers p2p.TestPeers, blobsLists ...[]*deneb.BlobSidecar) error {
	if len(peers) != len(blobsLists) {
		return errors.New("peers and blobsLists must have the same length")
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, len(peers))

	broadcastBlobs := func(testPeer *p2p.TestPeer, blobs []*deneb.BlobSidecar) {
		defer wg.Done()
		for i, blob := range blobs {
			if err := testPeer.BroadcastBlobSidecar(spec, blob, nil); err != nil {
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
	Spec  *common.Spec
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

	broadcastBlobs := func(testPeer *p2p.TestPeer, blobs []*deneb.BlobSidecar) error {
		for i, blob := range blobs {
			if err := testPeer.BroadcastBlobSidecar(b.Spec, blob, nil); err != nil {
				return errors.Wrapf(err, "failed to broadcast signed blob %d", i)
			}
		}
		return nil
	}

	broadcastBlock := func(testPeer *p2p.TestPeer, signedBlock *deneb.SignedBeaconBlock) error {
		if err := testPeer.BroadcastSignedBeaconBlock(b.Spec, signedBlock); err != nil {
			return errors.Wrap(err, "failed to broadcast signed block")
		}
		return nil
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, len(b.Peers))

	broadcastBundle := func(testPeer *p2p.TestPeer, bundle *SignedBlockSidecarsBundle) {
		defer wg.Done()
		if b.BlobsFirst {
			if err := broadcastBlobs(testPeer, bundle.BlobSidecars); err != nil {
				errs <- err
				return
			}
			if b.DelayMilliseconds > 0 {
				time.Sleep(time.Duration(b.DelayMilliseconds) * time.Millisecond)
			}
			if err := broadcastBlock(testPeer, bundle.SignedBlock); err != nil {
				errs <- err
				return
			}
		} else {
			if err := broadcastBlock(testPeer, bundle.SignedBlock); err != nil {
				errs <- err
				return
			}
			if b.DelayMilliseconds > 0 {
				time.Sleep(time.Duration(b.DelayMilliseconds) * time.Millisecond)
			}
			if err := broadcastBlobs(testPeer, bundle.BlobSidecars); err != nil {
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
	ModifyBlock(spec *common.Spec, block interface{}) error
}

type GraffitiModifier struct {
	NewGraffiti string
	Append      bool
}

func TextToRoot(s string) (root tree.Root, err error) {
	if len([]byte(s)) > len(root) {
		err = errors.New("text is too long to fit in a root")
		return
	}
	copy(root[:], []byte(s))
	return
}

func RootToText(root tree.Root) (string, error) {
	i := bytes.Index(root[:], []byte{0})
	return string(root[:i]), nil
}

func (gm *GraffitiModifier) ModifyBlock(spec *common.Spec, block interface{}) error {
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
			return errors.New("block is not a signed beacon block")
		}
		prefix += " - "
	}

	newRoot, err := TextToRoot(prefix + gm.NewGraffiti)
	if err != nil {
		return err
	}
	switch b := block.(type) {
	case *deneb.BeaconBlock:
		b.Body.Graffiti = newRoot
	default:
		return errors.New("block is not a signed beacon block")
	}
	return nil
}
