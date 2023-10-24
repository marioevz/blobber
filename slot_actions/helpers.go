package slot_actions

import (
	"sync"

	"github.com/marioevz/blobber/p2p"
	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
)

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

func CopyBlobs(blobs []*eth.BlobSidecar) ([]*eth.BlobSidecar, error) {
	copiedBlobs := make([]*eth.BlobSidecar, len(blobs))
	for i, blob := range blobs {
		copiedBlob := &eth.BlobSidecar{
			BlockRoot:       blob.BlockRoot,
			Index:           blob.Index,
			Slot:            blob.Slot,
			BlockParentRoot: blob.BlockParentRoot,
			ProposerIndex:   blob.ProposerIndex,
			Blob:            blob.Blob,
			KzgCommitment:   blob.KzgCommitment,
			KzgProof:        blob.KzgProof,
		}
		copiedBlobs[i] = copiedBlob
	}
	return copiedBlobs, nil
}

func MultiPeerSignedBlobBroadcast(peers p2p.TestPeers, signedBlobsLists [][]*eth.SignedBlobSidecar) error {
	if len(peers) != len(signedBlobsLists) {
		return errors.New("peers and signedBlobsLists must have the same length")
	}

	wg := sync.WaitGroup{}
	errs := make(chan error, len(peers))

	broadcastBlobs := func(testPeer *p2p.TestPeer, signedBlobs []*eth.SignedBlobSidecar) {
		defer wg.Done()
		for i, signedBlob := range signedBlobs {
			if err := testPeer.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
				errs <- errors.Wrapf(err, "failed to broadcast signed blob %d", i)
				return
			}
		}
	}

	for i, testPeer := range peers {
		wg.Add(1)
		go broadcastBlobs(testPeer, signedBlobsLists[i])
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		return err
	}

	return nil
}
