package blobber

import (
	"github.com/marioevz/blobber/p2p"
	"github.com/pkg/errors"
	blsu "github.com/protolambda/bls12-381-util"
	beacon_common "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	eth "github.com/prysmaticlabs/prysm/v4/proto/prysm/v1alpha1"
	"github.com/sirupsen/logrus"
)

type SlotAction interface {
	Execute(
		testP2P *p2p.TestP2P,
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

type DefaultSlotAction struct{}

func (dsa DefaultSlotAction) Execute(
	testP2P *p2p.TestP2P,
	beaconBlock *eth.BeaconBlockDeneb,
	beaconBlockDomain beacon_common.BLSDomain,
	blobSidecars []*eth.BlobSidecar,
	blobSidecarDomain beacon_common.BLSDomain,
	proposerKey *[32]byte,
) (bool, error) {
	// Sign block and blobs
	signedBlock, err := SignBlock(beaconBlock, beaconBlockDomain, proposerKey)
	if err != nil {
		logrus.WithError(err).Error("Failed to sign block")
		return false, errors.Wrap(err, "failed to sign block")
	}
	signedBlobs, err := SignBlobs(blobSidecars, blobSidecarDomain, proposerKey)
	if err != nil {
		logrus.WithError(err).Error("failed to sign blobs")
		return false, errors.Wrap(err, "failed to sign blobs")
	}

	// Broadcast the blobs
	for _, signedBlob := range signedBlobs {
		if err := testP2P.BroadcastSignedBlobSidecar(signedBlob, nil); err != nil {
			logrus.WithError(err).Error("Failed to broadcast signed blob sidecar")
			return false, errors.Wrap(err, "failed to broadcast signed blob sidecar")
		}
	}

	// Broadcast the block
	if err := testP2P.BroadcastSignedBeaconBlockDeneb(signedBlock); err != nil {
		logrus.WithError(err).Error("Failed to broadcast signed beacon block")
		return false, errors.Wrap(err, "failed to broadcast signed beacon block")
	}

	return true, nil
}
