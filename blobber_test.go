package blobber_test

import (
	"bytes"
	_ "embed"
	"testing"

	geth_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/blobber"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
)

//go:embed proposal_actions/response_deneb.json
var responseDeneb string

func TestResponseParse(t *testing.T) {
	version, blockBlobResponse, err := blobber.ParseResponse([]byte(responseDeneb))
	if err != nil {
		t.Fatal(err)
	} else if blockBlobResponse == nil {
		t.Fatal("block is nil")
	}
	if version != "deneb" {
		t.Fatalf("wrong version: %s, expected deneb", version)
	}

	expectedBlockRoot := geth_common.HexToHash("0x37977b8edac80973deb38f3888bff9483b45b057c188ec041273cfe4485e2695")

	spec := configs.Mainnet

	blockRoot := blockBlobResponse.Block.HashTreeRoot(spec, tree.GetHashFn())
	bodyRoot := blockBlobResponse.Block.Body.HashTreeRoot(spec, tree.GetHashFn())

	if !bytes.Equal(blockRoot[:], expectedBlockRoot[:]) {
		t.Fatalf("wrong block root: %s, expected %s", blockRoot.String(), expectedBlockRoot.String())
	}

	if len(blockBlobResponse.Blobs) != 6 {
		t.Fatalf("wrong number of blobs: %d, expected 6", len(blockBlobResponse.Blobs))
	}

	signedBlockContents := deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message: *blockBlobResponse.Block,
		},
		KZGProofs: blockBlobResponse.KZGProofs,
		Blobs:     blockBlobResponse.Blobs,
	}

	// Generate the sidecars
	blobSidecars, err := signedBlockContents.GenerateSidecars(spec, tree.GetHashFn())
	if err != nil {
		t.Fatal(err)
	}

	// Verify the sidecars
	if len(blobSidecars) != len(blockBlobResponse.Blobs) {
		t.Fatalf("wrong number of blobs: %d, expected %d", len(blobSidecars), len(blockBlobResponse.Blobs))
	}

	for i, blobSidecar := range blobSidecars {
		if blobSidecar.Index != deneb.BlobIndex(i) {
			t.Fatalf("wrong blob index: %d, expected %d", blobSidecar.Index, i+1)
		}

		if blobSidecar.KZGCommitment != blockBlobResponse.Block.Body.BlobKZGCommitments[i] {
			t.Fatalf("wrong blob commitment: %s, expected %s", blobSidecar.KZGCommitment.String(), blockBlobResponse.Block.Body.BlobKZGCommitments[i].String())
		}

		if blobSidecar.KZGProof != blockBlobResponse.KZGProofs[i] {
			t.Fatalf("wrong blob proof: %s, expected %s", blobSidecar.KZGProof.String(), blockBlobResponse.KZGProofs[i].String())
		}

		if !bytes.Equal(blobSidecar.SignedBlockHeader.Message.BodyRoot[:], bodyRoot[:]) {
			t.Fatalf("wrong blob body root: %s, expected %s", blobSidecar.SignedBlockHeader.Message.BodyRoot.String(), bodyRoot.String())
		}

		blockHeaderRoot := blobSidecar.SignedBlockHeader.Message.HashTreeRoot(tree.GetHashFn())
		if !bytes.Equal(blockHeaderRoot[:], blockRoot[:]) {
			t.Fatalf("wrong block header root: %s, expected %s", blockHeaderRoot.String(), blockRoot.String())
		}

		if err := blobSidecar.VerifyProof(tree.GetHashFn()); err != nil {
			t.Fatal(err)
		}
	}
}
