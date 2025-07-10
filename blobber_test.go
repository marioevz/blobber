package blobber_test

import (
	"bytes"
	_ "embed"
	"testing"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	geth_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/blobber"
	"github.com/marioevz/blobber/proposal_actions"
)

//go:embed proposal_actions/response_deneb.json
var responseDeneb string

func TestResponseParse(t *testing.T) {
	blockBlobResponse, err := blobber.ParseResponse([]byte(responseDeneb))
	if err != nil {
		t.Fatal(err)
	} else if blockBlobResponse == nil {
		t.Fatal("block is nil")
	}
	if blockBlobResponse.Version != "deneb" {
		t.Fatalf("wrong version: %s, expected deneb", blockBlobResponse.Version)
	}

	expectedBlockRoot := geth_common.HexToHash("0x37977b8edac80973deb38f3888bff9483b45b057c188ec041273cfe4485e2695")

	denebBlock := blockBlobResponse.Deneb
	if denebBlock == nil {
		t.Fatal("deneb block is nil")
		return
	}

	blockRoot, err := denebBlock.Block.HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	bodyRoot, err := denebBlock.Block.Body.HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(blockRoot[:], expectedBlockRoot[:]) {
		t.Fatalf("wrong block root: %x, expected %x", blockRoot, expectedBlockRoot)
	}

	if len(denebBlock.Blobs) != 6 {
		t.Fatalf("wrong number of blobs: %d, expected 6", len(denebBlock.Blobs))
	}

	signedBlockContents := apiv1deneb.SignedBlockContents{
		SignedBlock: &deneb.SignedBeaconBlock{
			Message: denebBlock.Block,
		},
		KZGProofs: denebBlock.KZGProofs,
		Blobs:     denebBlock.Blobs,
	}

	// Generate the sidecars using our custom implementation
	spec := map[string]interface{}{} // Add spec params if needed
	blobSidecars, err := proposal_actions.GenerateSidecars(spec, &signedBlockContents)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the sidecars
	if len(blobSidecars) != len(denebBlock.Blobs) {
		t.Fatalf("wrong number of sidecars: %d, expected %d", len(blobSidecars), len(denebBlock.Blobs))
	}

	for i, blobSidecar := range blobSidecars {
		if blobSidecar.Index != deneb.BlobIndex(i) {
			t.Fatalf("wrong blob index: %d, expected %d", blobSidecar.Index, i)
		}

		if blobSidecar.KZGCommitment != denebBlock.Block.Body.BlobKZGCommitments[i] {
			t.Fatalf("wrong blob commitment: %x, expected %x", blobSidecar.KZGCommitment, denebBlock.Block.Body.BlobKZGCommitments[i])
		}

		if blobSidecar.KZGProof != denebBlock.KZGProofs[i] {
			t.Fatalf("wrong blob proof: %x, expected %x", blobSidecar.KZGProof, denebBlock.KZGProofs[i])
		}

		if !bytes.Equal(blobSidecar.SignedBlockHeader.Message.BodyRoot[:], bodyRoot[:]) {
			t.Fatalf("wrong blob body root: %x, expected %x", blobSidecar.SignedBlockHeader.Message.BodyRoot, bodyRoot)
		}
	}
}
