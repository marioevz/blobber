package proposal_actions_test

import (
	"bytes"
	_ "embed"
	"testing"

	geth_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/blobber"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/proposal_actions"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
)

//go:embed response_deneb.json
var responseDeneb string
var spec = configs.Mainnet

func TestBlockSigning(t *testing.T) {
	version, blockContents, err := blobber.ParseResponse([]byte(responseDeneb))
	if err != nil {
		t.Fatal(err)
	} else if blockContents == nil {
		t.Fatal("block is nil")
	}
	if version != "deneb" {
		t.Fatalf("wrong version: %s, expected deneb", version)
	}

	expectedBlockContentsRoot := geth_common.HexToHash("0x63ab3be9cfed1fe67d61fc030edd985c838f865d524bdeb2faf340e03d861dd9")
	blockContentsRoot := blockContents.HashTreeRoot(spec, tree.GetHashFn())
	if !bytes.Equal(blockContentsRoot[:], expectedBlockContentsRoot[:]) {
		t.Fatalf("wrong block blob response root: %s, expected %s", blockContentsRoot.String(), expectedBlockContentsRoot.String())
	}

	expectedBlockRoot := geth_common.HexToHash("0x37977b8edac80973deb38f3888bff9483b45b057c188ec041273cfe4485e2695")

	blockRoot := blockContents.Block.HashTreeRoot(spec, tree.GetHashFn())
	if !bytes.Equal(blockRoot[:], expectedBlockRoot[:]) {
		t.Fatalf("wrong block root: %s, expected %s", blockRoot.String(), expectedBlockRoot.String())
	}

	beaconBlockDomain := common.ComputeDomain(
		common.DOMAIN_BEACON_PROPOSER,
		spec.ForkVersion(0),
		common.Root{},
	)

	validatorKey := new(keys.ValidatorKey)
	keyBytes := []byte("proposer key")
	if err := validatorKey.FromBytes(append(keyBytes, make([]byte, 32-len(keyBytes))...)); err != nil {
		t.Fatal(err)
	}

	// Test signing the block contents
	signedBlockContents, err := proposal_actions.SignBlockContents(spec, blockContents, beaconBlockDomain, validatorKey)
	if err != nil {
		t.Fatal(err)
	}

	signedBlockRoot := signedBlockContents.SignedBlock.Message.HashTreeRoot(spec, tree.GetHashFn())
	if !bytes.Equal(signedBlockRoot[:], expectedBlockRoot[:]) {
		t.Fatalf("wrong signed block root: %s, expected %s", signedBlockRoot.String(), expectedBlockRoot.String())
	}

	// Compare the blobs
	if len(signedBlockContents.Blobs) != len(blockContents.Blobs) {
		t.Fatalf("wrong number of blobs: %d, expected %d", len(signedBlockContents.Blobs), len(blockContents.Blobs))
	}
	for i, blob := range signedBlockContents.Blobs {
		if !bytes.Equal(blob[:], blockContents.Blobs[i][:]) {
			t.Fatalf("wrong blob: %s, expected %s", blob.String(), blockContents.Blobs[i].String())
		}
	}

	// Compare the KZG proofs
	if len(signedBlockContents.KZGProofs) != len(blockContents.KZGProofs) {
		t.Fatalf("wrong number of KZG proofs: %d, expected %d", len(signedBlockContents.KZGProofs), len(blockContents.KZGProofs))
	}

	for i, proof := range signedBlockContents.KZGProofs {
		if !bytes.Equal(proof[:], blockContents.KZGProofs[i][:]) {
			t.Fatalf("wrong KZG proof: %s, expected %s", proof.String(), blockContents.KZGProofs[i].String())
		}
	}

	// Check that the signature is valid
	if valid, err := proposal_actions.VerifySignature(beaconBlockDomain, signedBlockRoot, validatorKey.ValidatorPubkey, signedBlockContents.SignedBlock.Signature); err != nil {
		t.Fatal(err)
	} else if !valid {
		t.Fatal("signature is invalid")
	}
}

func TestBlockCopying(t *testing.T) {
	version, blockContents, err := blobber.ParseResponse([]byte(responseDeneb))
	if err != nil {
		t.Fatal(err)
	} else if blockContents == nil {
		t.Fatal("block is nil")
	}
	if version != "deneb" {
		t.Fatalf("wrong version: %s, expected deneb", version)
	}

	expectedBlockContentsRoot := geth_common.HexToHash("0x63ab3be9cfed1fe67d61fc030edd985c838f865d524bdeb2faf340e03d861dd9")
	expectedBlockRoot := geth_common.HexToHash("0x37977b8edac80973deb38f3888bff9483b45b057c188ec041273cfe4485e2695")

	blockContentsCopy, err := proposal_actions.CopyBlockContents(blockContents)
	if err != nil {
		t.Fatal(err)
	}

	blockContentsCopyRoot := blockContentsCopy.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	if !bytes.Equal(blockContentsCopyRoot[:], expectedBlockContentsRoot[:]) {
		t.Fatalf("wrong block contents root: %s, expected %s", blockContentsCopyRoot.String(), expectedBlockContentsRoot.String())
	}

	blockCopyRoot := blockContentsCopy.Block.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	if !bytes.Equal(blockCopyRoot[:], expectedBlockRoot[:]) {
		t.Fatalf("wrong block root: %s, expected %s", blockCopyRoot.String(), expectedBlockRoot.String())
	}

	// Modify the copy and verify that the original container dit not change
	graffitiModifier := &proposal_actions.GraffitiModifier{
		NewGraffiti: "Modified",
		Append:      true,
	}
	graffitiModifier.ModifyBlock(spec, blockContentsCopy.Block)

	blockContentsRoot := blockContents.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	blockRoot := blockContents.Block.HashTreeRoot(configs.Mainnet, tree.GetHashFn())

	blockContentsCopyRoot = blockContentsCopy.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	blockCopyRoot = blockContentsCopy.Block.HashTreeRoot(configs.Mainnet, tree.GetHashFn())

	// Check that the original block contents did not change
	if !bytes.Equal(blockContentsRoot[:], expectedBlockContentsRoot[:]) {
		t.Fatalf("wrong block blob response root: %s, expected %s", blockContentsRoot.String(), expectedBlockContentsRoot.String())
	}
	if !bytes.Equal(blockRoot[:], expectedBlockRoot[:]) {
		t.Fatalf("wrong block root: %s, expected %s", blockCopyRoot.String(), expectedBlockRoot.String())
	}

	if bytes.Equal(blockContentsCopyRoot[:], blockContentsRoot[:]) {
		t.Fatalf("wrong block blob response root: %s, expected change from %s", blockContentsCopyRoot.String(), blockContentsRoot.String())
	}
	if bytes.Equal(blockCopyRoot[:], blockRoot[:]) {
		t.Fatalf("wrong block root: %s, expected change from %s", blockCopyRoot.String(), blockRoot.String())
	}

	// Restore graffiti
	blockContentsCopy.Block.Body.Graffiti = blockContents.Block.Body.Graffiti

	// Now modify a blob
	blockContentsCopy.Blobs[5] = make(deneb.Blob, len(blockContents.Blobs[5]))
	blockContentsRoot = blockContents.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	if !bytes.Equal(blockContentsRoot[:], expectedBlockContentsRoot[:]) {
		t.Fatalf("wrong block blob response root: %s, expected %s", blockContentsRoot.String(), expectedBlockContentsRoot.String())
	}

	blockContentsCopyRoot = blockContentsCopy.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
	if bytes.Equal(blockContentsCopyRoot[:], blockContentsRoot[:]) {
		t.Fatalf("wrong block blob response root: %s, expected change from %s", blockContentsCopyRoot.String(), blockContentsRoot.String())
	}
}

func TestRootTextConverters(t *testing.T) {
	r, err := proposal_actions.TextToRoot("test")
	if err != nil {
		t.Fatal(err)
	}
	text, err := proposal_actions.RootToText(r)
	if err != nil {
		t.Fatal(err)
	}
	if text != "test" {
		t.Fatalf("wrong text: %s, expected test", text)
	}
}
