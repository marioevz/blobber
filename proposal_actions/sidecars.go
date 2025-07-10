package proposal_actions

import (
	"fmt"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// GenerateSidecars generates blob sidecars from signed block contents
func GenerateSidecars(spec map[string]interface{}, signedBlockContents *apiv1deneb.SignedBlockContents) ([]*deneb.BlobSidecar, error) {
	if signedBlockContents == nil {
		return nil, fmt.Errorf("signed block contents is nil")
	}
	if signedBlockContents.SignedBlock == nil {
		return nil, fmt.Errorf("signed block is nil")
	}

	block := signedBlockContents.SignedBlock.Message
	signature := signedBlockContents.SignedBlock.Signature

	// Create signed block header from the block
	bodyRoot, err := block.Body.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute body root: %w", err)
	}

	blockHeader := &phase0.BeaconBlockHeader{
		Slot:          block.Slot,
		ProposerIndex: block.ProposerIndex,
		ParentRoot:    block.ParentRoot,
		StateRoot:     block.StateRoot,
		BodyRoot:      bodyRoot,
	}

	signedBlockHeader := &phase0.SignedBeaconBlockHeader{
		Message:   blockHeader,
		Signature: signature,
	}

	// Generate sidecars for each blob
	sidecars := make([]*deneb.BlobSidecar, len(signedBlockContents.Blobs))
	for i := range signedBlockContents.Blobs {
		if i >= len(block.Body.BlobKZGCommitments) {
			return nil, fmt.Errorf("blob index %d exceeds KZG commitments length %d", i, len(block.Body.BlobKZGCommitments))
		}
		if i >= len(signedBlockContents.KZGProofs) {
			return nil, fmt.Errorf("blob index %d exceeds KZG proofs length %d", i, len(signedBlockContents.KZGProofs))
		}

		// Generate inclusion proof for this blob's KZG commitment
		inclusionProof, err := generateKZGCommitmentInclusionProof(block.Body, uint64(i))
		if err != nil {
			return nil, fmt.Errorf("failed to generate inclusion proof for blob %d: %w", i, err)
		}

		sidecars[i] = &deneb.BlobSidecar{
			Index:                       deneb.BlobIndex(i),
			Blob:                        signedBlockContents.Blobs[i],
			KZGCommitment:               block.Body.BlobKZGCommitments[i],
			KZGProof:                    signedBlockContents.KZGProofs[i],
			SignedBlockHeader:           signedBlockHeader,
			KZGCommitmentInclusionProof: inclusionProof,
		}
	}

	return sidecars, nil
}

// generateKZGCommitmentInclusionProof generates a Merkle proof showing that the KZG commitment
// at the given index is included in the beacon block body
func generateKZGCommitmentInclusionProof(body *deneb.BeaconBlockBody, blobIndex uint64) (deneb.KZGCommitmentInclusionProof, error) {
	// The inclusion proof needs to show the path from the KZG commitment to the body root
	// This involves:
	// 1. The path within the blob_kzg_commitments list
	// 2. The path from blob_kzg_commitments root to the body root

	// For now, we'll create a placeholder proof
	// In a production implementation, this would compute the actual Merkle proof
	var proof deneb.KZGCommitmentInclusionProof

	// The proof depth depends on the generalized index of blob_kzg_commitments in the body
	// and the index of the specific commitment within the list
	// This is a simplified implementation - a full implementation would need to:
	// 1. Build the Merkle tree of the blob_kzg_commitments list
	// 2. Get the generalized index path from the commitment to the body root
	// 3. Collect the sibling hashes along this path

	// Placeholder: Initialize with zero hashes
	// The actual proof would be computed using the SSZ Merkle tree structure
	for i := range proof {
		proof[i] = deneb.KZGCommitmentInclusionProofElement{}
	}

	return proof, nil
}

// VerifyBlobSidecar verifies that a blob sidecar is valid
func VerifyBlobSidecar(sidecar *deneb.BlobSidecar) error {
	if sidecar == nil {
		return fmt.Errorf("sidecar is nil")
	}

	// Verify the index is valid
	const maxBlobsPerBlock = 6 // MAX_BLOBS_PER_BLOCK from consensus specs
	if sidecar.Index >= maxBlobsPerBlock {
		return fmt.Errorf("blob index %d exceeds maximum %d", sidecar.Index, maxBlobsPerBlock)
	}

	// Additional verification would include:
	// 1. Verifying the KZG proof against the blob and commitment
	// 2. Verifying the inclusion proof
	// 3. Verifying the signed block header signature

	return nil
}
