package blobber_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	geth_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/blobber"
	"github.com/marioevz/blobber/common"
	"github.com/marioevz/blobber/proposal_actions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// Test data for Fulu blocks with various blob counts using the actual Fulu block structure
func generateFuluBlockResponse(blobCount int) string {
	blobs := make([]string, blobCount)
	kzgProofs := make([]string, blobCount)
	kzgCommitments := make([]string, blobCount)

	// Generate test data for each blob
	for i := 0; i < blobCount; i++ {
		// Generate dummy blob data (131072 bytes for proper blob size)
		blobData := make([]byte, 131072)
		copy(blobData[:4], []byte(fmt.Sprintf("%04d", i)))
		blobs[i] = fmt.Sprintf("0x%x", blobData)

		// Generate dummy KZG proof (48 bytes)
		kzgProofData := make([]byte, 48)
		for j := 0; j < 48; j++ {
			kzgProofData[j] = byte(i + j)
		}
		kzgProofs[i] = fmt.Sprintf("0x%x", kzgProofData)

		// Generate dummy KZG commitment (48 bytes)
		kzgCommitmentData := make([]byte, 48)
		for j := 0; j < 48; j++ {
			kzgCommitmentData[j] = byte(i + j + 100)
		}
		kzgCommitments[i] = fmt.Sprintf("0x%x", kzgCommitmentData)
	}

	// Convert to JSON
	blobsJSON, _ := json.Marshal(blobs)
	kzgProofsJSON, _ := json.Marshal(kzgProofs)
	kzgCommitmentsJSON, _ := json.Marshal(kzgCommitments)

	return fmt.Sprintf(`{
		"execution_optimistic": false,
		"finalized": true,
		"data": {
			"message": {
				"execution_payload_blinded": false,
				"block": {
					"slot": "12345",
					"proposer_index": "42",
					"parent_root": "0x4c2522c92d1bc2c116088566af3aa82e0e44f166563939d022dbdea91ee2c232",
					"state_root": "0x3ab74756ec62f454cf88f2a9dadfa0eccc542c215f8625622982cd84ccdcd403",
					"body": {
						"randao_reveal": "0x830094fc33d709d232e624eca65dcd8ed77591595c1bff6eea0fa8b700211c40368f25ed7b232f4fa6cba0cbc91950ab130297e1f5781dafc18d242b9debcbe419d6b1a907478a3165543aab130fa3e6b3222779323214ecd0e4dae5376b9341",
						"eth1_data": {
							"deposit_root": "0xd70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e",
							"deposit_count": "0",
							"block_hash": "0x40cfdeb068245b13986ba22098596af9dea7d8c186cb88b4191898c2f654c00d"
						},
						"graffiti": "0x4c6f6465737461722d76312e31312e3100000000000000000000000000000000",
						"proposer_slashings": [],
						"attester_slashings": [],
						"attestations": [],
						"deposits": [],
						"voluntary_exits": [],
						"sync_aggregate": {
							"sync_committee_bits": "0xffffffffffffffffffffffffffffffffcd27a6ceb9a52e091e728d226e30af17cd27a6ceb9a52e091e728d226e30af17cd27a6ceb9a52e091e728d226e30af17",
							"sync_committee_signature": "0xae4999d70ffd1beafdeb42513aa05fd60f81c9196efd813125e6ae8de3223a153f0120c3bb4a179fd371d9e9403709ab183cf1d97a59325978e949ca06cec0b314883699e0919c90f1318a529bec62239c4454b56e3a5ffb0a8e884cca6726c5"
						},
						"execution_payload": {
							"parent_hash": "0x51586ce7f9139b4e865353adbd1842b8436ea01eb57fc6db206f4fef378b33d9",
							"fee_recipient": "0x0000000000000000000000000000000000000000",
							"state_root": "0xdecd5cab7d5e5e8441c746f1caea1fb67191a392098a6be7869eb55deff68bcb",
							"receipts_root": "0x4fb7b2584ae750ff2999122562a70cb00fa9a8d56dc75902511b7bee5bc406b1",
							"logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"prev_randao": "0xf07812bf33e0772b9906d87f30a8563e93e49f96f198d3e163c4efcf3a00a95a",
							"block_number": "4",
							"gas_limit": "30000000",
							"gas_used": "0",
							"timestamp": "1696543823",
							"extra_data": "0xd883010d02846765746888676f312e32302e35856c696e7578",
							"base_fee_per_gas": "600362847",
							"block_hash": "0xa6138db1261e046bb99924c7b08c066ec667a99e54bcc1dc65a7a4aeb270f717",
							"transactions": [],
							"withdrawals": [],
							"blob_gas_used": "%d",
							"excess_blob_gas": "0"
						},
						"bls_to_execution_changes": [],
						"blob_kzg_commitments": %s,
						"execution_requests": {
							"deposits": [],
							"withdrawals": [],
							"consolidations": []
						}
					}
				},
				"kzg_proofs": %s,
				"blobs": %s
			}
		}
	}`, blobCount*131072, string(kzgCommitmentsJSON), string(kzgProofsJSON), string(blobsJSON))
}

// extractMessageFromFuluResponse extracts the message content from a Fulu response structure
func extractMessageFromFuluResponse(fuluResponse string) string {
	var fuluStruct struct {
		Data struct {
			Message json.RawMessage `json:"message"`
		} `json:"data"`
	}

	if err := json.Unmarshal([]byte(fuluResponse), &fuluStruct); err != nil {
		// If parsing fails, return the original response
		return fuluResponse
	}

	return string(fuluStruct.Data.Message)
}

func TestFuluBlockParsing(t *testing.T) {
	tests := []struct {
		name      string
		blobCount int
	}{
		{"zero blobs", 0},
		{"single blob", 1},
		{"multiple blobs", 3},
		{"maximum blobs", 6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test data - now in actual Fulu format
			testData := generateFuluBlockResponse(tt.blobCount)

			// Create a version-wrapped structure that extracts the message from the real Fulu format
			fuluResponse := fmt.Sprintf(`{"version": "fulu", "data": %s}`, extractMessageFromFuluResponse(testData))

			// Parse the response
			blockBlobResponse, err := blobber.ParseResponse([]byte(fuluResponse))
			require.NoError(t, err, "Failed to parse Fulu block response")
			require.NotNil(t, blockBlobResponse, "Block response should not be nil")

			// Verify version detection
			assert.Equal(t, common.VersionFulu, blockBlobResponse.Version, "Version should be detected as Fulu")

			// Verify Fulu block is populated
			require.NotNil(t, blockBlobResponse.Fulu, "Fulu block should not be nil")
			assert.Nil(t, blockBlobResponse.Deneb, "Deneb block should be nil for Fulu")
			assert.Nil(t, blockBlobResponse.Electra, "Electra block should be nil for Fulu")

			// Verify block contents
			fuluBlock := blockBlobResponse.Fulu
			assert.Equal(t, phase0.Slot(12345), fuluBlock.Block.Slot, "Slot should match")
			assert.Equal(t, phase0.ValidatorIndex(42), fuluBlock.Block.ProposerIndex, "Proposer index should match")

			// Verify blob count
			assert.Equal(t, tt.blobCount, len(fuluBlock.Blobs), "Blob count should match")
			assert.Equal(t, tt.blobCount, len(fuluBlock.KZGProofs), "KZG proof count should match")
			assert.Equal(t, tt.blobCount, len(fuluBlock.Block.Body.BlobKZGCommitments), "KZG commitment count should match")

			// Verify blob data if present
			for i, blob := range fuluBlock.Blobs {
				assert.Len(t, blob, 131072, "Blob %d should be 131072 bytes", i)
				// Check that blob starts with index marker
				expectedPrefix := fmt.Sprintf("%04d", i)
				actualPrefix := string(blob[:4])
				assert.Equal(t, expectedPrefix, actualPrefix, "Blob %d should have correct index prefix", i)
			}

			// Test VersionedBlockContents helper methods
			assert.Equal(t, phase0.Slot(12345), blockBlobResponse.GetSlot(), "GetSlot should work for Fulu")
			assert.Equal(t, phase0.ValidatorIndex(42), blockBlobResponse.GetProposerIndex(), "GetProposerIndex should work for Fulu")
			assert.Equal(t, tt.blobCount, blockBlobResponse.GetBlobsCount(), "GetBlobsCount should work for Fulu")
			assert.Equal(t, len(fuluBlock.Blobs), len(blockBlobResponse.GetBlobs()), "GetBlobs should work for Fulu")
			assert.Equal(t, len(fuluBlock.KZGProofs), len(blockBlobResponse.GetKZGProofs()), "GetKZGProofs should work for Fulu")
			assert.Equal(t, len(fuluBlock.Block.Body.BlobKZGCommitments), len(blockBlobResponse.GetBlobKZGCommitments()), "GetBlobKZGCommitments should work for Fulu")

			// Test Fulu-specific methods
			fuluBlockFromMethod := blockBlobResponse.GetFuluBlock()
			require.NotNil(t, fuluBlockFromMethod, "GetFuluBlock should return the block")
			assert.Equal(t, fuluBlock.Block.Slot, fuluBlockFromMethod.Slot, "GetFuluBlock should return correct block")

			// Verify that other fork methods return nil
			assert.Nil(t, blockBlobResponse.GetDenebBlock(), "GetDenebBlock should return nil for Fulu")
			assert.Nil(t, blockBlobResponse.GetElectraBlock(), "GetElectraBlock should return nil for Fulu")
		})
	}
}

func TestFuluVersionDetection(t *testing.T) {
	tests := []struct {
		name            string
		responseJSON    string
		expectedVersion string
		expectError     bool
	}{
		{
			name:            "valid fulu version",
			responseJSON:    fmt.Sprintf(`{"version": "fulu", "data": %s}`, extractMessageFromFuluResponse(generateFuluBlockResponse(0))),
			expectedVersion: common.VersionFulu,
			expectError:     false,
		},
		{
			name:            "case sensitive version",
			responseJSON:    fmt.Sprintf(`{"version": "FULU", "data": %s}`, extractMessageFromFuluResponse(generateFuluBlockResponse(0))),
			expectedVersion: "FULU", // Should preserve exact case
			expectError:     false,
		},
		{
			name:            "electra for comparison",
			responseJSON:    fmt.Sprintf(`{"version": "electra", "data": %s}`, extractMessageFromFuluResponse(generateFuluBlockResponse(0))),
			expectedVersion: common.VersionElectra,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blockBlobResponse, err := blobber.ParseResponse([]byte(tt.responseJSON))

			if tt.expectError {
				assert.Error(t, err, "Expected parsing error")
				return
			}

			require.NoError(t, err, "Should parse without error")
			require.NotNil(t, blockBlobResponse, "Response should not be nil")
			assert.Equal(t, tt.expectedVersion, blockBlobResponse.Version, "Version should be correctly detected")
		})
	}
}

func TestFuluErrorHandling(t *testing.T) {
	tests := []struct {
		name         string
		responseJSON string
		expectError  bool
		errorSubstr  string
	}{
		{
			name:         "invalid JSON in data",
			responseJSON: `{"version": "fulu", "data": {"invalid json"}}`,
			expectError:  true,
			errorSubstr:  "failed to unmarshal response into blockdatastruct",
		},
		{
			name:         "missing required fields",
			responseJSON: `{"version": "fulu", "data": {"block": {}}}`,
			expectError:  true,
			errorSubstr:  "failed to decode fulu block contents",
		},
		{
			name:         "malformed blob data",
			responseJSON: `{"version": "fulu", "data": {"block": {"slot": "1", "proposer_index": "0", "parent_root": "0x0000000000000000000000000000000000000000000000000000000000000000", "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000", "body": {"randao_reveal": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "eth1_data": {"deposit_root": "0x0000000000000000000000000000000000000000000000000000000000000000", "deposit_count": "0", "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000"}, "graffiti": "0x0000000000000000000000000000000000000000000000000000000000000000", "proposer_slashings": [], "attester_slashings": [], "attestations": [], "deposits": [], "voluntary_exits": [], "sync_aggregate": {"sync_committee_bits": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "sync_committee_signature": "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}, "execution_payload": {"parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000", "fee_recipient": "0x0000000000000000000000000000000000000000", "state_root": "0x0000000000000000000000000000000000000000000000000000000000000000", "receipts_root": "0x0000000000000000000000000000000000000000000000000000000000000000", "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "prev_randao": "0x0000000000000000000000000000000000000000000000000000000000000000", "block_number": "1", "gas_limit": "30000000", "gas_used": "0", "timestamp": "1234567890", "extra_data": "0x", "base_fee_per_gas": "1000000000", "block_hash": "0x0000000000000000000000000000000000000000000000000000000000000000", "transactions": [], "withdrawals": [], "blob_gas_used": "0", "excess_blob_gas": "0", "deposit_requests": [], "withdrawal_requests": [], "consolidation_requests": []}, "bls_to_execution_changes": [], "blob_kzg_commitments": []}}, "kzg_proofs": ["invalid_proof"], "blobs": ["invalid_blob"]}}`,
			expectError:  true,
			errorSubstr:  "failed to decode fulu block contents",
		},
		{
			name:         "missing version field",
			responseJSON: `{"data": {"block": {"slot": "1"}}}`,
			expectError:  false, // The parser handles missing version gracefully and returns VersionedBlockContents with empty version
			errorSubstr:  "",
		},
		{
			name:         "null data field",
			responseJSON: `{"version": "fulu", "data": null}`,
			expectError:  false, // The parser handles null data gracefully
			errorSubstr:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blockBlobResponse, err := blobber.ParseResponse([]byte(tt.responseJSON))

			if tt.expectError {
				assert.Error(t, err, "Expected an error")
				if tt.errorSubstr != "" && err != nil {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errorSubstr), "Error should contain expected substring")
				}
				return
			}

			require.NoError(t, err, "Should not error for valid input")
			// Note: Some edge cases may return nil response even without error
			if blockBlobResponse != nil {
				// Additional validation can be added here if needed
				assert.NotEmpty(t, blockBlobResponse.Version, "Version should be set when response is not nil")
			}
		})
	}
}

func TestFuluCompatibilityWithElectra(t *testing.T) {
	// Test that Fulu blocks are processed as Electra format
	testData := generateFuluBlockResponse(2)
	extractedMessage := extractMessageFromFuluResponse(testData)
	fuluResponse := fmt.Sprintf(`{"version": "fulu", "data": %s}`, extractedMessage)

	// Parse as Fulu
	fuluBlock, err := blobber.ParseResponse([]byte(fuluResponse))
	require.NoError(t, err)
	require.NotNil(t, fuluBlock)
	require.NotNil(t, fuluBlock.Fulu)

	// Parse the same data as Electra
	electraResponse := fmt.Sprintf(`{"version": "electra", "data": %s}`, extractedMessage)
	electraBlock, err := blobber.ParseResponse([]byte(electraResponse))
	require.NoError(t, err)
	require.NotNil(t, electraBlock)
	require.NotNil(t, electraBlock.Electra)

	// Verify that the underlying block structures are equivalent
	assert.Equal(t, fuluBlock.Fulu.Block.Slot, electraBlock.Electra.Block.Slot, "Slot should be the same")
	assert.Equal(t, fuluBlock.Fulu.Block.ProposerIndex, electraBlock.Electra.Block.ProposerIndex, "Proposer index should be the same")
	assert.Equal(t, len(fuluBlock.Fulu.Blobs), len(electraBlock.Electra.Blobs), "Blob count should be the same")
	assert.Equal(t, len(fuluBlock.Fulu.KZGProofs), len(electraBlock.Electra.KZGProofs), "KZG proof count should be the same")

	// Verify blob contents are identical
	for i, fuluBlob := range fuluBlock.Fulu.Blobs {
		electraBlob := electraBlock.Electra.Blobs[i]
		assert.Equal(t, fuluBlob, electraBlob, "Blob %d should be identical", i)
	}

	// Verify KZG proofs are identical
	for i, fuluProof := range fuluBlock.Fulu.KZGProofs {
		electraProof := electraBlock.Electra.KZGProofs[i]
		assert.Equal(t, fuluProof, electraProof, "KZG proof %d should be identical", i)
	}

	// Verify that VersionedBlockContents methods work identically
	assert.Equal(t, fuluBlock.GetSlot(), electraBlock.GetSlot(), "GetSlot should return same value")
	assert.Equal(t, fuluBlock.GetProposerIndex(), electraBlock.GetProposerIndex(), "GetProposerIndex should return same value")
	assert.Equal(t, fuluBlock.GetBlobsCount(), electraBlock.GetBlobsCount(), "GetBlobsCount should return same value")
}
