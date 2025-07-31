package common

import (
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/sirupsen/logrus"
)

// ConvertVersionedToDeneb converts a VersionedBlockContents to Deneb BlockContents for proposal actions
// This allows existing proposal actions to work with Deneb, Electra, and Fulu blocks
func ConvertVersionedToDeneb(versioned *VersionedBlockContents) *apiv1deneb.BlockContents {
	if versioned == nil {
		logrus.Debug("ConvertVersionedToDeneb called with nil versioned block contents")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"version":        versioned.Version,
		"slot":           versioned.GetSlot(),
		"proposer_index": versioned.GetProposerIndex(),
		"blob_count":     versioned.GetBlobsCount(),
	}).Debug("Converting versioned block contents to Deneb format")

	switch versioned.Version {
	case VersionDeneb:
		logrus.Debug("Block is already in Deneb format, returning as-is")
		return versioned.Deneb
	case VersionElectra:
		// For Electra, we create a Deneb BlockContents with the compatible fields
		if versioned.Electra != nil {
			logrus.WithFields(logrus.Fields{
				"version":    "electra",
				"slot":       versioned.Electra.Block.Slot,
				"proposer":   versioned.Electra.Block.ProposerIndex,
				"blob_count": len(versioned.Electra.Blobs),
			}).Debug("Converting Electra block contents to Deneb format")

			// Convert Electra to Deneb format
			// Note: This only works because Electra extends Deneb with additional fields
			// The blob-related fields remain compatible
			result := &apiv1deneb.BlockContents{
				Block:     convertElectraToDenebBlock(versioned.Electra.Block),
				KZGProofs: versioned.Electra.KZGProofs,
				Blobs:     versioned.Electra.Blobs,
			}

			logrus.Debug("Successfully converted Electra block to Deneb format")
			return result
		}
		logrus.Warn("Electra version specified but Electra block contents are nil")
	case VersionFulu:
		// For Fulu, we create a Deneb BlockContents with the compatible fields
		if versioned.Fulu != nil {
			logrus.WithFields(logrus.Fields{
				"version":    "fulu",
				"slot":       versioned.Fulu.Block.Slot,
				"proposer":   versioned.Fulu.Block.ProposerIndex,
				"blob_count": len(versioned.Fulu.Blobs),
			}).Info("Converting Fulu block contents to Deneb format")

			// Convert Fulu to Deneb format
			// Note: Fulu uses the same structure as Electra for now
			result := &apiv1deneb.BlockContents{
				Block:     convertElectraToDenebBlock(versioned.Fulu.Block),
				KZGProofs: versioned.Fulu.KZGProofs,
				Blobs:     versioned.Fulu.Blobs,
			}

			logrus.Info("Successfully converted Fulu block to Deneb format")
			return result
		}
		logrus.Warn("Fulu version specified but Fulu block contents are nil")
	default:
		logrus.WithField("version", versioned.Version).Error("Unknown block version in ConvertVersionedToDeneb")
	}

	logrus.Debug("Returning nil from ConvertVersionedToDeneb - no valid block contents found")
	return nil
}

// convertElectraToDenebBlock converts an Electra block to Deneb block format
// This is a simplified conversion that preserves the fields needed for proposal actions
func convertElectraToDenebBlock(electraBlock *electra.BeaconBlock) *deneb.BeaconBlock {
	if electraBlock == nil {
		logrus.Debug("convertElectraToDenebBlock called with nil Electra block")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"slot":           electraBlock.Slot,
		"proposer_index": electraBlock.ProposerIndex,
		"parent_root":    electraBlock.ParentRoot.String(),
		"state_root":     electraBlock.StateRoot.String(),
	}).Debug("Converting Electra beacon block to Deneb format")

	// Create a Deneb block with the common fields
	// Note: This loses Electra-specific fields but preserves what's needed for proposal actions
	result := &deneb.BeaconBlock{
		Slot:          electraBlock.Slot,
		ProposerIndex: electraBlock.ProposerIndex,
		ParentRoot:    electraBlock.ParentRoot,
		StateRoot:     electraBlock.StateRoot,
		Body:          convertElectraToDenebBody(electraBlock.Body),
	}

	logrus.Debug("Successfully converted Electra beacon block to Deneb format")
	return result
}

// convertElectraToDenebBody converts an Electra block body to Deneb format
func convertElectraToDenebBody(electraBody *electra.BeaconBlockBody) *deneb.BeaconBlockBody {
	if electraBody == nil {
		logrus.Debug("convertElectraToDenebBody called with nil Electra block body")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"deposits_count":             len(electraBody.Deposits),
		"voluntary_exits_count":      len(electraBody.VoluntaryExits),
		"bls_to_execution_changes":   len(electraBody.BLSToExecutionChanges),
		"blob_kzg_commitments_count": len(electraBody.BlobKZGCommitments),
		"has_execution_payload":      electraBody.ExecutionPayload != nil,
	}).Debug("Converting Electra block body to Deneb format")

	// Log warning about field differences
	logrus.Debug("Note: Electra-specific slashings and attestations will be excluded in Deneb conversion")

	// Create a Deneb body with the common fields that are needed for proposal actions
	// Note: Electra has a different structure, so we only copy the essential fields
	result := &deneb.BeaconBlockBody{
		RANDAOReveal: electraBody.RANDAOReveal,
		ETH1Data:     electraBody.ETH1Data,
		Graffiti:     electraBody.Graffiti,
		// Skip slashings and attestations as they have different formats
		ProposerSlashings: []*phase0.ProposerSlashing{},
		AttesterSlashings: []*phase0.AttesterSlashing{},
		Attestations:      []*phase0.Attestation{},
		Deposits:          electraBody.Deposits,
		VoluntaryExits:    electraBody.VoluntaryExits,
		SyncAggregate:     electraBody.SyncAggregate,
		// Convert ExecutionPayload from Electra to Deneb format
		ExecutionPayload:      convertElectraToDenebPayload(electraBody.ExecutionPayload),
		BLSToExecutionChanges: electraBody.BLSToExecutionChanges,
		BlobKZGCommitments:    electraBody.BlobKZGCommitments,
	}

	logrus.Debug("Successfully converted Electra block body to Deneb format")
	return result
}

// convertElectraToDenebPayload converts an Electra execution payload to Deneb format
func convertElectraToDenebPayload(electraPayload *deneb.ExecutionPayload) *deneb.ExecutionPayload {
	if electraPayload == nil {
		logrus.Debug("convertElectraToDenebPayload called with nil Electra execution payload")
		return nil
	}

	logrus.WithFields(logrus.Fields{
		"block_number":    electraPayload.BlockNumber,
		"gas_limit":       electraPayload.GasLimit,
		"gas_used":        electraPayload.GasUsed,
		"timestamp":       electraPayload.Timestamp,
		"transactions":    len(electraPayload.Transactions),
		"withdrawals":     len(electraPayload.Withdrawals),
		"blob_gas_used":   electraPayload.BlobGasUsed,
		"excess_blob_gas": electraPayload.ExcessBlobGas,
		"has_base_fee":    electraPayload.BaseFeePerGas != nil,
	}).Debug("Converting Electra execution payload to Deneb format")

	// Since Electra uses deneb.ExecutionPayload, we need to ensure nil fields are handled
	// Create a copy to avoid modifying the original
	result := &deneb.ExecutionPayload{
		ParentHash:    electraPayload.ParentHash,
		FeeRecipient:  electraPayload.FeeRecipient,
		StateRoot:     electraPayload.StateRoot,
		ReceiptsRoot:  electraPayload.ReceiptsRoot,
		LogsBloom:     electraPayload.LogsBloom,
		PrevRandao:    electraPayload.PrevRandao,
		BlockNumber:   electraPayload.BlockNumber,
		GasLimit:      electraPayload.GasLimit,
		GasUsed:       electraPayload.GasUsed,
		Timestamp:     electraPayload.Timestamp,
		ExtraData:     electraPayload.ExtraData,
		BaseFeePerGas: electraPayload.BaseFeePerGas,
		BlockHash:     electraPayload.BlockHash,
		Transactions:  electraPayload.Transactions,
		Withdrawals:   electraPayload.Withdrawals,
		BlobGasUsed:   electraPayload.BlobGasUsed,
		ExcessBlobGas: electraPayload.ExcessBlobGas,
	}

	// Ensure required fields are not nil
	if result.BaseFeePerGas == nil {
		logrus.Debug("BaseFeePerGas was nil, initializing with zero value")
		result.BaseFeePerGas = new(uint256.Int)
	}

	logrus.Debug("Successfully converted Electra execution payload to Deneb format")
	return result
}
