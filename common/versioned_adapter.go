package common

import (
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// ConvertVersionedToDeneb converts a VersionedBlockContents to Deneb BlockContents for proposal actions
// This allows existing proposal actions to work with both Deneb and Electra blocks
func ConvertVersionedToDeneb(versioned *VersionedBlockContents) *apiv1deneb.BlockContents {
	if versioned == nil {
		return nil
	}
	
	switch versioned.Version {
	case "deneb":
		return versioned.Deneb
	case "electra":
		// For Electra, we create a Deneb BlockContents with the compatible fields
		if versioned.Electra != nil {
			// Convert Electra to Deneb format
			// Note: This only works because Electra extends Deneb with additional fields
			// The blob-related fields remain compatible
			return &apiv1deneb.BlockContents{
				Block:     convertElectraToDenebBlock(versioned.Electra.Block),
				KZGProofs: versioned.Electra.KZGProofs,
				Blobs:     versioned.Electra.Blobs,
			}
		}
	}
	
	return nil
}

// convertElectraToDenebBlock converts an Electra block to Deneb block format
// This is a simplified conversion that preserves the fields needed for proposal actions
func convertElectraToDenebBlock(electraBlock *electra.BeaconBlock) *deneb.BeaconBlock {
	if electraBlock == nil {
		return nil
	}
	
	// Create a Deneb block with the common fields
	// Note: This loses Electra-specific fields but preserves what's needed for proposal actions
	return &deneb.BeaconBlock{
		Slot:          electraBlock.Slot,
		ProposerIndex: electraBlock.ProposerIndex,
		ParentRoot:    electraBlock.ParentRoot,
		StateRoot:     electraBlock.StateRoot,
		Body:          convertElectraToDenebBody(electraBlock.Body),
	}
}

// convertElectraToDenebBody converts an Electra block body to Deneb format
func convertElectraToDenebBody(electraBody *electra.BeaconBlockBody) *deneb.BeaconBlockBody {
	if electraBody == nil {
		return nil
	}
	
	// Create a Deneb body with the common fields that are needed for proposal actions
	// Note: Electra has a different structure, so we only copy the essential fields
	return &deneb.BeaconBlockBody{
		RANDAOReveal:       electraBody.RANDAOReveal,
		ETH1Data:           electraBody.ETH1Data,
		Graffiti:           electraBody.Graffiti,
		// Skip slashings and attestations as they have different formats
		ProposerSlashings:  []*phase0.ProposerSlashing{},
		AttesterSlashings:  []*phase0.AttesterSlashing{},
		Attestations:       []*phase0.Attestation{},
		Deposits:           electraBody.Deposits,
		VoluntaryExits:     electraBody.VoluntaryExits,
		SyncAggregate:      electraBody.SyncAggregate,
		// ExecutionPayload would need special handling - for now use empty
		ExecutionPayload:   &deneb.ExecutionPayload{},
		BLSToExecutionChanges: electraBody.BLSToExecutionChanges,
		BlobKZGCommitments: electraBody.BlobKZGCommitments,
	}
}