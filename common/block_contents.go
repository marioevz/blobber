package common

import (
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// VersionedBlockContents represents block contents that can be either Deneb or Electra
type VersionedBlockContents struct {
	Version string
	Deneb   *apiv1deneb.BlockContents
	Electra *apiv1electra.BlockContents
}

// GetSlot returns the slot of the block
func (v *VersionedBlockContents) GetSlot() phase0.Slot {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil && v.Deneb.Block != nil {
			return v.Deneb.Block.Slot
		}
	case "electra":
		if v.Electra != nil && v.Electra.Block != nil {
			return v.Electra.Block.Slot
		}
	}
	return phase0.Slot(0)
}

// GetProposerIndex returns the proposer index of the block
func (v *VersionedBlockContents) GetProposerIndex() phase0.ValidatorIndex {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil && v.Deneb.Block != nil {
			return v.Deneb.Block.ProposerIndex
		}
	case "electra":
		if v.Electra != nil && v.Electra.Block != nil {
			return v.Electra.Block.ProposerIndex
		}
	}
	return phase0.ValidatorIndex(0)
}

// GetBlobsCount returns the number of blobs
func (v *VersionedBlockContents) GetBlobsCount() int {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil {
			return len(v.Deneb.Blobs)
		}
	case "electra":
		if v.Electra != nil {
			return len(v.Electra.Blobs)
		}
	}
	return 0
}

// GetBlobs returns the blobs
func (v *VersionedBlockContents) GetBlobs() []deneb.Blob {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil {
			return v.Deneb.Blobs
		}
	case "electra":
		if v.Electra != nil {
			// Electra uses the same blob type as Deneb
			return v.Electra.Blobs
		}
	}
	return nil
}

// GetKZGProofs returns the KZG proofs
func (v *VersionedBlockContents) GetKZGProofs() []deneb.KZGProof {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil {
			return v.Deneb.KZGProofs
		}
	case "electra":
		if v.Electra != nil {
			return v.Electra.KZGProofs
		}
	}
	return nil
}

// GetDenebBlock returns the Deneb block if this is a Deneb block
func (v *VersionedBlockContents) GetDenebBlock() *deneb.BeaconBlock {
	if v.Version == "deneb" && v.Deneb != nil {
		return v.Deneb.Block
	}
	return nil
}

// GetElectraBlock returns the Electra block if this is an Electra block
func (v *VersionedBlockContents) GetElectraBlock() *electra.BeaconBlock {
	if v.Version == "electra" && v.Electra != nil {
		return v.Electra.Block
	}
	return nil
}

// GetGraffiti returns the graffiti field
func (v *VersionedBlockContents) GetGraffiti() [32]byte {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil && v.Deneb.Block != nil && v.Deneb.Block.Body != nil {
			return v.Deneb.Block.Body.Graffiti
		}
	case "electra":
		if v.Electra != nil && v.Electra.Block != nil && v.Electra.Block.Body != nil {
			return v.Electra.Block.Body.Graffiti
		}
	}
	return [32]byte{}
}

// SetGraffiti sets the graffiti field
func (v *VersionedBlockContents) SetGraffiti(graffiti [32]byte) {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil && v.Deneb.Block != nil && v.Deneb.Block.Body != nil {
			v.Deneb.Block.Body.Graffiti = graffiti
		}
	case "electra":
		if v.Electra != nil && v.Electra.Block != nil && v.Electra.Block.Body != nil {
			v.Electra.Block.Body.Graffiti = graffiti
		}
	}
}

// GetBlobKZGCommitments returns the blob KZG commitments
func (v *VersionedBlockContents) GetBlobKZGCommitments() []deneb.KZGCommitment {
	switch v.Version {
	case "deneb":
		if v.Deneb != nil && v.Deneb.Block != nil && v.Deneb.Block.Body != nil {
			return v.Deneb.Block.Body.BlobKZGCommitments
		}
	case "electra":
		if v.Electra != nil && v.Electra.Block != nil && v.Electra.Block.Body != nil {
			return v.Electra.Block.Body.BlobKZGCommitments
		}
	}
	return nil
}