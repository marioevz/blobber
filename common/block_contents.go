package common

import (
	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

const (
	VersionDeneb   = "deneb"
	VersionElectra = "electra"
	VersionFulu    = "fulu"
)

// VersionedBlockContents represents block contents that can be Deneb, Electra, or Fulu
type VersionedBlockContents struct {
	Version string
	Deneb   *apiv1deneb.BlockContents
	Electra *apiv1electra.BlockContents
	Fulu    *apiv1electra.BlockContents // Fulu uses the same structure as Electra
}

// GetSlot returns the slot of the block
func (v *VersionedBlockContents) GetSlot() phase0.Slot {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil && v.Deneb.Block != nil {
			return v.Deneb.Block.Slot
		}
	case VersionElectra:
		if v.Electra != nil && v.Electra.Block != nil {
			return v.Electra.Block.Slot
		}
	case VersionFulu:
		if v.Fulu != nil && v.Fulu.Block != nil {
			return v.Fulu.Block.Slot
		}
	}
	return phase0.Slot(0)
}

// GetProposerIndex returns the proposer index of the block
func (v *VersionedBlockContents) GetProposerIndex() phase0.ValidatorIndex {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil && v.Deneb.Block != nil {
			return v.Deneb.Block.ProposerIndex
		}
	case VersionElectra:
		if v.Electra != nil && v.Electra.Block != nil {
			return v.Electra.Block.ProposerIndex
		}
	case VersionFulu:
		if v.Fulu != nil && v.Fulu.Block != nil {
			return v.Fulu.Block.ProposerIndex
		}
	}
	return phase0.ValidatorIndex(0)
}

// GetBlobsCount returns the number of blobs
func (v *VersionedBlockContents) GetBlobsCount() int {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil {
			return len(v.Deneb.Blobs)
		}
	case VersionElectra:
		if v.Electra != nil {
			return len(v.Electra.Blobs)
		}
	case VersionFulu:
		if v.Fulu != nil {
			return len(v.Fulu.Blobs)
		}
	}
	return 0
}

// GetBlobs returns the blobs
func (v *VersionedBlockContents) GetBlobs() []deneb.Blob {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil {
			return v.Deneb.Blobs
		}
	case VersionElectra:
		if v.Electra != nil {
			// Electra uses the same blob type as Deneb
			return v.Electra.Blobs
		}
	case VersionFulu:
		if v.Fulu != nil {
			// Fulu uses the same blob type as Deneb
			return v.Fulu.Blobs
		}
	}
	return nil
}

// GetKZGProofs returns the KZG proofs
func (v *VersionedBlockContents) GetKZGProofs() []deneb.KZGProof {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil {
			return v.Deneb.KZGProofs
		}
	case VersionElectra:
		if v.Electra != nil {
			return v.Electra.KZGProofs
		}
	case VersionFulu:
		if v.Fulu != nil {
			return v.Fulu.KZGProofs
		}
	}
	return nil
}

// GetDenebBlock returns the Deneb block if this is a Deneb block
func (v *VersionedBlockContents) GetDenebBlock() *deneb.BeaconBlock {
	if v.Version == VersionDeneb && v.Deneb != nil {
		return v.Deneb.Block
	}
	return nil
}

// GetElectraBlock returns the Electra block if this is an Electra block
func (v *VersionedBlockContents) GetElectraBlock() *electra.BeaconBlock {
	if v.Version == VersionElectra && v.Electra != nil {
		return v.Electra.Block
	}
	return nil
}

// GetFuluBlock returns the Fulu block if this is a Fulu block
func (v *VersionedBlockContents) GetFuluBlock() *electra.BeaconBlock {
	if v.Version == VersionFulu && v.Fulu != nil {
		return v.Fulu.Block
	}
	return nil
}

// GetGraffiti returns the graffiti field
func (v *VersionedBlockContents) GetGraffiti() [32]byte {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil && v.Deneb.Block != nil && v.Deneb.Block.Body != nil {
			return v.Deneb.Block.Body.Graffiti
		}
	case VersionElectra:
		if v.Electra != nil && v.Electra.Block != nil && v.Electra.Block.Body != nil {
			return v.Electra.Block.Body.Graffiti
		}
	case VersionFulu:
		if v.Fulu != nil && v.Fulu.Block != nil && v.Fulu.Block.Body != nil {
			return v.Fulu.Block.Body.Graffiti
		}
	}
	return [32]byte{}
}

// SetGraffiti sets the graffiti field
func (v *VersionedBlockContents) SetGraffiti(graffiti [32]byte) {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil && v.Deneb.Block != nil && v.Deneb.Block.Body != nil {
			v.Deneb.Block.Body.Graffiti = graffiti
		}
	case VersionElectra:
		if v.Electra != nil && v.Electra.Block != nil && v.Electra.Block.Body != nil {
			v.Electra.Block.Body.Graffiti = graffiti
		}
	case VersionFulu:
		if v.Fulu != nil && v.Fulu.Block != nil && v.Fulu.Block.Body != nil {
			v.Fulu.Block.Body.Graffiti = graffiti
		}
	}
}

// GetBlobKZGCommitments returns the blob KZG commitments
func (v *VersionedBlockContents) GetBlobKZGCommitments() []deneb.KZGCommitment {
	switch v.Version {
	case VersionDeneb:
		if v.Deneb != nil && v.Deneb.Block != nil && v.Deneb.Block.Body != nil {
			return v.Deneb.Block.Body.BlobKZGCommitments
		}
	case VersionElectra:
		if v.Electra != nil && v.Electra.Block != nil && v.Electra.Block.Body != nil {
			return v.Electra.Block.Body.BlobKZGCommitments
		}
	case VersionFulu:
		if v.Fulu != nil && v.Fulu.Block != nil && v.Fulu.Block.Body != nil {
			return v.Fulu.Block.Body.BlobKZGCommitments
		}
	}
	return nil
}
