package common

import (
	"testing"

	apiv1deneb "github.com/attestantio/go-eth2-client/api/v1/deneb"
	apiv1electra "github.com/attestantio/go-eth2-client/api/v1/electra"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestConvertVersionedToDeneb_DenebBlock(t *testing.T) {
	// Create a test Deneb block
	denebBlock := &apiv1deneb.BlockContents{
		Block: &deneb.BeaconBlock{
			Slot:          100,
			ProposerIndex: 5,
			ParentRoot:    phase0.Root{1, 2, 3},
			StateRoot:     phase0.Root{4, 5, 6},
			Body: &deneb.BeaconBlockBody{
				Graffiti: [32]byte{7, 8, 9},
			},
		},
		Blobs: []deneb.Blob{
			{},
			{},
		},
		KZGProofs: []deneb.KZGProof{
			{},
			{},
		},
	}

	versioned := &VersionedBlockContents{
		Version: "deneb",
		Deneb:   denebBlock,
	}

	result := ConvertVersionedToDeneb(versioned)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result != denebBlock {
		t.Error("expected same deneb block to be returned")
	}

	if result.Block.Slot != 100 {
		t.Errorf("expected slot 100, got %d", result.Block.Slot)
	}
}

func TestConvertVersionedToDeneb_FuluBlock(t *testing.T) {
	// Create a test Fulu block (using Electra structure)
	fuluBlock := &apiv1electra.BlockContents{
		Block: &electra.BeaconBlock{
			Slot:          300,
			ProposerIndex: 15,
			ParentRoot:    phase0.Root{20, 21, 22},
			StateRoot:     phase0.Root{23, 24, 25},
			Body: &electra.BeaconBlockBody{
				Graffiti:           [32]byte{26, 27, 28},
				BlobKZGCommitments: []deneb.KZGCommitment{{}, {}, {}},
			},
		},
		Blobs: []deneb.Blob{
			{},
			{},
			{},
		},
		KZGProofs: []deneb.KZGProof{
			{},
			{},
			{},
		},
	}

	versioned := &VersionedBlockContents{
		Version: "fulu",
		Fulu:    fuluBlock,
	}

	result := ConvertVersionedToDeneb(versioned)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Check that the conversion preserved the important fields
	if result.Block.Slot != 300 {
		t.Errorf("expected slot 300, got %d", result.Block.Slot)
	}

	if result.Block.ProposerIndex != 15 {
		t.Errorf("expected proposer index 15, got %d", result.Block.ProposerIndex)
	}

	if result.Block.Body.Graffiti != [32]byte{26, 27, 28} {
		t.Error("graffiti was not preserved")
	}

	if len(result.Blobs) != 3 {
		t.Errorf("expected 3 blobs, got %d", len(result.Blobs))
	}

	if len(result.KZGProofs) != 3 {
		t.Errorf("expected 3 KZG proofs, got %d", len(result.KZGProofs))
	}
}

func TestConvertVersionedToDeneb_ElectraBlock(t *testing.T) {
	// Create a test Electra block
	electraBlock := &apiv1electra.BlockContents{
		Block: &electra.BeaconBlock{
			Slot:          200,
			ProposerIndex: 10,
			ParentRoot:    phase0.Root{10, 11, 12},
			StateRoot:     phase0.Root{13, 14, 15},
			Body: &electra.BeaconBlockBody{
				Graffiti:           [32]byte{16, 17, 18},
				BlobKZGCommitments: []deneb.KZGCommitment{{}, {}},
			},
		},
		Blobs: []deneb.Blob{
			{},
			{},
		},
		KZGProofs: []deneb.KZGProof{
			{},
			{},
		},
	}

	versioned := &VersionedBlockContents{
		Version: "electra",
		Electra: electraBlock,
	}

	result := ConvertVersionedToDeneb(versioned)

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Check that the conversion preserved the important fields
	if result.Block.Slot != 200 {
		t.Errorf("expected slot 200, got %d", result.Block.Slot)
	}

	if result.Block.ProposerIndex != 10 {
		t.Errorf("expected proposer index 10, got %d", result.Block.ProposerIndex)
	}

	if result.Block.Body.Graffiti != [32]byte{16, 17, 18} {
		t.Error("graffiti was not preserved")
	}

	if len(result.Blobs) != 2 {
		t.Errorf("expected 2 blobs, got %d", len(result.Blobs))
	}

	if len(result.KZGProofs) != 2 {
		t.Errorf("expected 2 KZG proofs, got %d", len(result.KZGProofs))
	}
}

func TestConvertVersionedToDeneb_Nil(t *testing.T) {
	result := ConvertVersionedToDeneb(nil)
	if result != nil {
		t.Error("expected nil result for nil input")
	}
}

func TestConvertVersionedToDeneb_UnsupportedVersion(t *testing.T) {
	versioned := &VersionedBlockContents{
		Version: "phase0",
	}

	result := ConvertVersionedToDeneb(versioned)
	if result != nil {
		t.Error("expected nil result for unsupported version")
	}
}

func TestVersionedBlockContents_GetSlot(t *testing.T) {
	tests := []struct {
		name     string
		contents *VersionedBlockContents
		want     phase0.Slot
	}{
		{
			name: "deneb slot",
			contents: &VersionedBlockContents{
				Version: "deneb",
				Deneb: &apiv1deneb.BlockContents{
					Block: &deneb.BeaconBlock{Slot: 100},
				},
			},
			want: 100,
		},
		{
			name: "electra slot",
			contents: &VersionedBlockContents{
				Version: "electra",
				Electra: &apiv1electra.BlockContents{
					Block: &electra.BeaconBlock{Slot: 200},
				},
			},
			want: 200,
		},
		{
			name: "fulu slot",
			contents: &VersionedBlockContents{
				Version: "fulu",
				Fulu: &apiv1electra.BlockContents{
					Block: &electra.BeaconBlock{Slot: 300},
				},
			},
			want: 300,
		},
		{
			name:     "nil contents",
			contents: &VersionedBlockContents{},
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.contents.GetSlot()
			if got != tt.want {
				t.Errorf("GetSlot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionedBlockContents_GetBlobsCount(t *testing.T) {
	tests := []struct {
		name     string
		contents *VersionedBlockContents
		want     int
	}{
		{
			name: "deneb with blobs",
			contents: &VersionedBlockContents{
				Version: "deneb",
				Deneb: &apiv1deneb.BlockContents{
					Blobs: []deneb.Blob{{}, {}, {}},
				},
			},
			want: 3,
		},
		{
			name: "electra with blobs",
			contents: &VersionedBlockContents{
				Version: "electra",
				Electra: &apiv1electra.BlockContents{
					Blobs: []deneb.Blob{{}, {}},
				},
			},
			want: 2,
		},
		{
			name: "fulu with blobs",
			contents: &VersionedBlockContents{
				Version: "fulu",
				Fulu: &apiv1electra.BlockContents{
					Blobs: []deneb.Blob{{}, {}, {}, {}},
				},
			},
			want: 4,
		},
		{
			name:     "no blobs",
			contents: &VersionedBlockContents{},
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.contents.GetBlobsCount()
			if got != tt.want {
				t.Errorf("GetBlobsCount() = %v, want %v", got, tt.want)
			}
		})
	}
}
