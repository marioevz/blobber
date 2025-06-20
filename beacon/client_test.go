package beacon

import (
	"context"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

func TestNewClient(t *testing.T) {
	// This test would require a mock server or actual beacon node
	// With WithAllowDelayedStart(true), the client creation won't fail immediately
	// even with an invalid URL
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// Test that client can be created even with unreachable address
	// (due to WithAllowDelayedStart)
	client, err := NewClient(ctx, "http://localhost:9999")
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	
	// Test that required interfaces are checked
	if client.client == nil {
		t.Fatal("expected non-nil eth2client")
	}
}

func TestBeaconClientAdapter(t *testing.T) {
	// Test BeaconClientAdapter creation
	// ctx := context.Background()
	
	// This would require a mock server
	// For now, test that the adapter can be created with proper config
	config := BeaconClientConfig{
		BeaconAPIURL:          "http://localhost:5052",
		Spec:                  make(map[string]interface{}),
		GenesisTime:           &time.Time{},
		GenesisValidatorsRoot: &phase0.Root{},
	}
	
	oldClient := &BeaconClient{
		Config: config,
	}
	
	// Test that we can access the config
	if oldClient.GetAddress() != "http://localhost:5052" {
		t.Fatalf("unexpected address: %s", oldClient.GetAddress())
	}
}

func TestParseStateId(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		valid   bool
		expected StateId
	}{
		{"head", "head", true, StateId("head")},
		{"genesis", "genesis", true, StateId("genesis")},
		{"finalized", "finalized", true, StateId("finalized")},
		{"justified", "justified", true, StateId("justified")},
		{"slot number", "12345", true, StateId("12345")},
		{"invalid", "invalid-state", false, ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseStateId(tt.input)
			if tt.valid {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Fatalf("expected %v, got %v", tt.expected, result)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			}
		})
	}
}

func TestParseValidatorId(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
		isIndex bool
	}{
		{"index", "12345", true, true},
		{"hex pubkey", "0x" + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", true, false},
		{"invalid", "not-a-validator-id", false, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseValidatorId(tt.input)
			if tt.valid {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.isIndex {
					if _, ok := result.(ValidatorIndexId); !ok {
						t.Fatal("expected ValidatorIndexId")
					}
				} else {
					if _, ok := result.(ValidatorPubkeyId); !ok {
						t.Fatal("expected ValidatorPubkeyId")
					}
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			}
		})
	}
}

func TestVersionedSignedBeaconBlock(t *testing.T) {
	// Test Root() method
	block := &VersionedSignedBeaconBlock{
		Version: BlockVersionPhase0,
		Phase0: &phase0.SignedBeaconBlock{
			Message: &phase0.BeaconBlock{
				Slot:      phase0.Slot(100),
				StateRoot: phase0.Root{1, 2, 3, 4},
			},
		},
	}
	
	root := block.Root()
	if root != (phase0.Root{1, 2, 3, 4}) {
		t.Fatalf("unexpected root: %v", root)
	}
	
	slot := block.Slot()
	if slot != phase0.Slot(100) {
		t.Fatalf("unexpected slot: %v", slot)
	}
	
	// Test with nil block
	emptyBlock := &VersionedSignedBeaconBlock{}
	if emptyBlock.Root() != (phase0.Root{}) {
		t.Fatal("expected zero root for empty block")
	}
	if emptyBlock.Slot() != phase0.Slot(0) {
		t.Fatal("expected zero slot for empty block")
	}
}