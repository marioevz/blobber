package blobber

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/marioevz/blobber/config"
	"github.com/marioevz/blobber/keys"
)

func TestNewBlobber(t *testing.T) {
	ctx := context.Background()
	
	// Test creating a blobber with minimal config
	b, err := NewBlobber(ctx,
		config.WithHost("localhost"),
		config.WithExternalIP(net.ParseIP("127.0.0.1")),
		config.WithID(1),
		config.WithSpec(map[string]interface{}{
			"SLOTS_PER_EPOCH": uint64(32),
		}),
		config.WithBeaconGenesisTime(uint64(time.Now().Unix())),
		config.WithGenesisValidatorsRoot(phase0.Root{1, 2, 3}), // Non-zero root
	)
	
	if err != nil {
		t.Fatalf("unexpected error creating blobber: %v", err)
	}
	
	// Clean up
	b.Close()
	
	// Verify basic properties
	if b.Config == nil {
		t.Fatal("blobber config is nil")
	}
	
	if b.Config.Host != "localhost" {
		t.Errorf("expected host localhost, got %s", b.Config.Host)
	}
	
	if b.Config.ID != 1 {
		t.Errorf("expected ID 1, got %d", b.Config.ID)
	}
}

func TestBlobberWithValidatorKeys(t *testing.T) {
	ctx := context.Background()
	
	// Create test validator keys
	validatorKeys := map[phase0.ValidatorIndex]*keys.ValidatorKey{
		100: {},
		200: {},
	}
	
	b, err := NewBlobber(ctx,
		config.WithHost("localhost"),
		config.WithExternalIP(net.ParseIP("127.0.0.1")),
		config.WithID(1),
		config.WithSpec(map[string]interface{}{}),
		config.WithBeaconGenesisTime(uint64(time.Now().Unix())),
		config.WithGenesisValidatorsRoot(phase0.Root{1, 2, 3}), // Non-zero root
		config.WithValidatorKeys(validatorKeys),
	)
	
	if err != nil {
		t.Fatalf("unexpected error creating blobber: %v", err)
	}
	defer b.Close()
	
	// Verify validator keys were set
	if len(b.Config.ValidatorKeys) != 2 {
		t.Errorf("expected 2 validator keys, got %d", len(b.Config.ValidatorKeys))
	}
}

func TestBlobberClose(t *testing.T) {
	ctx := context.Background()
	
	b, err := NewBlobber(ctx,
		config.WithHost("localhost"),
		config.WithExternalIP(net.ParseIP("127.0.0.1")),
		config.WithID(1),
		config.WithSpec(map[string]interface{}{}),
		config.WithBeaconGenesisTime(uint64(time.Now().Unix())),
		config.WithGenesisValidatorsRoot(phase0.Root{1, 2, 3}), // Non-zero root
	)
	
	if err != nil {
		t.Fatalf("unexpected error creating blobber: %v", err)
	}
	
	// Close should not panic
	b.Close()
	
	// Multiple closes should not panic
	b.Close()
}

func TestGetProducedBlockRoots(t *testing.T) {
	ctx := context.Background()
	
	b, err := NewBlobber(ctx,
		config.WithHost("localhost"),
		config.WithExternalIP(net.ParseIP("127.0.0.1")),
		config.WithID(1),
		config.WithSpec(map[string]interface{}{}),
		config.WithBeaconGenesisTime(uint64(time.Now().Unix())),
		config.WithGenesisValidatorsRoot(phase0.Root{1, 2, 3}), // Non-zero root
	)
	
	if err != nil {
		t.Fatalf("unexpected error creating blobber: %v", err)
	}
	defer b.Close()
	
	// Initially should be empty
	roots := b.GetProducedBlockRoots()
	if len(roots) != 0 {
		t.Errorf("expected 0 block roots, got %d", len(roots))
	}
	
	// Add some test data
	testRoot := [32]byte{1, 2, 3, 4}
	b.builtBlocksMap.Lock()
	b.builtBlocksMap.BlockRoots[phase0.Slot(100)] = testRoot
	b.builtBlocksMap.Unlock()
	
	// Should now have one root
	roots = b.GetProducedBlockRoots()
	if len(roots) != 1 {
		t.Errorf("expected 1 block root, got %d", len(roots))
	}
	
	if roots[phase0.Slot(100)] != testRoot {
		t.Errorf("unexpected block root for slot 100")
	}
}

func TestCalcBeaconBlockDomain(t *testing.T) {
	ctx := context.Background()
	
	b, err := NewBlobber(ctx,
		config.WithHost("localhost"),
		config.WithExternalIP(net.ParseIP("127.0.0.1")),
		config.WithID(1),
		config.WithSpec(map[string]interface{}{
			"DOMAIN_BEACON_PROPOSER": phase0.DomainType{0x00, 0x00, 0x00, 0x00},
			"GENESIS_FORK_VERSION": phase0.Version{0x00, 0x00, 0x00, 0x00},
		}),
		config.WithBeaconGenesisTime(uint64(time.Now().Unix())),
		config.WithGenesisValidatorsRoot(phase0.Root{1, 2, 3}), // Non-zero root
	)
	
	if err != nil {
		t.Fatalf("unexpected error creating blobber: %v", err)
	}
	defer b.Close()
	
	// Test domain calculation
	domain := b.calcBeaconBlockDomain(phase0.Slot(100))
	
	// Should return a non-empty domain
	if domain == (phase0.Domain{}) {
		t.Error("expected non-empty domain, got empty")
	}
}