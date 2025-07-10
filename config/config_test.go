package config

import (
	"net"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/marioevz/blobber/keys"
	"github.com/marioevz/blobber/p2p"
)

func TestConfigOptions(t *testing.T) {
	cfg := &Config{
		TestP2P: &p2p.TestP2P{
			ChainStatus: p2p.NewStatus(),
		},
	}

	// Test WithHost
	err := cfg.Apply(WithHost("192.168.1.1"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Host != "192.168.1.1" {
		t.Errorf("expected host 192.168.1.1, got %s", cfg.Host)
	}

	// Test WithExternalIP
	ip := net.ParseIP("10.0.0.1")
	err = cfg.Apply(WithExternalIP(ip))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ExternalIP.Equal(ip) {
		t.Errorf("expected external IP %v, got %v", ip, cfg.ExternalIP)
	}

	// Test WithID
	err = cfg.Apply(WithID(42))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ID != 42 {
		t.Errorf("expected ID 42, got %d", cfg.ID)
	}

	// Test WithSpec
	spec := map[string]interface{}{
		"SLOTS_PER_EPOCH": uint64(32),
	}
	err = cfg.Apply(WithSpec(spec))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Spec["SLOTS_PER_EPOCH"] != uint64(32) {
		t.Errorf("expected SLOTS_PER_EPOCH 32, got %v", cfg.Spec["SLOTS_PER_EPOCH"])
	}

	// Test WithBeaconGenesisTime
	err = cfg.Apply(WithBeaconGenesisTime(1606824023))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BeaconGenesisTime != 1606824023 {
		t.Errorf("expected genesis time 1606824023, got %d", cfg.BeaconGenesisTime)
	}

	// Test WithGenesisValidatorsRoot
	root := phase0.Root{1, 2, 3, 4}
	err = cfg.Apply(WithGenesisValidatorsRoot(root))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GenesisValidatorsRoot != root {
		t.Errorf("expected genesis validators root %v, got %v", root, cfg.GenesisValidatorsRoot)
	}

	// Test WithBeaconPortStart
	err = cfg.Apply(WithBeaconPortStart(9000))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BeaconPortStart != 9000 {
		t.Errorf("expected beacon port start 9000, got %d", cfg.BeaconPortStart)
	}

	// Test WithProxiesPortStart
	err = cfg.Apply(WithProxiesPortStart(20000))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProxiesPortStart != 20000 {
		t.Errorf("expected proxies port start 20000, got %d", cfg.ProxiesPortStart)
	}

	// Test WithProposalActionFrequency - requires a ProposalAction first
	// This will fail without a ProposalAction
	err = cfg.Apply(WithProposalActionFrequency(5))
	if err == nil {
		t.Error("expected error when setting frequency without proposal action")
	}

	// Test WithMaxDevP2PSessionReuses
	err = cfg.Apply(WithMaxDevP2PSessionReuses(10))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MaxDevP2PSessionReuses != 10 {
		t.Errorf("expected max dev p2p session reuses 10, got %d", cfg.MaxDevP2PSessionReuses)
	}

	// Test WithLogLevel
	err = cfg.Apply(WithLogLevel("debug"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Note: LogLevel is not stored in the config, it's applied to logrus

	// Test WithValidatorLoadTimeoutSeconds
	err = cfg.Apply(WithValidatorLoadTimeoutSeconds(30))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ValidatorLoadTimeoutSeconds != 30 {
		t.Errorf("expected validator load timeout 30, got %d", cfg.ValidatorLoadTimeoutSeconds)
	}
}

func TestConfigWithProposalAction(t *testing.T) {
	// Skip this test as it requires creating a mock ProposalAction
	t.Skip("Skipping test that requires ProposalAction mock")
}

func TestConfigWithValidatorKeys(t *testing.T) {
	cfg := &Config{}

	// Create test validator keys
	key1 := &keys.ValidatorKey{}
	key2 := &keys.ValidatorKey{}

	validatorKeys := map[phase0.ValidatorIndex]*keys.ValidatorKey{
		100: key1,
		200: key2,
	}

	err := cfg.Apply(WithValidatorKeys(validatorKeys))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.ValidatorKeys) != 2 {
		t.Errorf("expected 2 validator keys, got %d", len(cfg.ValidatorKeys))
	}

	if cfg.ValidatorKeys[100] != key1 {
		t.Error("validator key 100 mismatch")
	}

	if cfg.ValidatorKeys[200] != key2 {
		t.Error("validator key 200 mismatch")
	}
}

func TestConfigWithValidatorKeysList(t *testing.T) {
	cfg := &Config{}

	// Create test validator keys list
	keys := []*keys.ValidatorKey{
		{},
		{},
		{},
	}

	err := cfg.Apply(WithValidatorKeysList(keys))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.ValidatorKeysList) != 3 {
		t.Errorf("expected 3 validator keys in list, got %d", len(cfg.ValidatorKeysList))
	}
}

func TestConfigApplyMultipleOptions(t *testing.T) {
	cfg := &Config{
		TestP2P: &p2p.TestP2P{
			ChainStatus: p2p.NewStatus(),
		},
	}

	// Apply multiple options at once
	err := cfg.Apply(
		WithHost("localhost"),
		WithID(123),
		WithBeaconPortStart(9500),
		WithProxiesPortStart(21000),
	)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify all options were applied
	if cfg.Host != "localhost" {
		t.Errorf("expected host localhost, got %s", cfg.Host)
	}
	if cfg.ID != 123 {
		t.Errorf("expected ID 123, got %d", cfg.ID)
	}
	if cfg.BeaconPortStart != 9500 {
		t.Errorf("expected beacon port start 9500, got %d", cfg.BeaconPortStart)
	}
	if cfg.ProxiesPortStart != 21000 {
		t.Errorf("expected proxies port start 21000, got %d", cfg.ProxiesPortStart)
	}
}
