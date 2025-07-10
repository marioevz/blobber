package beacon

import (
	"context"
	"fmt"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// BeaconClientConfig holds configuration for beacon client
type BeaconClientConfig struct {
	BeaconAPIURL          string
	Spec                  map[string]interface{}
	GenesisTime           *time.Time
	GenesisValidatorsRoot *phase0.Root
}

// BeaconClient is a minimal implementation to replace marioevz/eth-clients
type BeaconClient struct {
	Config BeaconClientConfig
	Logger interface {
		Logf(msg string, args ...interface{})
	}
}

// Init initializes the beacon client
func (b *BeaconClient) Init(ctx context.Context) error {
	// This is a placeholder - the real initialization happens in the adapter
	return nil
}

// GetAddress returns the beacon API address
func (b *BeaconClient) GetAddress() string {
	return b.Config.BeaconAPIURL
}

// ENR returns the node's ENR
func (b *BeaconClient) ENR(ctx context.Context) (string, error) {
	// Legacy client doesn't have ENR method - this is just a placeholder
	// The actual ENR retrieval is handled by the adapter which wraps this client
	return "", fmt.Errorf("ENR retrieval not implemented for legacy client")
}
