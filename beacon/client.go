package beacon

import (
	"context"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/rs/zerolog"
)

// Client wraps go-eth2-client to provide beacon node functionality
type Client struct {
	address string
	client  eth2client.Service
}

// NewClient creates a new beacon client using go-eth2-client
func NewClient(ctx context.Context, address string) (*Client, error) {
	client, err := http.New(ctx,
		http.WithAddress(address),
		http.WithLogLevel(zerolog.WarnLevel),
		http.WithTimeout(30*time.Second),
		http.WithAllowDelayedStart(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create eth2 client: %w", err)
	}

	// Check if all required interfaces are supported
	if _, ok := client.(eth2client.NodeSyncingProvider); !ok {
		return nil, fmt.Errorf("client does not support node syncing")
	}
	if _, ok := client.(eth2client.SignedBeaconBlockProvider); !ok {
		return nil, fmt.Errorf("client does not support beacon blocks")
	}
	if _, ok := client.(eth2client.ValidatorsProvider); !ok {
		return nil, fmt.Errorf("client does not support validators")
	}

	return &Client{
		address: address,
		client:  client,
	}, nil
}

// GetAddress returns the beacon node address
func (c *Client) GetAddress() string {
	return c.address
}

// GetClient returns the underlying eth2client
func (c *Client) GetClient() eth2client.Service {
	return c.client
}

// ValidatorsByPubKey fetches validators by their public keys
func (c *Client) ValidatorsByPubKey(ctx context.Context, stateID string, pubKeys []phase0.BLSPubKey) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	validatorsProvider, ok := c.client.(eth2client.ValidatorsProvider)
	if !ok {
		return nil, fmt.Errorf("client does not support validators")
	}

	opts := &eth2api.ValidatorsOpts{
		State:   stateID,
		PubKeys: pubKeys,
	}

	response, err := validatorsProvider.Validators(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get validators: %w", err)
	}

	return response.Data, nil
}

// ValidatorsByIndex fetches validators by their indices
func (c *Client) ValidatorsByIndex(ctx context.Context, stateID string, indices []phase0.ValidatorIndex) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	validatorsProvider, ok := c.client.(eth2client.ValidatorsProvider)
	if !ok {
		return nil, fmt.Errorf("client does not support validators")
	}

	opts := &eth2api.ValidatorsOpts{
		State:   stateID,
		Indices: indices,
	}

	response, err := validatorsProvider.Validators(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get validators: %w", err)
	}

	return response.Data, nil
}

// AllValidators fetches all validators
func (c *Client) AllValidators(ctx context.Context, stateID string) (map[phase0.ValidatorIndex]*apiv1.Validator, error) {
	validatorsProvider, ok := c.client.(eth2client.ValidatorsProvider)
	if !ok {
		return nil, fmt.Errorf("client does not support validators")
	}

	opts := &eth2api.ValidatorsOpts{
		State: stateID,
	}

	response, err := validatorsProvider.Validators(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get validators: %w", err)
	}

	return response.Data, nil
}

// BeaconBlock fetches a beacon block
func (c *Client) BeaconBlock(ctx context.Context, blockID string) (*phase0.SignedBeaconBlock, error) {
	beaconBlockProvider, ok := c.client.(eth2client.SignedBeaconBlockProvider)
	if !ok {
		return nil, fmt.Errorf("client does not support beacon blocks")
	}

	opts := &eth2api.SignedBeaconBlockOpts{
		Block: blockID,
	}

	response, err := beaconBlockProvider.SignedBeaconBlock(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get beacon block: %w", err)
	}

	if response == nil || response.Data == nil {
		return nil, fmt.Errorf("no block data returned")
	}

	// go-eth2-client returns versioned data, we need to handle different versions
	switch response.Data.Version {
	case spec.DataVersionPhase0:
		if response.Data.Phase0 != nil {
			return response.Data.Phase0, nil
		}
	case spec.DataVersionAltair:
		if response.Data.Altair != nil {
			// Convert Altair block to Phase0 format if needed
			// This is a simplification - in practice you might want to handle this differently
			return nil, fmt.Errorf("altair blocks not yet supported")
		}
	case spec.DataVersionBellatrix:
		if response.Data.Bellatrix != nil {
			return nil, fmt.Errorf("bellatrix blocks not yet supported")
		}
	case spec.DataVersionCapella:
		if response.Data.Capella != nil {
			return nil, fmt.Errorf("capella blocks not yet supported")
		}
	case spec.DataVersionDeneb:
		if response.Data.Deneb != nil {
			return nil, fmt.Errorf("deneb blocks not yet supported")
		}
	}

	return nil, fmt.Errorf("unknown block version")
}

// NodeSyncing checks if the node is syncing
func (c *Client) NodeSyncing(ctx context.Context) (bool, error) {
	nodeSyncingProvider, ok := c.client.(eth2client.NodeSyncingProvider)
	if !ok {
		return false, fmt.Errorf("client does not support node syncing")
	}

	response, err := nodeSyncingProvider.NodeSyncing(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to get node syncing status: %w", err)
	}

	return response.Data.IsSyncing, nil
}