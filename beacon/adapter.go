package beacon

import (
	"context"
	"fmt"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	eth2api "github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/sirupsen/logrus"
)

// BeaconClientAdapter adapts our go-eth2-client based client to the existing beacon_client interface
type BeaconClientAdapter struct {
	*BeaconClient
	client *Client
	address string
}

// NewBeaconClientAdapter creates a new adapter
func NewBeaconClientAdapter(ctx context.Context, address string) (*BeaconClientAdapter, error) {
	// Create our go-eth2-client based client
	client, err := NewClient(ctx, address)
	if err != nil {
		return nil, err
	}

	// Get the eth2 client to fetch spec and genesis info
	eth2Client := client.GetClient()

	// Fetch spec
	var spec map[string]interface{}
	if specProvider, ok := eth2Client.(eth2client.SpecProvider); ok {
		response, err := specProvider.Spec(ctx, &eth2api.SpecOpts{})
		if err == nil && response != nil {
			spec = response.Data
		}
	}

	// Fetch genesis information
	var genesisTime time.Time
	var genesisValidatorsRoot phase0.Root
	if genesisProvider, ok := eth2Client.(eth2client.GenesisProvider); ok {
		response, err := genesisProvider.Genesis(ctx, &eth2api.GenesisOpts{})
		if err == nil && response != nil {
			genesisTime = response.Data.GenesisTime
			genesisValidatorsRoot = response.Data.GenesisValidatorsRoot
		}
	}

	// Create a minimal BeaconClient to satisfy the interface
	oldClient := &BeaconClient{
		Config: BeaconClientConfig{
			BeaconAPIURL:          address,
			Spec:                  spec,
			GenesisTime:           &genesisTime,
			GenesisValidatorsRoot: &genesisValidatorsRoot,
		},
	}

	return &BeaconClientAdapter{
		BeaconClient: oldClient,
		client:       client,
		address:      address,
	}, nil
}

// GetAddress returns the beacon node address
func (a *BeaconClientAdapter) GetAddress() string {
	return a.client.GetAddress()
}

// StateValidators queries validators - this replaces the eth2api based implementation
func (a *BeaconClientAdapter) StateValidators(
	ctx context.Context,
	stateId StateId,
	validatorIds []ValidatorId,
	statusFilter []ValidatorStatus,
) ([]ValidatorResponse, error) {
	// Convert StateId to string
	stateIDStr := string(stateId)

	// If no specific validators requested, get all
	if len(validatorIds) == 0 {
		validators, err := a.client.AllValidators(ctx, stateIDStr)
		if err != nil {
			return nil, err
		}
		return a.convertValidatorsToResponses(validators, statusFilter), nil
	}

	// Separate indices and pubkeys
	var indices []phase0.ValidatorIndex
	var pubkeys []phase0.BLSPubKey

	for _, id := range validatorIds {
		switch v := id.(type) {
		case ValidatorIndexId:
			indices = append(indices, phase0.ValidatorIndex(v))
		case ValidatorPubkeyId:
			var pubkey phase0.BLSPubKey
			copy(pubkey[:], v[:])
			pubkeys = append(pubkeys, pubkey)
		default:
			logrus.Warnf("Unknown validator ID type: %T", v)
		}
	}

	// Fetch validators
	result := make(map[phase0.ValidatorIndex]*apiv1.Validator)

	if len(indices) > 0 {
		validatorsByIndex, err := a.client.ValidatorsByIndex(ctx, stateIDStr, indices)
		if err != nil {
			return nil, err
		}
		for k, v := range validatorsByIndex {
			result[k] = v
		}
	}

	if len(pubkeys) > 0 {
		validatorsByPubkey, err := a.client.ValidatorsByPubKey(ctx, stateIDStr, pubkeys)
		if err != nil {
			return nil, err
		}
		for k, v := range validatorsByPubkey {
			result[k] = v
		}
	}

	return a.convertValidatorsToResponses(result, statusFilter), nil
}

// BlockV2 gets block data and returns it in our format
func (a *BeaconClientAdapter) BlockV2(ctx context.Context, blockId BlockId) (*VersionedSignedBeaconBlock, error) {
	// Convert blockId to string
	blockIDStr := string(blockId)
	
	// Get the eth2client
	eth2Client := a.client.GetClient()
	
	// Use SignedBeaconBlock method which returns versioned data
	signedBeaconBlockProvider, ok := eth2Client.(eth2client.SignedBeaconBlockProvider)
	if !ok {
		return nil, fmt.Errorf("client does not support signed beacon blocks")
	}
	
	opts := &eth2api.SignedBeaconBlockOpts{
		Block: blockIDStr,
	}
	
	response, err := signedBeaconBlockProvider.SignedBeaconBlock(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed beacon block: %w", err)
	}
	
	if response == nil || response.Data == nil {
		return nil, fmt.Errorf("no block data returned")
	}
	
	// Convert go-eth2-client response to our format
	result := &VersionedSignedBeaconBlock{}
	
	switch response.Data.Version {
	case spec.DataVersionPhase0:
		if response.Data.Phase0 != nil {
			result.Version = BlockVersionPhase0
			result.Phase0 = response.Data.Phase0
		}
	case spec.DataVersionAltair:
		if response.Data.Altair != nil {
			result.Version = BlockVersionAltair
			// Would need to convert Altair block to our format
			return nil, fmt.Errorf("altair blocks not yet supported in adapter")
		}
	case spec.DataVersionBellatrix:
		if response.Data.Bellatrix != nil {
			result.Version = BlockVersionBellatrix
			// Would need to convert Bellatrix block to our format
			return nil, fmt.Errorf("bellatrix blocks not yet supported in adapter")
		}
	case spec.DataVersionCapella:
		if response.Data.Capella != nil {
			result.Version = BlockVersionCapella
			// Would need to convert Capella block to our format
			return nil, fmt.Errorf("capella blocks not yet supported in adapter")
		}
	case spec.DataVersionDeneb:
		if response.Data.Deneb != nil {
			result.Version = BlockVersionDeneb
			result.Deneb = response.Data.Deneb
		}
	case spec.DataVersionElectra:
		if response.Data.Electra != nil {
			result.Version = BlockVersionElectra
			result.Electra = response.Data.Electra
		}
	default:
		return nil, fmt.Errorf("unknown block version: %v", response.Data.Version)
	}
	
	return result, nil
}

// convertValidatorsToResponses converts go-eth2-client validators to our format
func (a *BeaconClientAdapter) convertValidatorsToResponses(
	validators map[phase0.ValidatorIndex]*apiv1.Validator,
	statusFilter []ValidatorStatus,
) []ValidatorResponse {
	var responses []ValidatorResponse

	for index, validator := range validators {
		// Check if we should include this validator based on status filter
		if len(statusFilter) > 0 && !a.matchesStatusFilter(validator, statusFilter) {
			continue
		}

		responses = append(responses, ValidatorResponse{
			Index:   index,
			Balance: validator.Balance,
			Status:  ValidatorStatus(validator.Status.String()),
			Validator: Validator{
				PublicKey:                  validator.Validator.PublicKey,
				WithdrawalCredentials:      phase0.Hash32(validator.Validator.WithdrawalCredentials),
				EffectiveBalance:           validator.Validator.EffectiveBalance,
				Slashed:                    validator.Validator.Slashed,
				ActivationEligibilityEpoch: validator.Validator.ActivationEligibilityEpoch,
				ActivationEpoch:            validator.Validator.ActivationEpoch,
				ExitEpoch:                  validator.Validator.ExitEpoch,
				WithdrawableEpoch:          validator.Validator.WithdrawableEpoch,
			},
		})
	}

	return responses
}

// getValidatorStatus determines the status of a validator
func (a *BeaconClientAdapter) getValidatorStatus(validator *apiv1.Validator) ValidatorStatus {
	// The apiv1.Validator already includes a status field
	return ValidatorStatus(validator.Status.String())
}

// matchesStatusFilter checks if a validator matches the status filter
func (a *BeaconClientAdapter) matchesStatusFilter(validator *apiv1.Validator, statusFilter []ValidatorStatus) bool {
	currentStatus := a.getValidatorStatus(validator)
	for _, status := range statusFilter {
		if status == currentStatus {
			return true
		}
		// Handle grouped statuses
		switch status {
		case ValidatorStatusActive:
			if currentStatus == ValidatorStatusActiveOngoing ||
				currentStatus == ValidatorStatusActiveExiting ||
				currentStatus == ValidatorStatusActiveSlashed {
				return true
			}
		case ValidatorStatusPending:
			if currentStatus == ValidatorStatusPendingInitialized ||
				currentStatus == ValidatorStatusPendingQueued {
				return true
			}
		case ValidatorStatusExited:
			if currentStatus == ValidatorStatusExitedUnslashed ||
				currentStatus == ValidatorStatusExitedSlashed {
				return true
			}
		case ValidatorStatusWithdrawal:
			if currentStatus == ValidatorStatusWithdrawalPossible ||
				currentStatus == ValidatorStatusWithdrawalDone {
				return true
			}
		}
	}
	return false
}

// ENR returns the node's ENR (Ethereum Node Record)
func (a *BeaconClientAdapter) ENR(ctx context.Context) (string, error) {
	// Use the embedded BeaconClient's ENR method if available
	if a.BeaconClient != nil {
		return a.BeaconClient.ENR(ctx)
	}
	return "", fmt.Errorf("ENR not available")
}