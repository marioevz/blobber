package beacon

import (
	"context"
)

// BeaconClientInterface defines the methods we need from a beacon client
type BeaconClientInterface interface {
	ENR(ctx context.Context) (string, error)
	GetAddress() string
	StateValidators(ctx context.Context, stateId StateId, validatorIds []ValidatorId, statusFilter []ValidatorStatus) ([]ValidatorResponse, error)
	BlockV2(ctx context.Context, blockId BlockId) (*VersionedSignedBeaconBlock, error)
}
