package errors

import (
	"errors"
	"fmt"
)

// Common error types for the blobber application
var (
	// Configuration errors
	ErrNoSpecConfigured        = errors.New("no spec configured")
	ErrNoProxiesPortConfigured = errors.New("no proxies port start configured")
	ErrNoGenesisValidatorsRoot = errors.New("no genesis validators root configured")
	ErrNoExternalIPConfigured  = errors.New("no external ip configured")
	ErrInvalidProposalAction   = errors.New("invalid proposal action configuration")
	ErrProposalActionParse     = errors.New("failed to parse proposal action")

	// Beacon client errors
	ErrBeaconClientInit       = errors.New("failed to initialize beacon client")
	ErrBeaconClientConnection = errors.New("failed to connect to beacon client")
	ErrBlockFetch             = errors.New("failed to fetch block")
	ErrValidatorFetch         = errors.New("failed to fetch validators")
	ErrForkVersionNotFound    = errors.New("fork version not found")
	ErrDomainTypeNotFound     = errors.New("domain type not found")

	// P2P errors
	ErrP2PConnection      = errors.New("p2p connection failed")
	ErrP2PPeerNotFound    = errors.New("p2p peer not found")
	ErrP2PBroadcastFailed = errors.New("p2p broadcast failed")

	// Validation errors
	ErrValidatorKeyNotFound = errors.New("validator key not found")
	ErrInvalidValidatorKey  = errors.New("invalid validator key")
	ErrValidatorKeyParse    = errors.New("failed to parse validator key")

	// Block processing errors
	ErrBlockConversionFailed = errors.New("failed to convert block format")
	ErrBlockRootCalculation  = errors.New("failed to calculate block root")
	ErrInvalidBlockVersion   = errors.New("invalid block version")
)

// ConfigError represents a configuration-related error
type ConfigError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ConfigError) Error() string {
	if e.Value != nil {
		return fmt.Sprintf("config error for field %s (value: %v): %s", e.Field, e.Value, e.Message)
	}
	return fmt.Sprintf("config error for field %s: %s", e.Field, e.Message)
}

// NewConfigError creates a new configuration error
func NewConfigError(field string, value interface{}, message string) error {
	return &ConfigError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}

// BeaconClientError represents a beacon client operation error
type BeaconClientError struct {
	Operation string
	Endpoint  string
	Err       error
}

func (e *BeaconClientError) Error() string {
	return fmt.Sprintf("beacon client error during %s on %s: %v", e.Operation, e.Endpoint, e.Err)
}

func (e *BeaconClientError) Unwrap() error {
	return e.Err
}

// NewBeaconClientError creates a new beacon client error
func NewBeaconClientError(operation, endpoint string, err error) error {
	return &BeaconClientError{
		Operation: operation,
		Endpoint:  endpoint,
		Err:       err,
	}
}

// P2PError represents a P2P operation error
type P2PError struct {
	Operation string
	PeerID    string
	Err       error
}

func (e *P2PError) Error() string {
	if e.PeerID != "" {
		return fmt.Sprintf("p2p error during %s with peer %s: %v", e.Operation, e.PeerID, e.Err)
	}
	return fmt.Sprintf("p2p error during %s: %v", e.Operation, e.Err)
}

func (e *P2PError) Unwrap() error {
	return e.Err
}

// NewP2PError creates a new P2P error
func NewP2PError(operation, peerID string, err error) error {
	return &P2PError{
		Operation: operation,
		PeerID:    peerID,
		Err:       err,
	}
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for %s: %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(field string, value interface{}, message string) error {
	return &ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	}
}
