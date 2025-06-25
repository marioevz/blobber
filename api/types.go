package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// HexBytes is a byte array that marshals/unmarshals as a hex string in JSON
type HexBytes []byte

// UnmarshalJSON implements json.Unmarshaler
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	
	// Remove 0x prefix if present
	str = strings.TrimPrefix(str, "0x")
	
	// Decode hex string
	decoded, err := hex.DecodeString(str)
	if err != nil {
		return fmt.Errorf("invalid hex string: %w", err)
	}
	
	*h = decoded
	return nil
}

// MarshalJSON implements json.Marshaler
func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal("0x" + hex.EncodeToString(h))
}

// Bytes returns the byte slice
func (h HexBytes) Bytes() []byte {
	return []byte(h)
}

// ToArray48 converts HexBytes to a [48]byte array (for pubkeys)
func (h HexBytes) ToArray48() ([48]byte, error) {
	var arr [48]byte
	if len(h) != 48 {
		return arr, fmt.Errorf("expected 48 bytes, got %d", len(h))
	}
	copy(arr[:], h)
	return arr, nil
}

// ToArray32 converts HexBytes to a [32]byte array (for withdrawal credentials)
func (h HexBytes) ToArray32() ([32]byte, error) {
	var arr [32]byte
	if len(h) != 32 {
		return arr, fmt.Errorf("expected 32 bytes, got %d", len(h))
	}
	copy(arr[:], h)
	return arr, nil
}

// StateId represents a state identifier
type StateId string

const (
	// StateHead represents the head state
	StateHead StateId = "head"
	// StateGenesis represents the genesis state
	StateGenesis StateId = "genesis"
	// StateFinalized represents the finalized state
	StateFinalized StateId = "finalized"
	// StateJustified represents the justified state
	StateJustified StateId = "justified"
)

// BlockId represents a block identifier
type BlockId string

const (
	// BlockHead represents the head block
	BlockHead BlockId = "head"
	// BlockGenesis represents the genesis block
	BlockGenesis BlockId = "genesis"
	// BlockFinalized represents the finalized block
	BlockFinalized BlockId = "finalized"
	// BlockJustified represents the justified block
	BlockJustified BlockId = "justified"
)

// ValidatorId represents a validator identifier (can be index or pubkey)
type ValidatorId string

// ValidatorStatus represents validator status
type ValidatorStatus string

const (
	// ValidatorStatusPendingInitialized represents pending initialized status
	ValidatorStatusPendingInitialized ValidatorStatus = "pending_initialized"
	// ValidatorStatusPendingQueued represents pending queued status
	ValidatorStatusPendingQueued ValidatorStatus = "pending_queued"
	// ValidatorStatusActiveOngoing represents active ongoing status
	ValidatorStatusActiveOngoing ValidatorStatus = "active_ongoing"
	// ValidatorStatusActiveExiting represents active exiting status
	ValidatorStatusActiveExiting ValidatorStatus = "active_exiting"
	// ValidatorStatusActiveSlashed represents active slashed status
	ValidatorStatusActiveSlashed ValidatorStatus = "active_slashed"
	// ValidatorStatusExitedUnslashed represents exited unslashed status
	ValidatorStatusExitedUnslashed ValidatorStatus = "exited_unslashed"
	// ValidatorStatusExitedSlashed represents exited slashed status
	ValidatorStatusExitedSlashed ValidatorStatus = "exited_slashed"
	// ValidatorStatusWithdrawalPossible represents withdrawal possible status
	ValidatorStatusWithdrawalPossible ValidatorStatus = "withdrawal_possible"
	// ValidatorStatusWithdrawalDone represents withdrawal done status
	ValidatorStatusWithdrawalDone ValidatorStatus = "withdrawal_done"
	// ValidatorStatusActive represents any active status
	ValidatorStatusActive ValidatorStatus = "active"
	// ValidatorStatusPending represents any pending status
	ValidatorStatusPending ValidatorStatus = "pending"
	// ValidatorStatusExited represents any exited status
	ValidatorStatusExited ValidatorStatus = "exited"
	// ValidatorStatusWithdrawal represents any withdrawal status
	ValidatorStatusWithdrawal ValidatorStatus = "withdrawal"
)

// ValidatorResponse represents a validator response from the API
type ValidatorResponse struct {
	Index     string    `json:"index"`     // Changed to string as beacon nodes return this as string
	Balance   string    `json:"balance"`   // Changed to string for consistency
	Status    string    `json:"status"`
	Validator Validator `json:"validator"`
}

// Validator represents validator data
type Validator struct {
	Pubkey                     HexBytes `json:"pubkey"`
	WithdrawalCredentials      HexBytes `json:"withdrawal_credentials"`
	EffectiveBalance           string   `json:"effective_balance"`
	Slashed                    bool     `json:"slashed"`
	ActivationEligibilityEpoch string   `json:"activation_eligibility_epoch"`
	ActivationEpoch            string   `json:"activation_epoch"`
	ExitEpoch                  string   `json:"exit_epoch"`
	WithdrawableEpoch          string   `json:"withdrawable_epoch"`
}