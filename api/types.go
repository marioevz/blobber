package api

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
	Pubkey                     [48]byte `json:"pubkey"`
	WithdrawalCredentials      [32]byte `json:"withdrawal_credentials"`
	EffectiveBalance           uint64   `json:"effective_balance"`
	Slashed                    bool     `json:"slashed"`
	ActivationEligibilityEpoch uint64   `json:"activation_eligibility_epoch"`
	ActivationEpoch            uint64   `json:"activation_epoch"`
	ExitEpoch                  uint64   `json:"exit_epoch"`
	WithdrawableEpoch          uint64   `json:"withdrawable_epoch"`
}