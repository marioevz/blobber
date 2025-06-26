package beacon

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// StateId represents a state identifier (head, genesis, finalized, justified, or a slot)
type StateId string

// ParseStateId parses a state ID string
func ParseStateId(s string) (StateId, error) {
	// Valid state IDs are: head, genesis, finalized, justified, or a slot number
	switch s {
	case "head", "genesis", "finalized", "justified":
		return StateId(s), nil
	default:
		// Try to parse as slot number
		if _, err := strconv.ParseUint(s, 10, 64); err == nil {
			return StateId(s), nil
		}
		return "", fmt.Errorf("invalid state ID: %s", s)
	}
}

// BlockId represents a block identifier
type BlockId string

const (
	BlockHead      BlockId = "head"
	BlockGenesis   BlockId = "genesis"
	BlockFinalized BlockId = "finalized"
)

// ValidatorId represents a validator identifier
type ValidatorId interface {
	String() string
}

// ValidatorIndexId represents a validator by index
type ValidatorIndexId phase0.ValidatorIndex

func (v ValidatorIndexId) String() string {
	return strconv.FormatUint(uint64(v), 10)
}

// ValidatorPubkeyId represents a validator by public key
type ValidatorPubkeyId phase0.BLSPubKey

func (v ValidatorPubkeyId) String() string {
	return fmt.Sprintf("0x%x", v[:])
}

// ParseValidatorId parses a validator ID string
func ParseValidatorId(s string) (ValidatorId, error) {
	// Try to parse as index first
	if idx, err := strconv.ParseUint(s, 10, 64); err == nil {
		return ValidatorIndexId(idx), nil
	}

	// Try to parse as hex pubkey
	if strings.HasPrefix(s, "0x") {
		hexStr := strings.TrimPrefix(s, "0x")
		if len(hexStr) == 96 { // 48 bytes * 2
			var pubkey phase0.BLSPubKey
			bytes, err := hex.DecodeString(hexStr)
			if err == nil && len(bytes) == 48 {
				copy(pubkey[:], bytes)
				return ValidatorPubkeyId(pubkey), nil
			}
		}
	}

	return nil, fmt.Errorf("invalid validator ID: %s", s)
}

// ValidatorStatus represents the status of a validator
type ValidatorStatus string

const (
	ValidatorStatusUnknown            ValidatorStatus = "unknown"
	ValidatorStatusPendingInitialized ValidatorStatus = "pending_initialized"
	ValidatorStatusPendingQueued      ValidatorStatus = "pending_queued"
	ValidatorStatusActiveOngoing      ValidatorStatus = "active_ongoing"
	ValidatorStatusActiveExiting      ValidatorStatus = "active_exiting"
	ValidatorStatusActiveSlashed      ValidatorStatus = "active_slashed"
	ValidatorStatusExitedUnslashed    ValidatorStatus = "exited_unslashed"
	ValidatorStatusExitedSlashed      ValidatorStatus = "exited_slashed"
	ValidatorStatusWithdrawalPossible ValidatorStatus = "withdrawal_possible"
	ValidatorStatusWithdrawalDone     ValidatorStatus = "withdrawal_done"

	// Composite statuses
	ValidatorStatusActive     ValidatorStatus = "active"
	ValidatorStatusPending    ValidatorStatus = "pending"
	ValidatorStatusExited     ValidatorStatus = "exited"
	ValidatorStatusWithdrawal ValidatorStatus = "withdrawal"
)

// Validator represents a validator
type Validator struct {
	PublicKey                  phase0.BLSPubKey `json:"pubkey"`
	WithdrawalCredentials      phase0.Hash32    `json:"withdrawal_credentials"`
	EffectiveBalance           phase0.Gwei      `json:"effective_balance,string"`
	Slashed                    bool             `json:"slashed"`
	ActivationEligibilityEpoch phase0.Epoch     `json:"activation_eligibility_epoch,string"`
	ActivationEpoch            phase0.Epoch     `json:"activation_epoch,string"`
	ExitEpoch                  phase0.Epoch     `json:"exit_epoch,string"`
	WithdrawableEpoch          phase0.Epoch     `json:"withdrawable_epoch,string"`
}

// ValidatorResponse represents a validator response
type ValidatorResponse struct {
	Index     phase0.ValidatorIndex `json:"index,string"`
	Balance   phase0.Gwei           `json:"balance,string"`
	Status    ValidatorStatus       `json:"status"`
	Validator Validator             `json:"validator"`
}

// BlockVersion represents the version of a block
type BlockVersion string

const (
	BlockVersionPhase0    BlockVersion = "phase0"
	BlockVersionAltair    BlockVersion = "altair"
	BlockVersionBellatrix BlockVersion = "bellatrix"
	BlockVersionCapella   BlockVersion = "capella"
	BlockVersionDeneb     BlockVersion = "deneb"
	BlockVersionElectra   BlockVersion = "electra"
)

// VersionedSignedBeaconBlock represents a versioned signed beacon block
type VersionedSignedBeaconBlock struct {
	Version   BlockVersion               `json:"version"`
	Phase0    *phase0.SignedBeaconBlock  `json:"data,omitempty"`
	Altair    interface{}                `json:"-"`
	Bellatrix interface{}                `json:"-"`
	Capella   interface{}                `json:"-"`
	Deneb     *deneb.SignedBeaconBlock   `json:"-"`
	Electra   *electra.SignedBeaconBlock `json:"-"`
}

// Root returns the block root (state root)
func (v *VersionedSignedBeaconBlock) Root() phase0.Root {
	switch v.Version {
	case BlockVersionPhase0:
		if v.Phase0 != nil && v.Phase0.Message != nil {
			return v.Phase0.Message.StateRoot
		}
	case BlockVersionDeneb:
		if v.Deneb != nil && v.Deneb.Message != nil {
			return v.Deneb.Message.StateRoot
		}
	case BlockVersionElectra:
		if v.Electra != nil && v.Electra.Message != nil {
			return v.Electra.Message.StateRoot
		}
	}
	return phase0.Root{}
}

// Slot returns the block slot
func (v *VersionedSignedBeaconBlock) Slot() phase0.Slot {
	switch v.Version {
	case BlockVersionPhase0:
		if v.Phase0 != nil && v.Phase0.Message != nil {
			return v.Phase0.Message.Slot
		}
	case BlockVersionDeneb:
		if v.Deneb != nil && v.Deneb.Message != nil {
			return v.Deneb.Message.Slot
		}
	case BlockVersionElectra:
		if v.Electra != nil && v.Electra.Message != nil {
			return v.Electra.Message.Slot
		}
	}
	return phase0.Slot(0)
}
