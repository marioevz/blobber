package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/marioevz/blobber/beacon"
)

func TestGetStateValidators(t *testing.T) {
	// Create test response
	testResponse := StateValidatorsResponse{
		ExecutionOptimistic: false,
		Finalized:           true,
		Data: []ValidatorResponse{
			{
				Index:   "100",
				Balance: "32000000000",
				Status:  "active_ongoing",
				Validator: Validator{
					Pubkey:                     HexBytes{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					WithdrawalCredentials:      HexBytes{4, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					EffectiveBalance:           "32000000000",
					Slashed:                    false,
					ActivationEligibilityEpoch: "0",
					ActivationEpoch:            "0",
					ExitEpoch:                  "18446744073709551615",
					WithdrawableEpoch:          "18446744073709551615",
				},
			},
		},
	}

	// Create mock server
	server := CreateMockBeaconServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Send response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(testResponse); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})
	defer server.Close()

	// Create adapter directly
	adapter, err := beacon.NewBeaconClientAdapter(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Test the function
	ctx := context.Background()
	validators, err := GetStateValidators(ctx, adapter, StateHead, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify response
	if len(validators) != 1 {
		t.Fatalf("expected 1 validator, got %d", len(validators))
	}

	validator := validators[0]
	if validator.Index != "100" {
		t.Errorf("expected index 100, got %s", validator.Index)
	}
	if validator.Balance != "32000000000" {
		t.Errorf("expected balance 32000000000, got %s", validator.Balance)
	}
	if string(validator.Status) != "active_ongoing" {
		t.Errorf("expected status active_ongoing, got %s", validator.Status)
	}
}

func TestGetStateValidatorsWithFilters(t *testing.T) {
	// Create mock server that checks query parameters
	server := CreateMockBeaconServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Check query parameters
		query := r.URL.Query()

		if ids := query.Get("id"); ids != "100,200" {
			t.Errorf("expected id=100,200, got %s", ids)
		}

		if status := query.Get("status"); status != "active,pending" {
			t.Errorf("expected status=active,pending, got %s", status)
		}

		// Send empty response
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(StateValidatorsResponse{Data: []ValidatorResponse{}}); err != nil {
			t.Errorf("failed to encode response: %v", err)
		}
	})
	defer server.Close()

	// Create adapter directly
	adapter, err := beacon.NewBeaconClientAdapter(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Test with filters
	ctx := context.Background()
	validatorIds := []ValidatorId{"100", "200"}
	statusFilter := []ValidatorStatus{ValidatorStatusActive, ValidatorStatusPending}

	_, err = GetStateValidators(ctx, adapter, StateHead, validatorIds, statusFilter)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetStateValidatorsError(t *testing.T) {
	// Create mock server that returns error for validators endpoint
	server := CreateMockBeaconServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	// Create adapter directly
	adapter, err := beacon.NewBeaconClientAdapter(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("failed to create adapter: %v", err)
	}

	// Test error handling
	ctx := context.Background()
	_, err = GetStateValidators(ctx, adapter, StateHead, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStateIdConstants(t *testing.T) {
	// Test StateId constants
	if StateHead != "head" {
		t.Errorf("StateHead should be 'head', got %s", StateHead)
	}
	if StateGenesis != "genesis" {
		t.Errorf("StateGenesis should be 'genesis', got %s", StateGenesis)
	}
	if StateFinalized != "finalized" {
		t.Errorf("StateFinalized should be 'finalized', got %s", StateFinalized)
	}
	if StateJustified != "justified" {
		t.Errorf("StateJustified should be 'justified', got %s", StateJustified)
	}
}

func TestBlockIdConstants(t *testing.T) {
	// Test BlockId constants
	if BlockHead != "head" {
		t.Errorf("BlockHead should be 'head', got %s", BlockHead)
	}
	if BlockGenesis != "genesis" {
		t.Errorf("BlockGenesis should be 'genesis', got %s", BlockGenesis)
	}
	if BlockFinalized != "finalized" {
		t.Errorf("BlockFinalized should be 'finalized', got %s", BlockFinalized)
	}
	if BlockJustified != "justified" {
		t.Errorf("BlockJustified should be 'justified', got %s", BlockJustified)
	}
}

func TestValidatorStatusConstants(t *testing.T) {
	// Test a few ValidatorStatus constants
	statuses := []struct {
		status   ValidatorStatus
		expected string
	}{
		{ValidatorStatusPendingInitialized, "pending_initialized"},
		{ValidatorStatusActiveOngoing, "active_ongoing"},
		{ValidatorStatusExitedSlashed, "exited_slashed"},
		{ValidatorStatusWithdrawalDone, "withdrawal_done"},
	}

	for _, s := range statuses {
		if string(s.status) != s.expected {
			t.Errorf("expected %s, got %s", s.expected, s.status)
		}
	}
}
