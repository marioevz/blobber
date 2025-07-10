package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/marioevz/blobber/beacon"
	"github.com/pkg/errors"
)

// StateValidatorsResponse represents the response from the state validators endpoint
type StateValidatorsResponse struct {
	ExecutionOptimistic bool                `json:"execution_optimistic"`
	Finalized           bool                `json:"finalized"`
	Data                []ValidatorResponse `json:"data"`
}

// GetStateValidators queries the beacon node for validators
func GetStateValidators(
	ctx context.Context,
	client *beacon.BeaconClientAdapter,
	stateId StateId,
	validatorIds []ValidatorId,
	statusFilter []ValidatorStatus,
) ([]ValidatorResponse, error) {
	// Build the URL
	baseURL := client.GetAddress()
	url := fmt.Sprintf("%s/eth/v1/beacon/states/%s/validators", baseURL, stateId)

	// Build query parameters
	params := []string{}
	if len(validatorIds) > 0 {
		ids := make([]string, len(validatorIds))
		for i, id := range validatorIds {
			ids[i] = string(id)
		}
		params = append(params, fmt.Sprintf("id=%s", strings.Join(ids, ",")))
	}
	if len(statusFilter) > 0 {
		statuses := make([]string, len(statusFilter))
		for i, status := range statusFilter {
			statuses[i] = string(status)
		}
		params = append(params, fmt.Sprintf("status=%s", strings.Join(statuses, ",")))
	}

	if len(params) > 0 {
		url = fmt.Sprintf("%s?%s", url, strings.Join(params, "&"))
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute request")
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parse response
	var result StateValidatorsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Log raw response for debugging
		fmt.Printf("DEBUG: Failed to decode validators response: %v\n", err)
		return nil, errors.Wrap(err, "failed to decode response")
	}

	// Log the number of validators returned
	if len(result.Data) > 0 {
		// Log a sample validator for debugging
		fmt.Printf("DEBUG: Got %d validators, first validator index: %s\n", len(result.Data), result.Data[0].Index)
	}

	return result.Data, nil
}
