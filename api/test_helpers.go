package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// CreateMockBeaconServer creates a mock beacon node server that responds to common endpoints
func CreateMockBeaconServer(t *testing.T, validatorsHandler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/eth/v1/node/version":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"version": "mock/v1.0.0",
				},
			})
		case "/eth/v1/node/syncing":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"is_syncing": false,
				},
			})
		case "/eth/v1/config/spec":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"SECONDS_PER_SLOT": "12",
				},
			})
		case "/eth/v1/beacon/genesis":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"data": map[string]interface{}{
					"genesis_time": "1606824023",
				},
			})
		case "/eth/v1/beacon/states/head/validators":
			if validatorsHandler != nil {
				validatorsHandler(w, r)
			} else {
				w.WriteHeader(http.StatusInternalServerError)
			}
		default:
			// Log but don't fail on unexpected paths during initialization
			// The http client may make additional calls during startup
			if r.URL.Path != "/favicon.ico" {
				t.Logf("unhandled path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}