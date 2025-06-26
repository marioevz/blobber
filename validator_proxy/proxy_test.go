package validator_proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewProxy(t *testing.T) {
	ctx := context.Background()

	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create proxy
	proxy, err := NewProxy(
		ctx,
		1,
		"localhost",
		30000,
		backend.URL,
		nil,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error creating proxy: %v", err)
	}

	// Clean up
	proxy.Cancel()

	// Verify proxy properties
	// Note: ID is not directly exposed in the proxy struct

	if proxy.Port() != 30000 {
		t.Errorf("expected port 30000, got %d", proxy.Port())
	}
}

func TestProxyWithCallbacks(t *testing.T) {
	ctx := context.Background()

	// Track if callback was called
	callbackCalled := false
	testResponse := []byte(`{"test": "response"}`)

	// Create callback
	callbacks := map[string]ResponseCallback{
		"/test/endpoint": func(req *http.Request, resp []byte) (bool, error) {
			callbackCalled = true

			// Verify request
			if req.URL.Path != "/test/endpoint" {
				t.Errorf("unexpected path in callback: %s", req.URL.Path)
			}

			// Verify response
			if string(resp) != string(testResponse) {
				t.Errorf("unexpected response in callback: %s", string(resp))
			}

			return false, nil // Don't override response
		},
	}

	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(testResponse)
	}))
	defer backend.Close()

	// Create proxy with callbacks
	proxy, err := NewProxy(
		ctx,
		1,
		"localhost",
		30001,
		backend.URL,
		callbacks,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error creating proxy: %v", err)
	}
	defer proxy.Cancel()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Make request through proxy
	resp, err := http.Get("http://localhost:30001/test/endpoint")
	if err != nil {
		t.Fatalf("unexpected error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading response: %v", err)
	}

	// Verify response
	if string(body) != string(testResponse) {
		t.Errorf("unexpected response body: %s", string(body))
	}

	// Verify callback was called
	if !callbackCalled {
		t.Error("callback was not called")
	}
}

func TestProxyErrorResponse(t *testing.T) {
	ctx := context.Background()

	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not see this"))
	}))
	defer backend.Close()

	// Create proxy with error response enabled for a callback that returns an error
	proxy, err := NewProxy(
		ctx,
		1,
		"localhost",
		30002,
		backend.URL,
		map[string]ResponseCallback{
			"/any/endpoint": func(r *http.Request, response []byte) (bool, error) {
				return false, fmt.Errorf("test error") // Return an error from callback
			},
		},
		true, // alwaysErrorResponse
	)

	if err != nil {
		t.Fatalf("unexpected error creating proxy: %v", err)
	}
	defer proxy.Cancel()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Make request through proxy
	resp, err := http.Get("http://localhost:30002/any/endpoint")
	if err != nil {
		t.Fatalf("unexpected error making request: %v", err)
	}
	defer resp.Body.Close()

	// Should get error response when alwaysError is true and callback returns error
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("unexpected error reading response: %v", err)
	}

	// Should contain error message
	if !strings.Contains(string(body), "test error") {
		t.Errorf("expected 'test error' in response, got: %s", string(body))
	}
}

func TestProxyMethods(t *testing.T) {
	ctx := context.Background()

	// Create a test backend server that echoes the method
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(r.Method))
	}))
	defer backend.Close()

	// Create proxy
	proxy, err := NewProxy(
		ctx,
		1,
		"localhost",
		30003,
		backend.URL,
		nil,
		false,
	)

	if err != nil {
		t.Fatalf("unexpected error creating proxy: %v", err)
	}
	defer proxy.Cancel()

	// Wait for proxy to start
	time.Sleep(100 * time.Millisecond)

	// Test different HTTP methods
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	for _, method := range methods {
		req, err := http.NewRequest(method, "http://localhost:30003/test", nil)
		if err != nil {
			t.Fatalf("unexpected error creating request: %v", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("unexpected error making %s request: %v", method, err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("unexpected error reading response: %v", err)
		}

		if string(body) != method {
			t.Errorf("expected method %s, got %s", method, string(body))
		}
	}
}

func TestProxyCallbackOverride(t *testing.T) {
	// Skip this test as OverrideResponse is not implemented in the proxy
	t.Skip("Skipping test for unimplemented OverrideResponse feature")
}
