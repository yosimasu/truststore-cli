package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 15*time.Second {
		t.Errorf("Expected timeout 15s, got %v", config.Timeout)
	}
	if config.MaxRetries != 3 {
		t.Errorf("Expected max retries 3, got %d", config.MaxRetries)
	}
	if config.BaseDelay != 100*time.Millisecond {
		t.Errorf("Expected base delay 100ms, got %v", config.BaseDelay)
	}
	if config.MaxDelay != 5*time.Second {
		t.Errorf("Expected max delay 5s, got %v", config.MaxDelay)
	}
}

func TestNewHTTPClient(t *testing.T) {
	// Test with nil config
	client := NewHTTPClient(nil)
	if client == nil {
		t.Fatal("NewHTTPClient returned nil")
	}

	// Test with custom config
	config := &Config{
		Timeout:    5 * time.Second,
		MaxRetries: 1,
		BaseDelay:  50 * time.Millisecond,
		MaxDelay:   1 * time.Second,
	}
	client = NewHTTPClient(config)
	if client == nil {
		t.Fatal("NewHTTPClient returned nil")
	}
}

func TestHTTPClient_Get_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test response"))
	}))
	defer server.Close()

	client := NewHTTPClient(DefaultConfig())
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_GetWithContext_Success(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("test response"))
	}))
	defer server.Close()

	client := NewHTTPClient(DefaultConfig())
	ctx := context.Background()
	resp, err := client.GetWithContext(ctx, server.URL)
	if err != nil {
		t.Fatalf("GetWithContext failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_GetWithContext_Cancelled(t *testing.T) {
	// Create test server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewHTTPClient(DefaultConfig())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.GetWithContext(ctx, server.URL)
	if err == nil {
		t.Fatal("Expected context cancellation error")
	}
}

func TestHTTPClient_Retry_ServerErrors(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
		}
	}))
	defer server.Close()

	config := &Config{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond, // Fast test
		MaxDelay:   10 * time.Millisecond,
	}
	client := NewHTTPClient(config)

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected success after retries, got error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_Retry_ExhaustRetries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	config := &Config{
		Timeout:    5 * time.Second,
		MaxRetries: 2,
		BaseDelay:  1 * time.Millisecond, // Fast test
		MaxDelay:   10 * time.Millisecond,
	}
	client := NewHTTPClient(config)

	_, err := client.Get(server.URL)
	if err == nil {
		t.Fatal("Expected error after exhausting retries")
	}

	expectedErr := "HTTP request returned status 500"
	if errStr := err.Error(); errStr[:len(expectedErr)] != expectedErr {
		t.Errorf("Expected error containing %q, got %q", expectedErr, errStr)
	}
}

func TestHTTPClient_NoRetryFor4xxErrors(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := &Config{
		Timeout:    5 * time.Second,
		MaxRetries: 3,
		BaseDelay:  1 * time.Millisecond,
		MaxDelay:   10 * time.Millisecond,
	}
	client := NewHTTPClient(config)

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Expected no error for 4xx status, got: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if attempts != 1 {
		t.Errorf("Expected 1 attempt (no retry for 4xx), got %d", attempts)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestHTTPClient_CalculateDelay(t *testing.T) {
	config := &Config{
		BaseDelay: 100 * time.Millisecond,
		MaxDelay:  5 * time.Second,
	}
	client := &httpClient{config: config}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{10, 5 * time.Second}, // Should cap at MaxDelay
	}

	for _, test := range tests {
		delay := client.calculateDelay(test.attempt)
		if delay != test.expected {
			t.Errorf("For attempt %d, expected delay %v, got %v", test.attempt, test.expected, delay)
		}
	}
}

func TestHTTPClient_ShouldRetryStatus(t *testing.T) {
	client := &httpClient{}

	retryableStatuses := []int{
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	}

	nonRetryableStatuses := []int{
		http.StatusOK,
		http.StatusNotFound,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
	}

	for _, status := range retryableStatuses {
		if !client.shouldRetryStatus(status) {
			t.Errorf("Expected status %d to be retryable", status)
		}
	}

	for _, status := range nonRetryableStatuses {
		if client.shouldRetryStatus(status) {
			t.Errorf("Expected status %d to NOT be retryable", status)
		}
	}
}

func TestHTTPClient_InvalidURL(t *testing.T) {
	client := NewHTTPClient(DefaultConfig())
	_, err := client.Get("invalid-url")
	if err == nil {
		t.Fatal("Expected error for invalid URL")
	}
}

func TestHTTPClient_NetworkError_Retry(t *testing.T) {
	config := &Config{
		Timeout:    100 * time.Millisecond,
		MaxRetries: 2,
		BaseDelay:  1 * time.Millisecond,
		MaxDelay:   10 * time.Millisecond,
	}
	client := NewHTTPClient(config)

	// Use non-routable IP to simulate network error
	_, err := client.Get("http://192.0.2.1:12345") // RFC 5737 test address
	if err == nil {
		t.Fatal("Expected network error")
	}

	expectedErr := "attempt 3/3"
	if errStr := err.Error(); !containsString(errStr, expectedErr) {
		t.Errorf("Expected error containing %q, got %q", expectedErr, errStr)
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}
