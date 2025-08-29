package client

import (
	"net/http"
	"testing"
	"time"
)

func TestNewMockServer(t *testing.T) {
	config := MockServerConfig{
		ReturnStatus: http.StatusOK,
		ResponseBody: "test response",
	}
	
	server := NewMockServer(config)
	defer server.Close()
	
	if server == nil {
		t.Fatal("NewMockServer returned nil")
	}
	
	// Test basic functionality
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
	
	if server.RequestCount() != 1 {
		t.Errorf("Expected 1 request, got %d", server.RequestCount())
	}
}

func TestMockServer_ResponseDelay(t *testing.T) {
	config := MockServerConfig{
		ResponseDelay: 100 * time.Millisecond,
		ReturnStatus:  http.StatusOK,
	}
	
	server := NewMockServer(config)
	defer server.Close()
	
	start := time.Now()
	resp, err := http.Get(server.URL)
	duration := time.Since(start)
	
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	resp.Body.Close()
	
	if duration < 100*time.Millisecond {
		t.Errorf("Expected at least 100ms delay, got %v", duration)
	}
}

func TestMockServer_FailAfterAttempts(t *testing.T) {
	config := MockServerConfig{
		FailAfterAttempts: 2,
		ReturnStatus:      http.StatusOK,
	}
	
	server := NewMockServer(config)
	defer server.Close()
	
	// First request should succeed
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("First request: expected status 200, got %d", resp.StatusCode)
	}
	
	// Second request should succeed
	resp, err = http.Get(server.URL)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Second request: expected status 200, got %d", resp.StatusCode)
	}
	
	// Third request should fail
	resp, err = http.Get(server.URL)
	if err != nil {
		t.Fatalf("Third request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Third request: expected status 500, got %d", resp.StatusCode)
	}
}

func TestMockServer_RequestCount(t *testing.T) {
	server := NewMockServer(MockServerConfig{})
	defer server.Close()
	
	if server.RequestCount() != 0 {
		t.Errorf("Initial request count should be 0, got %d", server.RequestCount())
	}
	
	// Make multiple requests
	for i := 1; i <= 3; i++ {
		resp, err := http.Get(server.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		resp.Body.Close()
		
		if server.RequestCount() != i {
			t.Errorf("After %d requests, expected count %d, got %d", i, i, server.RequestCount())
		}
	}
	
	// Test reset
	server.ResetRequestCount()
	if server.RequestCount() != 0 {
		t.Errorf("After reset, expected count 0, got %d", server.RequestCount())
	}
}

func TestNewMockTimeoutServer(t *testing.T) {
	server := NewMockTimeoutServer()
	defer server.Close()
	
	// Create client with short timeout
	client := &http.Client{Timeout: 50 * time.Millisecond}
	
	_, err := client.Get(server.URL)
	if err == nil {
		t.Fatal("Expected timeout error")
	}
	
	// Should have received the request even though it timed out
	if server.RequestCount() != 1 {
		t.Errorf("Expected 1 request despite timeout, got %d", server.RequestCount())
	}
}

func TestNewMockNetworkErrorServer(t *testing.T) {
	server := NewMockNetworkErrorServer()
	defer server.Close()
	
	_, err := http.Get(server.URL)
	if err == nil {
		t.Fatal("Expected network error")
	}
	
	// Should have received the request before connection was closed
	if server.RequestCount() != 1 {
		t.Errorf("Expected 1 request despite network error, got %d", server.RequestCount())
	}
}

func TestNewCTLogMockServer(t *testing.T) {
	server := NewCTLogMockServer()
	defer server.Close()
	
	// Test certificate search
	resp, err := http.Get(server.URL + "?CN=example.org&output=json&exclude=expired")
	if err != nil {
		t.Fatalf("Search request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Search request: expected status 200, got %d", resp.StatusCode)
	}
	
	// Test certificate download
	resp, err = http.Get(server.URL + "?d=123456789")
	if err != nil {
		t.Fatalf("Download request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Download request: expected status 200, got %d", resp.StatusCode)
	}
}

func TestCTLogMockServer_SearchScenarios(t *testing.T) {
	server := NewCTLogMockServer()
	defer server.Close()
	
	tests := []struct {
		name           string
		cn             string
		expectedStatus int
	}{
		{"known certificate", "example.org", http.StatusOK},
		{"not found", "notfound.example", http.StatusOK},
		{"server error", "error.example", http.StatusInternalServerError},
		{"generic certificate", "test.example", http.StatusOK},
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			url := server.URL + "?CN=" + test.cn + "&output=json&exclude=expired"
			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestCTLogMockServer_DownloadScenarios(t *testing.T) {
	server := NewCTLogMockServer()
	defer server.Close()
	
	tests := []struct {
		name           string
		certID         string
		expectedStatus int
	}{
		{"valid certificate ID", "123456789", http.StatusOK},
		{"another valid ID", "987654321", http.StatusOK},
		{"not found", "404", http.StatusNotFound},
		{"server error", "500", http.StatusInternalServerError},
		{"invalid data", "999", http.StatusOK}, // Returns OK but invalid data
	}
	
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			url := server.URL + "?d=" + test.certID
			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != test.expectedStatus {
				t.Errorf("Expected status %d, got %d", test.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestCTLogMockServer_UnknownRequest(t *testing.T) {
	server := NewCTLogMockServer()
	defer server.Close()
	
	resp, err := http.Get(server.URL + "?unknown=param")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", resp.StatusCode)
	}
}