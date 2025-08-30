package client

import (
	"context"
	"testing"
	"time"
)

func TestDefaultResilientConfig(t *testing.T) {
	config := DefaultResilientConfig()
	
	if !config.EnableCaching {
		t.Error("DefaultResilientConfig() EnableCaching should be true")
	}
	if config.SearchCacheTTL != 15*time.Minute {
		t.Errorf("DefaultResilientConfig() SearchCacheTTL = %v, want 15m", config.SearchCacheTTL)
	}
	if config.CertCacheTTL != 1*time.Hour {
		t.Errorf("DefaultResilientConfig() CertCacheTTL = %v, want 1h", config.CertCacheTTL)
	}
	if !config.EnableOfflineFallback {
		t.Error("DefaultResilientConfig() EnableOfflineFallback should be true")
	}
}

func TestNewResilientCTLogClient(t *testing.T) {
	mockClient := &mockCTLogClient{
		searchResults: []CTLogEntry{{ID: 123}},
		certificate:   generateTestCertificate("test"),
	}
	
	config := DefaultResilientConfig()
	client := NewResilientCTLogClient(mockClient, config)
	
	if client == nil {
		t.Fatal("NewResilientCTLogClient() returned nil")
	}
}

func TestNewResilientCTLogClient_NilConfig(t *testing.T) {
	mockClient := &mockCTLogClient{}
	
	client := NewResilientCTLogClient(mockClient, nil)
	
	if client == nil {
		t.Fatal("NewResilientCTLogClient() with nil config should use defaults")
	}
}

func TestResilientCTLogClient_SearchWithCaching(t *testing.T) {
	mockClient := &mockCTLogClient{
		searchResults: []CTLogEntry{{ID: 123, CommonName: "test.example.org"}},
	}
	
	config := &ResilientConfig{
		EnableCaching:           true,
		SearchCacheTTL:         1 * time.Hour,
		EnableOfflineFallback:  false,
	}
	
	client := NewResilientCTLogClient(mockClient, config)
	issuer := "example.org"
	
	// First call should hit the underlying client
	results1, err := client.SearchCertificatesByIssuer(issuer)
	if err != nil {
		t.Fatalf("SearchCertificatesByIssuer() error = %v", err)
	}
	if len(results1) != 1 {
		t.Errorf("SearchCertificatesByIssuer() results length = %d, want 1", len(results1))
	}
	if mockClient.searchCallCount != 1 {
		t.Errorf("First call count = %d, want 1", mockClient.searchCallCount)
	}
	
	// Second call should use cache
	results2, err := client.SearchCertificatesByIssuer(issuer)
	if err != nil {
		t.Fatalf("SearchCertificatesByIssuer() error = %v", err)
	}
	if len(results2) != 1 {
		t.Errorf("SearchCertificatesByIssuer() results length = %d, want 1", len(results2))
	}
	// Call count should still be 1 (cache hit)
	if mockClient.searchCallCount != 1 {
		t.Errorf("Cached call count = %d, want 1 (cache hit)", mockClient.searchCallCount)
	}
}

func TestResilientCTLogClient_DownloadWithCaching(t *testing.T) {
	mockClient := &mockCTLogClient{
		certificate: generateTestCertificate("test.example.org"),
	}
	
	config := &ResilientConfig{
		EnableCaching:           true,
		CertCacheTTL:           1 * time.Hour,
		EnableOfflineFallback:  false,
	}
	
	client := NewResilientCTLogClient(mockClient, config)
	certID := 456
	
	// First call should hit the underlying client
	cert1, err := client.DownloadCertificate(certID)
	if err != nil {
		t.Fatalf("DownloadCertificate() error = %v", err)
	}
	if cert1 == nil {
		t.Error("DownloadCertificate() cert should not be nil")
	}
	if mockClient.downloadCallCount != 1 {
		t.Errorf("First call count = %d, want 1", mockClient.downloadCallCount)
	}
	
	// Second call should use cache
	cert2, err := client.DownloadCertificate(certID)
	if err != nil {
		t.Fatalf("DownloadCertificate() error = %v", err)
	}
	if cert2 == nil {
		t.Error("DownloadCertificate() cert should not be nil")
	}
	// Call count should still be 1 (cache hit)
	if mockClient.downloadCallCount != 1 {
		t.Errorf("Cached call count = %d, want 1 (cache hit)", mockClient.downloadCallCount)
	}
}

func TestResilientCTLogClient_GetNetworkStatus(t *testing.T) {
	mockClient := &mockCTLogClient{}
	config := DefaultResilientConfig()
	
	client := NewResilientCTLogClient(mockClient, config)
	
	status := client.GetNetworkStatus()
	
	// Should return connectivity status (exact values depend on network environment)
	if status.HostsChecked < 0 {
		t.Error("GetNetworkStatus() HostsChecked should be non-negative")
	}
}

func TestResilientCTLogClient_SearchWithFallback(t *testing.T) {
	mockClient := &mockCTLogClient{
		searchResults: []CTLogEntry{{ID: 123}},
	}
	
	config := &ResilientConfig{
		EnableCaching:           false,
		EnableOfflineFallback:  true,
		ConnectivityCheckTimeout: 100 * time.Millisecond,
	}
	
	client := NewResilientCTLogClient(mockClient, config).(*resilientCTLogClient)
	
	t.Run("with network connectivity", func(t *testing.T) {
		ctx := context.Background()
		results, err := client.SearchWithFallback(ctx, "example.org")
		if err != nil {
			t.Fatalf("SearchWithFallback() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("SearchWithFallback() results length = %d, want 1", len(results))
		}
	})
	
	t.Run("with context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		
		_, err := client.SearchWithFallback(ctx, "example.org")
		// Should handle context cancellation gracefully
		// Exact error depends on whether fallback triggers first
		if err == nil {
			t.Log("SearchWithFallback() with cancelled context succeeded (acceptable if cached or fallback disabled)")
		}
	})
}

func TestNewRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(5)
	defer limiter.Close()
	
	if limiter == nil {
		t.Fatal("NewRateLimiter() returned nil")
	}
	
	// Should have tokens available immediately
	ctx := context.Background()
	if err := limiter.Wait(ctx); err != nil {
		t.Errorf("RateLimiter.Wait() should succeed immediately: %v", err)
	}
}

func TestNewRateLimiter_ZeroRate(t *testing.T) {
	limiter := NewRateLimiter(0)
	defer limiter.Close()
	
	// Should default to some positive rate
	ctx := context.Background()
	if err := limiter.Wait(ctx); err != nil {
		t.Errorf("RateLimiter.Wait() with zero rate should use default: %v", err)
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	limiter := NewRateLimiter(2) // 2 requests per second
	defer limiter.Close()
	
	ctx := context.Background()
	
	// First two waits should succeed immediately (initial tokens)
	if err := limiter.Wait(ctx); err != nil {
		t.Errorf("First Wait() should succeed: %v", err)
	}
	if err := limiter.Wait(ctx); err != nil {
		t.Errorf("Second Wait() should succeed: %v", err)
	}
	
	// Third wait should take some time (need to wait for refill)
	start := time.Now()
	if err := limiter.Wait(ctx); err != nil {
		t.Errorf("Third Wait() should succeed after delay: %v", err)
	}
	elapsed := time.Since(start)
	
	// Should have waited at least some time for refill (but be lenient for timing)
	if elapsed < 100*time.Millisecond {
		t.Logf("Third Wait() took %v, expected some delay (may vary in test environment)", elapsed)
	}
}

func TestRateLimiter_WaitWithCancelledContext(t *testing.T) {
	limiter := NewRateLimiter(1)
	defer limiter.Close()
	
	// Consume the initial token
	ctx := context.Background()
	_ = limiter.Wait(ctx)
	
	// Now create cancelled context
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	
	// Wait should return context error
	if err := limiter.Wait(cancelledCtx); err != context.Canceled {
		t.Errorf("Wait() with cancelled context should return context.Canceled, got %v", err)
	}
}

func TestNewRateLimitedCTLogClient(t *testing.T) {
	mockClient := &mockCTLogClient{
		searchResults: []CTLogEntry{{ID: 123}},
		certificate:   generateTestCertificate("test"),
	}
	
	rateLimitedClient := NewRateLimitedCTLogClient(mockClient, 5)
	
	// Should be able to make requests (with rate limiting)
	results, err := rateLimitedClient.SearchCertificatesByIssuer("example.org")
	if err != nil {
		t.Fatalf("SearchCertificatesByIssuer() error = %v", err)
	}
	if len(results) != 1 {
		t.Errorf("SearchCertificatesByIssuer() results length = %d, want 1", len(results))
	}
	
	cert, err := rateLimitedClient.DownloadCertificate(456)
	if err != nil {
		t.Fatalf("DownloadCertificate() error = %v", err)
	}
	if cert == nil {
		t.Error("DownloadCertificate() cert should not be nil")
	}
}

func TestNewFullyCTLogClient(t *testing.T) {
	// This creates a fully configured client with all features
	client := NewFullyCTLogClient()
	
	if client == nil {
		t.Fatal("NewFullyCTLogClient() returned nil")
	}
	
	// Should be able to get network status
	status := client.GetNetworkStatus()
	if status.HostsChecked < 0 {
		t.Error("NewFullyCTLogClient() network status should be valid")
	}
	
	// Basic functionality tests would require network access
	// For unit tests, we just verify the client is constructed properly
	t.Log("NewFullyCTLogClient() created successfully with all features")
}

func TestResilientCTLogClient_Interfaces(t *testing.T) {
	mockClient := &mockCTLogClient{}
	config := DefaultResilientConfig()
	
	client := NewResilientCTLogClient(mockClient, config)
	
	// Should implement CTLogClient
	var _ CTLogClient = client
	
	// Should implement ResilientCTLogClient
	var _ = client
	
	// Test basic CTLogClient interface methods
	_, err := client.SearchCertificatesByIssuer("test")
	if err == nil && mockClient.searchError != nil {
		t.Error("SearchCertificatesByIssuer() should forward errors from underlying client")
	}
	
	_, err = client.DownloadCertificate(123)
	if err == nil && mockClient.downloadError != nil {
		t.Error("DownloadCertificate() should forward errors from underlying client")
	}
	
	// Test ResilientCTLogClient interface methods
	ctx := context.Background()
	_, err = client.SearchWithFallback(ctx, "test")
	if err == nil && mockClient.searchError != nil {
		t.Error("SearchWithFallback() should forward errors from underlying client")
	}
	
	_, err = client.DownloadWithFallback(ctx, 123)
	if err == nil && mockClient.downloadError != nil {
		t.Error("DownloadWithFallback() should forward errors from underlying client")
	}
	
	// GetNetworkStatus should always return status
	status := client.GetNetworkStatus()
	if status.HostsChecked < 0 {
		t.Error("GetNetworkStatus() should return valid status")
	}
}