package client

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// generateTestCertificate creates a test certificate for caching tests
func generateTestCertificate(commonName string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
}

func TestNewMemoryCache(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	if cache == nil {
		t.Fatal("NewMemoryCache() returned nil")
	}
	
	if cache.Size() != 0 {
		t.Errorf("NewMemoryCache() size = %d, want 0", cache.Size())
	}
}

func TestMemoryCache_SearchResults(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	issuer := "example.org"
	entries := []CTLogEntry{
		{ID: 123, CommonName: "test.example.org"},
		{ID: 456, CommonName: "api.example.org"},
	}
	
	t.Run("cache miss", func(t *testing.T) {
		results, found := cache.GetSearchResults(issuer)
		if found {
			t.Error("GetSearchResults() found = true, want false")
		}
		if results != nil {
			t.Error("GetSearchResults() results should be nil on cache miss")
		}
	})
	
	t.Run("cache set and hit", func(t *testing.T) {
		cache.SetSearchResults(issuer, entries, 1*time.Hour)
		
		results, found := cache.GetSearchResults(issuer)
		if !found {
			t.Error("GetSearchResults() found = false, want true")
		}
		if len(results) != len(entries) {
			t.Errorf("GetSearchResults() results length = %d, want %d", len(results), len(entries))
		}
		if results[0].ID != entries[0].ID {
			t.Errorf("GetSearchResults() first entry ID = %d, want %d", results[0].ID, entries[0].ID)
		}
	})
	
	t.Run("cache size", func(t *testing.T) {
		if cache.Size() != 1 {
			t.Errorf("cache.Size() = %d, want 1", cache.Size())
		}
	})
}

func TestMemoryCache_Certificates(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	certID := 789
	cert := generateTestCertificate("test.example.org")
	
	t.Run("cache miss", func(t *testing.T) {
		result, found := cache.GetCertificate(certID)
		if found {
			t.Error("GetCertificate() found = true, want false")
		}
		if result != nil {
			t.Error("GetCertificate() result should be nil on cache miss")
		}
	})
	
	t.Run("cache set and hit", func(t *testing.T) {
		cache.SetCertificate(certID, cert, 1*time.Hour)
		
		result, found := cache.GetCertificate(certID)
		if !found {
			t.Error("GetCertificate() found = false, want true")
		}
		if result == nil {
			t.Error("GetCertificate() result should not be nil on cache hit")
			return
		}
		if result.Subject.CommonName != cert.Subject.CommonName {
			t.Errorf("GetCertificate() CommonName = %s, want %s", result.Subject.CommonName, cert.Subject.CommonName)
		}
	})
}

func TestMemoryCache_Expiration(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	issuer := "example.org"
	entries := []CTLogEntry{{ID: 123}}
	
	// Set with very short TTL
	cache.SetSearchResults(issuer, entries, 10*time.Millisecond)
	
	// Should be found immediately
	_, found := cache.GetSearchResults(issuer)
	if !found {
		t.Error("GetSearchResults() should find entry immediately after set")
	}
	
	// Wait for expiration
	time.Sleep(20 * time.Millisecond)
	
	// Should be expired now
	_, found = cache.GetSearchResults(issuer)
	if found {
		t.Error("GetSearchResults() should not find expired entry")
	}
}

func TestMemoryCache_Clear(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	// Add some entries
	cache.SetSearchResults("issuer1", []CTLogEntry{{ID: 123}}, 1*time.Hour)
	cache.SetSearchResults("issuer2", []CTLogEntry{{ID: 456}}, 1*time.Hour)
	cache.SetCertificate(789, generateTestCertificate("test"), 1*time.Hour)
	
	if cache.Size() != 3 {
		t.Errorf("cache.Size() before clear = %d, want 3", cache.Size())
	}
	
	cache.Clear()
	
	if cache.Size() != 0 {
		t.Errorf("cache.Size() after clear = %d, want 0", cache.Size())
	}
	
	// Verify entries are actually gone
	_, found := cache.GetSearchResults("issuer1")
	if found {
		t.Error("GetSearchResults() found entry after clear")
	}
	
	_, found = cache.GetCertificate(789)
	if found {
		t.Error("GetCertificate() found entry after clear")
	}
}

func TestMemoryCache_Stats(t *testing.T) {
	cache := NewMemoryCache().(*memoryCache)
	defer cache.Close()
	
	issuer := "example.org"
	entries := []CTLogEntry{{ID: 123}}
	
	// Initial stats
	stats := cache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Errorf("Initial stats: hits=%d misses=%d, want hits=0 misses=0", stats.Hits, stats.Misses)
	}
	
	// Cache miss
	cache.GetSearchResults(issuer)
	stats = cache.GetStats()
	if stats.Misses != 1 {
		t.Errorf("After miss: misses=%d, want 1", stats.Misses)
	}
	
	// Cache set and hit
	cache.SetSearchResults(issuer, entries, 1*time.Hour)
	cache.GetSearchResults(issuer)
	stats = cache.GetStats()
	if stats.Hits != 1 {
		t.Errorf("After hit: hits=%d, want 1", stats.Hits)
	}
	if stats.Entries != 1 {
		t.Errorf("After set: entries=%d, want 1", stats.Entries)
	}
}

func TestMemoryCache_Cleanup(t *testing.T) {
	cache := NewMemoryCache().(*memoryCache)
	defer cache.Close()
	
	// Add expired entries
	cache.SetSearchResults("expired", []CTLogEntry{{ID: 123}}, 1*time.Millisecond)
	cache.SetCertificate(456, generateTestCertificate("expired"), 1*time.Millisecond)
	
	// Add non-expired entries
	cache.SetSearchResults("valid", []CTLogEntry{{ID: 789}}, 1*time.Hour)
	
	// Wait for expiration
	time.Sleep(5 * time.Millisecond)
	
	// Force cleanup
	cache.cleanup()
	
	// Expired entries should be gone
	_, found := cache.GetSearchResults("expired")
	if found {
		t.Error("Expired search entry should be cleaned up")
	}
	
	_, found = cache.GetCertificate(456)
	if found {
		t.Error("Expired certificate entry should be cleaned up")
	}
	
	// Valid entry should remain
	_, found = cache.GetSearchResults("valid")
	if !found {
		t.Error("Valid entry should not be cleaned up")
	}
}

// mockCTLogClient for testing cached client
type mockCTLogClient struct {
	searchCallCount int
	downloadCallCount int
	searchResults   []CTLogEntry
	certificate     *x509.Certificate
	searchError     error
	downloadError   error
}

func (m *mockCTLogClient) SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error) {
	m.searchCallCount++
	return m.searchResults, m.searchError
}

func (m *mockCTLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	m.downloadCallCount++
	return m.certificate, m.downloadError
}

func TestNewCachedCTLogClient(t *testing.T) {
	mockClient := &mockCTLogClient{}
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	cachedClient := NewCachedCTLogClient(mockClient, cache)
	
	if cachedClient == nil {
		t.Fatal("NewCachedCTLogClient() returned nil")
	}
}

func TestCachedCTLogClient_SearchCaching(t *testing.T) {
	mockClient := &mockCTLogClient{
		searchResults: []CTLogEntry{{ID: 123, CommonName: "test.example.org"}},
	}
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	cachedClient := NewCachedCTLogClient(mockClient, cache)
	issuer := "example.org"
	
	t.Run("first call hits underlying client", func(t *testing.T) {
		results, err := cachedClient.SearchCertificatesByIssuer(issuer)
		if err != nil {
			t.Fatalf("SearchCertificatesByIssuer() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("SearchCertificatesByIssuer() results length = %d, want 1", len(results))
		}
		if mockClient.searchCallCount != 1 {
			t.Errorf("SearchCertificatesByIssuer() call count = %d, want 1", mockClient.searchCallCount)
		}
	})
	
	t.Run("second call uses cache", func(t *testing.T) {
		results, err := cachedClient.SearchCertificatesByIssuer(issuer)
		if err != nil {
			t.Fatalf("SearchCertificatesByIssuer() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("SearchCertificatesByIssuer() results length = %d, want 1", len(results))
		}
		// Call count should still be 1 (cache hit)
		if mockClient.searchCallCount != 1 {
			t.Errorf("SearchCertificatesByIssuer() call count = %d, want 1 (cache hit)", mockClient.searchCallCount)
		}
	})
}

func TestCachedCTLogClient_DownloadCaching(t *testing.T) {
	mockClient := &mockCTLogClient{
		certificate: generateTestCertificate("test.example.org"),
	}
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	cachedClient := NewCachedCTLogClient(mockClient, cache)
	certID := 456
	
	t.Run("first call hits underlying client", func(t *testing.T) {
		cert, err := cachedClient.DownloadCertificate(certID)
		if err != nil {
			t.Fatalf("DownloadCertificate() error = %v", err)
		}
		if cert == nil {
			t.Error("DownloadCertificate() cert should not be nil")
		}
		if mockClient.downloadCallCount != 1 {
			t.Errorf("DownloadCertificate() call count = %d, want 1", mockClient.downloadCallCount)
		}
	})
	
	t.Run("second call uses cache", func(t *testing.T) {
		cert, err := cachedClient.DownloadCertificate(certID)
		if err != nil {
			t.Fatalf("DownloadCertificate() error = %v", err)
		}
		if cert == nil {
			t.Error("DownloadCertificate() cert should not be nil")
		}
		// Call count should still be 1 (cache hit)
		if mockClient.downloadCallCount != 1 {
			t.Errorf("DownloadCertificate() call count = %d, want 1 (cache hit)", mockClient.downloadCallCount)
		}
	})
}

func TestCachedCTLogClient_ErrorHandling(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	t.Run("search error not cached", func(t *testing.T) {
		mockClient := &mockCTLogClient{
			searchError: NewNetworkError("network error"),
		}
		
		cachedClient := NewCachedCTLogClient(mockClient, cache)
		
		_, err := cachedClient.SearchCertificatesByIssuer("example.org")
		if err == nil {
			t.Error("SearchCertificatesByIssuer() should return error")
		}
		
		// Verify error is not cached by calling again
		_, err = cachedClient.SearchCertificatesByIssuer("example.org")
		if err == nil {
			t.Error("SearchCertificatesByIssuer() should still return error (not cached)")
		}
		if mockClient.searchCallCount != 2 {
			t.Errorf("SearchCertificatesByIssuer() call count = %d, want 2 (errors not cached)", mockClient.searchCallCount)
		}
	})
	
	t.Run("download error not cached", func(t *testing.T) {
		mockClient := &mockCTLogClient{
			downloadError: NewValidationError("invalid ID"),
		}
		
		cachedClient := NewCachedCTLogClient(mockClient, cache)
		
		_, err := cachedClient.DownloadCertificate(123)
		if err == nil {
			t.Error("DownloadCertificate() should return error")
		}
		
		// Verify error is not cached by calling again
		_, err = cachedClient.DownloadCertificate(123)
		if err == nil {
			t.Error("DownloadCertificate() should still return error (not cached)")
		}
		if mockClient.downloadCallCount != 2 {
			t.Errorf("DownloadCertificate() call count = %d, want 2 (errors not cached)", mockClient.downloadCallCount)
		}
	})
}

func TestCachedCTLogClient_TTLConfiguration(t *testing.T) {
	mockClient := &mockCTLogClient{
		searchResults: []CTLogEntry{{ID: 123}},
		certificate:   generateTestCertificate("test"),
	}
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	cachedClient := NewCachedCTLogClient(mockClient, cache).(*cachedCTLogClient)
	
	// Test TTL configuration
	cachedClient = cachedClient.WithSearchTTL(30 * time.Minute)
	cachedClient = cachedClient.WithCertificateTTL(2 * time.Hour)
	
	if cachedClient.searchTTL != 30*time.Minute {
		t.Errorf("WithSearchTTL() searchTTL = %v, want 30m", cachedClient.searchTTL)
	}
	if cachedClient.certTTL != 2*time.Hour {
		t.Errorf("WithCertificateTTL() certTTL = %v, want 2h", cachedClient.certTTL)
	}
}

func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	cache := NewMemoryCache()
	defer cache.(*memoryCache).Close()
	
	done := make(chan bool)
	
	// Start multiple goroutines doing concurrent operations
	for i := 0; i < 10; i++ {
		go func(id int) {
			issuer := "issuer" + string(rune(id))
			entries := []CTLogEntry{{ID: id}}
			
			// Set and get operations
			cache.SetSearchResults(issuer, entries, 1*time.Hour)
			cache.GetSearchResults(issuer)
			
			cache.SetCertificate(id, generateTestCertificate("test"), 1*time.Hour)
			cache.GetCertificate(id)
			
			done <- true
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	
	// Verify cache has expected number of entries
	if cache.Size() != 20 { // 10 search + 10 cert entries
		t.Errorf("cache.Size() = %d, want 20", cache.Size())
	}
}