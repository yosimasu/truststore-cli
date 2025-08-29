package client

import (
	"crypto/x509"
	"sync"
	"time"
)

// Cache interface moved to interface.go

// CacheStats provides cache performance metrics
type CacheStats struct {
	Hits        int64
	Misses      int64
	Entries     int
	LastCleanup time.Time
}

// cacheEntry represents a single cache entry with TTL
type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

// isExpired checks if the cache entry has expired
func (e *cacheEntry) isExpired() bool {
	return time.Now().After(e.expiresAt)
}

// memoryCache implements Cache using in-memory storage with TTL
type memoryCache struct {
	mu             sync.RWMutex
	searchEntries  map[string]*cacheEntry
	certEntries    map[int]*cacheEntry
	stats          CacheStats
	cleanupTicker  *time.Ticker
	done           chan bool
}

// NewMemoryCache creates a new memory-based cache with automatic cleanup
func NewMemoryCache() Cache {
	cache := &memoryCache{
		searchEntries: make(map[string]*cacheEntry),
		certEntries:   make(map[int]*cacheEntry),
		done:          make(chan bool),
	}
	
	// Start cleanup goroutine
	cache.startCleanup()
	
	return cache
}

// startCleanup starts the background cleanup goroutine
func (c *memoryCache) startCleanup() {
	c.cleanupTicker = time.NewTicker(5 * time.Minute)
	
	go func() {
		for {
			select {
			case <-c.cleanupTicker.C:
				c.cleanup()
			case <-c.done:
				return
			}
		}
	}()
}

// cleanup removes expired entries
func (c *memoryCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	
	// Clean up search entries
	for key, entry := range c.searchEntries {
		if entry.isExpired() {
			delete(c.searchEntries, key)
		}
	}
	
	// Clean up certificate entries
	for key, entry := range c.certEntries {
		if entry.isExpired() {
			delete(c.certEntries, key)
		}
	}
	
	c.stats.LastCleanup = now
}

// Close stops the cleanup goroutine
func (c *memoryCache) Close() {
	if c.cleanupTicker != nil {
		c.cleanupTicker.Stop()
	}
	close(c.done)
}

// GetSearchResults retrieves cached search results for an issuer
func (c *memoryCache) GetSearchResults(issuer string) ([]CTLogEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.searchEntries[issuer]
	if !exists || entry.isExpired() {
		c.stats.Misses++
		return nil, false
	}
	
	c.stats.Hits++
	if results, ok := entry.value.([]CTLogEntry); ok {
		return results, true
	}
	
	// Invalid entry type, remove it
	delete(c.searchEntries, issuer)
	return nil, false
}

// SetSearchResults caches search results for an issuer
func (c *memoryCache) SetSearchResults(issuer string, entries []CTLogEntry, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.searchEntries[issuer] = &cacheEntry{
		value:     entries,
		expiresAt: time.Now().Add(ttl),
	}
}

// GetCertificate retrieves a cached certificate by ID
func (c *memoryCache) GetCertificate(id int) (*x509.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.certEntries[id]
	if !exists || entry.isExpired() {
		c.stats.Misses++
		return nil, false
	}
	
	c.stats.Hits++
	if cert, ok := entry.value.(*x509.Certificate); ok {
		return cert, true
	}
	
	// Invalid entry type, remove it
	delete(c.certEntries, id)
	return nil, false
}

// SetCertificate caches a certificate by ID
func (c *memoryCache) SetCertificate(id int, cert *x509.Certificate, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.certEntries[id] = &cacheEntry{
		value:     cert,
		expiresAt: time.Now().Add(ttl),
	}
}

// Clear removes all cached entries
func (c *memoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.searchEntries = make(map[string]*cacheEntry)
	c.certEntries = make(map[int]*cacheEntry)
	c.stats = CacheStats{}
}

// Size returns the number of cached items
func (c *memoryCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return len(c.searchEntries) + len(c.certEntries)
}

// GetStats returns cache performance statistics
func (c *memoryCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	stats := c.stats
	stats.Entries = len(c.searchEntries) + len(c.certEntries)
	return stats
}

// cachedCTLogClient wraps a CTLogClient with caching capabilities
type cachedCTLogClient struct {
	client     CTLogClient
	cache      Cache
	searchTTL  time.Duration
	certTTL    time.Duration
}

// NewCachedCTLogClient creates a cached CT log client wrapper
func NewCachedCTLogClient(client CTLogClient, cache Cache) CTLogClient {
	return &cachedCTLogClient{
		client:    client,
		cache:     cache,
		searchTTL: 15 * time.Minute, // Search results cached for 15 minutes
		certTTL:   1 * time.Hour,    // Certificates cached for 1 hour
	}
}

// WithSearchTTL sets the TTL for search result caching
func (c *cachedCTLogClient) WithSearchTTL(ttl time.Duration) *cachedCTLogClient {
	c.searchTTL = ttl
	return c
}

// WithCertificateTTL sets the TTL for certificate caching
func (c *cachedCTLogClient) WithCertificateTTL(ttl time.Duration) *cachedCTLogClient {
	c.certTTL = ttl
	return c
}

// SearchCertificatesByIssuer searches for certificates with caching
func (c *cachedCTLogClient) SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error) {
	// Check cache first
	if entries, found := c.cache.GetSearchResults(issuerName); found {
		return entries, nil
	}
	
	// Cache miss, fetch from underlying client
	entries, err := c.client.SearchCertificatesByIssuer(issuerName)
	if err != nil {
		return nil, err
	}
	
	// Cache the results
	c.cache.SetSearchResults(issuerName, entries, c.searchTTL)
	
	return entries, nil
}

// DownloadCertificate downloads certificates with caching
func (c *cachedCTLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	// Check cache first
	if cert, found := c.cache.GetCertificate(id); found {
		return cert, nil
	}
	
	// Cache miss, fetch from underlying client
	cert, err := c.client.DownloadCertificate(id)
	if err != nil {
		return nil, err
	}
	
	// Cache the certificate
	c.cache.SetCertificate(id, cert, c.certTTL)
	
	return cert, nil
}