package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"
)

// resilientCTLogClient implements ResilientCTLogClient with caching, fallback, and connectivity detection
type resilientCTLogClient struct {
	client       CTLogClient
	cache        Cache
	connectivity NetworkConnectivityChecker
	fallback     FallbackHandler
	config       *ResilientConfig
}

// ResilientConfig configures resilient client behavior
type ResilientConfig struct {
	// EnableCaching enables response caching
	EnableCaching bool
	// SearchCacheTTL is the TTL for search result caching
	SearchCacheTTL time.Duration
	// CertCacheTTL is the TTL for certificate caching
	CertCacheTTL time.Duration
	// EnableOfflineFallback enables offline fallback mode
	EnableOfflineFallback bool
	// ConnectivityCheckTimeout timeout for connectivity checks
	ConnectivityCheckTimeout time.Duration
	// MaxOfflineRetries maximum retries when offline
	MaxOfflineRetries int
}

// DefaultResilientConfig returns a default resilient client configuration
func DefaultResilientConfig() *ResilientConfig {
	return &ResilientConfig{
		EnableCaching:            true,
		SearchCacheTTL:           15 * time.Minute,
		CertCacheTTL:             1 * time.Hour,
		EnableOfflineFallback:    true,
		ConnectivityCheckTimeout: 5 * time.Second,
		MaxOfflineRetries:        3,
	}
}

// NewResilientCTLogClient creates a new resilient CT log client with all features
func NewResilientCTLogClient(baseClient CTLogClient, config *ResilientConfig) ResilientCTLogClient {
	if config == nil {
		config = DefaultResilientConfig()
	}

	client := &resilientCTLogClient{
		client:       baseClient,
		connectivity: NewNetworkConnectivity(),
		config:       config,
	}

	// Set up caching if enabled
	if config.EnableCaching {
		cache := NewMemoryCache()
		cachedClient := NewCachedCTLogClient(baseClient, cache).(*cachedCTLogClient)
		cachedClient.WithSearchTTL(config.SearchCacheTTL)
		cachedClient.WithCertificateTTL(config.CertCacheTTL)
		client.client = cachedClient
		client.cache = cache
	}

	// Set up fallback handling if enabled
	if config.EnableOfflineFallback {
		fallbackConfig := &FallbackConfig{
			EnableOfflineMode: true,
			OfflineTimeout:    config.ConnectivityCheckTimeout,
			MaxRetries:        config.MaxOfflineRetries,
		}
		client.fallback = NewFallbackManager(fallbackConfig)
	}

	return client
}

// SearchCertificatesByIssuer implements basic CTLogClient interface
func (r *resilientCTLogClient) SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error) {
	return r.SearchWithFallback(context.Background(), issuerName)
}

// DownloadCertificate implements basic CTLogClient interface
func (r *resilientCTLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	return r.DownloadWithFallback(context.Background(), id)
}

// SearchWithFallback searches with graceful degradation
func (r *resilientCTLogClient) SearchWithFallback(ctx context.Context, issuerName string) ([]CTLogEntry, error) {
	// If caching is enabled, try cache first
	if r.cache != nil {
		if results, found := r.cache.GetSearchResults(issuerName); found {
			return results, nil
		}
	}

	// Check connectivity if fallback is enabled
	if r.fallback != nil && r.fallback.ShouldUseOfflineMode(ctx) {
		return nil, NewNetworkError("offline mode: network connectivity unavailable for certificate search")
	}

	// Attempt network request
	return r.client.SearchCertificatesByIssuer(issuerName)
}

// DownloadWithFallback downloads with graceful degradation
func (r *resilientCTLogClient) DownloadWithFallback(ctx context.Context, id int) (*x509.Certificate, error) {
	// If caching is enabled, try cache first
	if r.cache != nil {
		if cert, found := r.cache.GetCertificate(id); found {
			return cert, nil
		}
	}

	// Check connectivity if fallback is enabled
	if r.fallback != nil && r.fallback.ShouldUseOfflineMode(ctx) {
		return nil, NewNetworkError("offline mode: network connectivity unavailable for certificate download")
	}

	// Attempt network request
	return r.client.DownloadCertificate(id)
}

// GetNetworkStatus returns current network connectivity status
func (r *resilientCTLogClient) GetNetworkStatus() ConnectivityStatus {
	if r.connectivity == nil {
		return ConnectivityStatus{Online: true, HostsChecked: 0, ReachableHosts: []string{}}
	}
	return r.connectivity.GetConnectivityStatus()
}

// rateLimitedCTLogClient adds rate limiting to any CTLogClient
type rateLimitedCTLogClient struct {
	client      CTLogClient
	rateLimiter *RateLimiter
}

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	tokens     chan struct{}
	refillRate time.Duration
	done       chan bool
}

// NewRateLimiter creates a new rate limiter with specified rate
func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	if requestsPerSecond <= 0 {
		requestsPerSecond = 10 // Default to 10 requests per second
	}

	limiter := &RateLimiter{
		tokens:     make(chan struct{}, requestsPerSecond),
		refillRate: time.Second / time.Duration(requestsPerSecond),
		done:       make(chan bool),
	}

	// Fill initial tokens
	for i := 0; i < requestsPerSecond; i++ {
		limiter.tokens <- struct{}{}
	}

	// Start token refill goroutine
	go limiter.refillTokens()

	return limiter
}

// refillTokens continuously refills the token bucket
func (rl *RateLimiter) refillTokens() {
	ticker := time.NewTicker(rl.refillRate)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			select {
			case rl.tokens <- struct{}{}:
				// Token added
			default:
				// Bucket full, skip
			}
		case <-rl.done:
			return
		}
	}
}

// Wait waits for a token to become available
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-rl.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the rate limiter
func (rl *RateLimiter) Close() {
	close(rl.done)
}

// NewRateLimitedCTLogClient creates a rate-limited CT log client
func NewRateLimitedCTLogClient(client CTLogClient, requestsPerSecond int) CTLogClient {
	return &rateLimitedCTLogClient{
		client:      client,
		rateLimiter: NewRateLimiter(requestsPerSecond),
	}
}

// SearchCertificatesByIssuer implements rate-limited search
func (r *rateLimitedCTLogClient) SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error) {
	ctx := context.Background()
	if err := r.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit timeout: %w", err)
	}
	return r.client.SearchCertificatesByIssuer(issuerName)
}

// DownloadCertificate implements rate-limited download
func (r *rateLimitedCTLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	ctx := context.Background()
	if err := r.rateLimiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit timeout: %w", err)
	}
	return r.client.DownloadCertificate(id)
}

// NewFullyCTLogClient creates a CT log client with all resilience features enabled
func NewFullyCTLogClient() ResilientCTLogClient {
	// Start with base HTTP client with retry logic
	httpClient := NewHTTPClient(DefaultConfig())

	// Create basic CT log client
	baseClient := NewCTLogClientWithHTTPClient(httpClient)

	// Add rate limiting (10 requests per second to be respectful)
	rateLimitedClient := NewRateLimitedCTLogClient(baseClient, 10)

	// Wrap with resilient features (caching, fallback, connectivity)
	config := DefaultResilientConfig()
	resilientClient := NewResilientCTLogClient(rateLimitedClient, config)

	return resilientClient
}
