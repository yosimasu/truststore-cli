package client

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"
)

// CTLogClient provides access to Certificate Transparency logs
// This interface supports dependency injection for testing and different implementations
type CTLogClient interface {
	// SearchCertificatesByIssuer searches for certificates by issuer common name
	SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error)
	// DownloadCertificate downloads a certificate by its crt.sh ID
	DownloadCertificate(id int) (*x509.Certificate, error)
}

// HTTPClient provides a generic HTTP client interface for dependency injection and testing
type HTTPClient interface {
	// Get performs a GET request
	Get(url string) (*http.Response, error)
	// GetWithContext performs a GET request with context
	GetWithContext(ctx context.Context, url string) (*http.Response, error)
}

// Cache provides a generic caching interface for CT log responses
type Cache interface {
	// GetSearchResults retrieves cached search results for an issuer
	GetSearchResults(issuer string) ([]CTLogEntry, bool)
	// SetSearchResults caches search results for an issuer
	SetSearchResults(issuer string, entries []CTLogEntry, ttl time.Duration)
	// GetCertificate retrieves a cached certificate by ID
	GetCertificate(id int) (*x509.Certificate, bool)
	// SetCertificate caches a certificate by ID
	SetCertificate(id int, cert *x509.Certificate, ttl time.Duration)
	// Clear removes all cached entries
	Clear()
	// Size returns the number of cached items
	Size() int
}

// NetworkConnectivityChecker provides network connectivity detection
type NetworkConnectivityChecker interface {
	// IsOnline checks if the system has network connectivity
	IsOnline() bool
	// IsOnlineWithContext checks network connectivity with context
	IsOnlineWithContext(ctx context.Context) bool
	// CanReachHost checks if a specific host is reachable
	CanReachHost(host string) bool
	// CanReachURL checks if a URL is reachable via HTTP
	CanReachURL(url string) bool
	// GetConnectivityStatus returns detailed connectivity status
	GetConnectivityStatus() ConnectivityStatus
}

// FallbackHandler manages graceful degradation when network is unavailable
type FallbackHandler interface {
	// ShouldUseOfflineMode determines if offline mode should be used
	ShouldUseOfflineMode(ctx context.Context) bool
	// WaitForConnectivity waits for network connectivity with retries
	WaitForConnectivity(ctx context.Context) error
}

// ResilientCTLogClient combines CTLogClient with network resilience features
type ResilientCTLogClient interface {
	CTLogClient
	// SearchWithFallback searches with graceful degradation
	SearchWithFallback(ctx context.Context, issuerName string) ([]CTLogEntry, error)
	// DownloadWithFallback downloads with graceful degradation  
	DownloadWithFallback(ctx context.Context, id int) (*x509.Certificate, error)
	// GetNetworkStatus returns current network connectivity status
	GetNetworkStatus() ConnectivityStatus
}