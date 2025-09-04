package client

import (
	"context"
	"net"
	"net/http"
	"time"
)

// NetworkConnectivity provides utilities for network connectivity detection
type NetworkConnectivity struct {
	timeout       time.Duration
	fallbackHosts []string
}

// NewNetworkConnectivity creates a new network connectivity checker
func NewNetworkConnectivity() *NetworkConnectivity {
	return &NetworkConnectivity{
		timeout: 5 * time.Second,
		fallbackHosts: []string{
			"8.8.8.8:53",        // Google DNS
			"1.1.1.1:53",        // Cloudflare DNS
			"208.67.222.222:53", // OpenDNS
		},
	}
}

// WithTimeout sets the timeout for connectivity checks
func (nc *NetworkConnectivity) WithTimeout(timeout time.Duration) *NetworkConnectivity {
	nc.timeout = timeout
	return nc
}

// WithFallbackHosts sets custom fallback hosts for connectivity checks
func (nc *NetworkConnectivity) WithFallbackHosts(hosts []string) *NetworkConnectivity {
	nc.fallbackHosts = hosts
	return nc
}

// IsOnline checks if the system has network connectivity
func (nc *NetworkConnectivity) IsOnline() bool {
	return nc.IsOnlineWithContext(context.Background())
}

// IsOnlineWithContext checks network connectivity with context
func (nc *NetworkConnectivity) IsOnlineWithContext(ctx context.Context) bool {
	// Try to connect to fallback hosts
	for _, host := range nc.fallbackHosts {
		if nc.canConnect(ctx, host) {
			return true
		}
	}
	return false
}

// CanReachHost checks if a specific host is reachable
func (nc *NetworkConnectivity) CanReachHost(host string) bool {
	return nc.CanReachHostWithContext(context.Background(), host)
}

// CanReachHostWithContext checks if a host is reachable with context
func (nc *NetworkConnectivity) CanReachHostWithContext(ctx context.Context, host string) bool {
	return nc.canConnect(ctx, host)
}

// CanReachURL checks if a URL is reachable via HTTP
func (nc *NetworkConnectivity) CanReachURL(url string) bool {
	return nc.CanReachURLWithContext(context.Background(), url)
}

// CanReachURLWithContext checks if a URL is reachable via HTTP with context
func (nc *NetworkConnectivity) CanReachURLWithContext(ctx context.Context, url string) bool {
	client := &http.Client{Timeout: nc.timeout}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()

	// Consider any response (even errors) as connectivity
	return true
}

// GetConnectivityStatus returns detailed connectivity status
func (nc *NetworkConnectivity) GetConnectivityStatus() ConnectivityStatus {
	return nc.GetConnectivityStatusWithContext(context.Background())
}

// GetConnectivityStatusWithContext returns detailed connectivity status with context
func (nc *NetworkConnectivity) GetConnectivityStatusWithContext(ctx context.Context) ConnectivityStatus {
	status := ConnectivityStatus{
		Online:         false,
		HostsChecked:   len(nc.fallbackHosts),
		ReachableHosts: make([]string, 0),
	}

	for _, host := range nc.fallbackHosts {
		if nc.canConnect(ctx, host) {
			status.Online = true
			status.ReachableHosts = append(status.ReachableHosts, host)
		}
	}

	return status
}

// canConnect attempts to connect to a host
func (nc *NetworkConnectivity) canConnect(ctx context.Context, host string) bool {
	dialer := &net.Dialer{Timeout: nc.timeout}

	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return false
	}

	if err := conn.Close(); err != nil {
		// Log but don't fail - connectivity test already succeeded
		_ = err
	}
	return true
}

// ConnectivityStatus represents the network connectivity status
type ConnectivityStatus struct {
	Online         bool     // Whether any connectivity was detected
	HostsChecked   int      // Number of hosts checked
	ReachableHosts []string // List of reachable hosts
}

// FallbackConfig provides configuration for graceful fallbacks
type FallbackConfig struct {
	EnableOfflineMode bool          // Whether to enable offline mode
	OfflineTimeout    time.Duration // How long to wait before switching to offline mode
	RetryInterval     time.Duration // Interval between connectivity checks
	MaxRetries        int           // Maximum number of retry attempts
}

// DefaultFallbackConfig returns default fallback configuration
func DefaultFallbackConfig() *FallbackConfig {
	return &FallbackConfig{
		EnableOfflineMode: true,
		OfflineTimeout:    30 * time.Second,
		RetryInterval:     5 * time.Second,
		MaxRetries:        3,
	}
}

// FallbackManager manages graceful degradation when network is unavailable
type FallbackManager struct {
	connectivity *NetworkConnectivity
	config       *FallbackConfig
}

// NewFallbackManager creates a new fallback manager
func NewFallbackManager(config *FallbackConfig) *FallbackManager {
	if config == nil {
		config = DefaultFallbackConfig()
	}

	return &FallbackManager{
		connectivity: NewNetworkConnectivity(),
		config:       config,
	}
}

// WithConnectivity sets a custom connectivity checker
func (fm *FallbackManager) WithConnectivity(nc *NetworkConnectivity) *FallbackManager {
	fm.connectivity = nc
	return fm
}

// ShouldUseOfflineMode determines if offline mode should be used
func (fm *FallbackManager) ShouldUseOfflineMode(ctx context.Context) bool {
	if !fm.config.EnableOfflineMode {
		return false
	}

	// Check connectivity with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, fm.config.OfflineTimeout)
	defer cancel()

	return !fm.connectivity.IsOnlineWithContext(timeoutCtx)
}

// WaitForConnectivity waits for network connectivity with retries
func (fm *FallbackManager) WaitForConnectivity(ctx context.Context) error {
	for attempt := 0; attempt < fm.config.MaxRetries; attempt++ {
		if fm.connectivity.IsOnlineWithContext(ctx) {
			return nil
		}

		if attempt < fm.config.MaxRetries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(fm.config.RetryInterval):
				continue
			}
		}
	}

	return NewNetworkError("network connectivity not available after retries")
}

// NewNetworkError creates a network connectivity error
func NewNetworkError(message string) *HTTPError {
	return &HTTPError{
		Type:      ErrorTypeNetwork,
		Message:   message,
		Retryable: true,
	}
}
