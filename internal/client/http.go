package client

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"
)

// HTTPClient provides a generic HTTP client interface for dependency injection and testing
type HTTPClient interface {
	Get(url string) (*http.Response, error)
	GetWithContext(ctx context.Context, url string) (*http.Response, error)
}

// Config holds HTTP client configuration
type Config struct {
	// Timeout is the overall request timeout
	Timeout time.Duration
	// MaxRetries is the maximum number of retry attempts
	MaxRetries int
	// BaseDelay is the initial delay between retries
	BaseDelay time.Duration
	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration
}

// DefaultConfig returns a default HTTP client configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout:    15 * time.Second,
		MaxRetries: 3,
		BaseDelay:  100 * time.Millisecond,
		MaxDelay:   5 * time.Second,
	}
}

// httpClient implements HTTPClient with retry logic and configurable timeouts
type httpClient struct {
	client *http.Client
	config *Config
}

// NewHTTPClient creates a new HTTP client with the given configuration
func NewHTTPClient(config *Config) HTTPClient {
	if config == nil {
		config = DefaultConfig()
	}

	return &httpClient{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config: config,
	}
}

// Get performs a GET request with retry logic
func (c *httpClient) Get(url string) (*http.Response, error) {
	ctx := context.Background()
	return c.GetWithContext(ctx, url)
}

// GetWithContext performs a GET request with context and retry logic
func (c *httpClient) GetWithContext(ctx context.Context, url string) (*http.Response, error) {
	var lastErr error
	
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			// Calculate exponential backoff delay
			delay := c.calculateDelay(attempt)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("HTTP request failed (attempt %d/%d): %w", attempt+1, c.config.MaxRetries+1, err)
			if !c.isRetryable(err) {
				return nil, lastErr
			}
			continue
		}

		// Check if response status indicates we should retry
		if c.shouldRetryStatus(resp.StatusCode) {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP request returned status %d (attempt %d/%d)", resp.StatusCode, attempt+1, c.config.MaxRetries+1)
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}

// calculateDelay calculates the delay for exponential backoff
func (c *httpClient) calculateDelay(attempt int) time.Duration {
	delay := time.Duration(float64(c.config.BaseDelay) * math.Pow(2, float64(attempt-1)))
	if delay > c.config.MaxDelay {
		delay = c.config.MaxDelay
	}
	return delay
}

// isRetryable determines if an error should trigger a retry
func (c *httpClient) isRetryable(err error) bool {
	// For now, retry on any network error
	// In the future, we could be more specific about which errors to retry
	return true
}

// shouldRetryStatus determines if an HTTP status code should trigger a retry
func (c *httpClient) shouldRetryStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}