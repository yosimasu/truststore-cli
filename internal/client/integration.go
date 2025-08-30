package client

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// IntegrationTestConfig holds configuration for integration tests
type IntegrationTestConfig struct {
	// OnlineTestsEnabled controls whether online tests should run
	OnlineTestsEnabled bool
	// TestTimeout is the timeout for integration tests
	TestTimeout time.Duration
	// MockMode forces tests to use mock servers instead of live APIs
	MockMode bool
	// BaseURL overrides the default API base URL for testing
	BaseURL string
}

// DefaultIntegrationConfig returns default integration test configuration
func DefaultIntegrationConfig() *IntegrationTestConfig {
	config := &IntegrationTestConfig{
		OnlineTestsEnabled: true,
		TestTimeout:        30 * time.Second,
		MockMode:           false,
	}

	// Check environment variables
	if os.Getenv("OFFLINE_TESTS") == "true" || os.Getenv("CI") == "true" {
		config.OnlineTestsEnabled = false
	}

	if os.Getenv("MOCK_MODE") == "true" {
		config.MockMode = true
	}

	if baseURL := os.Getenv("TEST_BASE_URL"); baseURL != "" {
		config.BaseURL = baseURL
	}

	if timeout := os.Getenv("TEST_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.TestTimeout = d
		}
	}

	return config
}

// IntegrationTestSuite provides a framework for running integration tests
type IntegrationTestSuite struct {
	config     *IntegrationTestConfig
	httpClient HTTPClient
	mockServer *MockServer
	t          *testing.T
}

// NewIntegrationTestSuite creates a new integration test suite
func NewIntegrationTestSuite(t *testing.T, config *IntegrationTestConfig) *IntegrationTestSuite {
	if config == nil {
		config = DefaultIntegrationConfig()
	}

	suite := &IntegrationTestSuite{
		config: config,
		t:      t,
	}

	// Create HTTP client
	clientConfig := &Config{
		Timeout:    config.TestTimeout,
		MaxRetries: 1, // Reduced retries for tests
		BaseDelay:  10 * time.Millisecond,
		MaxDelay:   100 * time.Millisecond,
	}
	suite.httpClient = NewHTTPClient(clientConfig)

	return suite
}

// SkipIfOffline skips the test if online tests are disabled
func (s *IntegrationTestSuite) SkipIfOffline() {
	if !s.config.OnlineTestsEnabled {
		s.t.Skip("Skipping online test (OFFLINE_TESTS=true or CI=true)")
	}
}

// SkipIfOnline skips the test if running in online mode (useful for mock-only tests)
func (s *IntegrationTestSuite) SkipIfOnline() {
	if s.config.OnlineTestsEnabled && !s.config.MockMode {
		s.t.Skip("Skipping offline-only test")
	}
}

// SetupMockServer creates and starts a mock server for testing
func (s *IntegrationTestSuite) SetupMockServer(config MockServerConfig) {
	s.mockServer = NewMockServer(config)
}

// SetupCTLogMockServer creates a CT log specific mock server
func (s *IntegrationTestSuite) SetupCTLogMockServer() {
	ctLogMock := NewCTLogMockServer()
	s.mockServer = ctLogMock.MockServer
}

// TearDown cleans up test resources
func (s *IntegrationTestSuite) TearDown() {
	if s.mockServer != nil {
		s.mockServer.Close()
	}
}

// HTTPClient returns the configured HTTP client
func (s *IntegrationTestSuite) HTTPClient() HTTPClient {
	return s.httpClient
}

// MockServerURL returns the mock server URL (only available after SetupMockServer)
func (s *IntegrationTestSuite) MockServerURL() string {
	if s.mockServer == nil {
		return ""
	}
	return s.mockServer.URL
}

// BaseURL returns the base URL to use for tests
func (s *IntegrationTestSuite) BaseURL(defaultURL string) string {
	// Priority: 1. Explicit config BaseURL, 2. Mock server URL, 3. Default URL
	if s.config.BaseURL != "" {
		return s.config.BaseURL
	}
	if s.mockServer != nil && s.config.MockMode {
		return s.mockServer.URL
	}
	return defaultURL
}

// IsOnlineMode returns true if tests should run against live APIs
func (s *IntegrationTestSuite) IsOnlineMode() bool {
	return s.config.OnlineTestsEnabled && !s.config.MockMode
}

// IsMockMode returns true if tests should use mock servers
func (s *IntegrationTestSuite) IsMockMode() bool {
	return s.config.MockMode || s.mockServer != nil
}

// TestNetworkConnectivity tests if network connectivity is available
func (s *IntegrationTestSuite) TestNetworkConnectivity(url string) bool {
	if s.config.MockMode {
		return true // Always available in mock mode
	}

	// Try a simple HTTP request with short timeout
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	
	return resp.StatusCode < 500
}

// RunOnlineTest runs a test only if online mode is enabled
func (s *IntegrationTestSuite) RunOnlineTest(name string, testFunc func(t *testing.T)) {
	s.t.Run(name+"_online", func(t *testing.T) {
		if !s.config.OnlineTestsEnabled {
			t.Skip("Skipping online test")
		}
		testFunc(t)
	})
}

// RunOfflineTest runs a test only if offline mode is enabled or mock server is available
func (s *IntegrationTestSuite) RunOfflineTest(name string, testFunc func(t *testing.T)) {
	s.t.Run(name+"_offline", func(t *testing.T) {
		if s.config.OnlineTestsEnabled && s.mockServer == nil {
			t.Skip("Skipping offline test (no mock server configured)")
		}
		testFunc(t)
	})
}

// RunBothModes runs a test in both online and offline modes if available
func (s *IntegrationTestSuite) RunBothModes(name string, testFunc func(t *testing.T, suite *IntegrationTestSuite)) {
	// Online test
	if s.config.OnlineTestsEnabled {
		s.t.Run(name+"_online", func(t *testing.T) {
			onlineSuite := NewIntegrationTestSuite(t, s.config)
			defer onlineSuite.TearDown()
			testFunc(t, onlineSuite)
		})
	}

	// Offline test with mock server
	s.t.Run(name+"_offline", func(t *testing.T) {
		offlineConfig := *s.config
		offlineConfig.OnlineTestsEnabled = false
		offlineConfig.MockMode = true
		
		offlineSuite := NewIntegrationTestSuite(t, &offlineConfig)
		offlineSuite.SetupCTLogMockServer()
		defer offlineSuite.TearDown()
		
		testFunc(t, offlineSuite)
	})
}

// AssertResponseHeaders checks common response headers
func (s *IntegrationTestSuite) AssertResponseHeaders(resp *http.Response, expectedHeaders map[string]string) {
	for key, expectedValue := range expectedHeaders {
		actualValue := resp.Header.Get(key)
		if expectedValue != "" && actualValue == "" {
			s.t.Errorf("Expected header %s to be present", key)
		}
		if expectedValue != "" && !strings.Contains(actualValue, expectedValue) {
			s.t.Errorf("Expected header %s to contain %q, got %q", key, expectedValue, actualValue)
		}
	}
}

// AssertNoError is a helper to assert no error occurred
func (s *IntegrationTestSuite) AssertNoError(err error) {
	if err != nil {
		s.t.Fatalf("Expected no error, got: %v", err)
	}
}

// AssertError is a helper to assert an error occurred
func (s *IntegrationTestSuite) AssertError(err error, msgPrefix string) {
	if err == nil {
		s.t.Fatalf("Expected error with prefix %q, got nil", msgPrefix)
	}
	if !strings.Contains(err.Error(), msgPrefix) {
		s.t.Errorf("Expected error to contain %q, got %q", msgPrefix, err.Error())
	}
}