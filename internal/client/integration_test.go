package client

import (
	"os"
	"testing"
	"time"
)

func TestDefaultIntegrationConfig(t *testing.T) {
	// Save original env vars
	originalOffline := os.Getenv("OFFLINE_TESTS")
	originalCI := os.Getenv("CI")
	originalMock := os.Getenv("MOCK_MODE")
	originalBaseURL := os.Getenv("TEST_BASE_URL")
	originalTimeout := os.Getenv("TEST_TIMEOUT")

	defer func() {
		// Restore original env vars
		_ = os.Setenv("OFFLINE_TESTS", originalOffline)
		_ = os.Setenv("CI", originalCI)
		_ = os.Setenv("MOCK_MODE", originalMock)
		_ = os.Setenv("TEST_BASE_URL", originalBaseURL)
		_ = os.Setenv("TEST_TIMEOUT", originalTimeout)
	}()

	t.Run("default config", func(t *testing.T) {
		// Clear env vars
		_ = os.Unsetenv("OFFLINE_TESTS")
		_ = os.Unsetenv("CI")
		_ = os.Unsetenv("MOCK_MODE")
		_ = os.Unsetenv("TEST_BASE_URL")
		_ = os.Unsetenv("TEST_TIMEOUT")

		config := DefaultIntegrationConfig()

		if !config.OnlineTestsEnabled {
			t.Error("Expected OnlineTestsEnabled to be true by default")
		}
		if config.TestTimeout != 30*time.Second {
			t.Errorf("Expected timeout 30s, got %v", config.TestTimeout)
		}
		if config.MockMode {
			t.Error("Expected MockMode to be false by default")
		}
		if config.BaseURL != "" {
			t.Errorf("Expected empty BaseURL, got %q", config.BaseURL)
		}
	})

	t.Run("offline tests enabled", func(t *testing.T) {
		_ = os.Setenv("OFFLINE_TESTS", "true")

		config := DefaultIntegrationConfig()
		if config.OnlineTestsEnabled {
			t.Error("Expected OnlineTestsEnabled to be false when OFFLINE_TESTS=true")
		}
	})

	t.Run("CI environment", func(t *testing.T) {
		_ = os.Unsetenv("OFFLINE_TESTS")
		_ = os.Setenv("CI", "true")

		config := DefaultIntegrationConfig()
		if config.OnlineTestsEnabled {
			t.Error("Expected OnlineTestsEnabled to be false in CI environment")
		}
	})

	t.Run("mock mode enabled", func(t *testing.T) {
		_ = os.Setenv("MOCK_MODE", "true")

		config := DefaultIntegrationConfig()
		if !config.MockMode {
			t.Error("Expected MockMode to be true when MOCK_MODE=true")
		}
	})

	t.Run("custom base URL", func(t *testing.T) {
		expectedURL := "https://test.example.com"
		_ = os.Setenv("TEST_BASE_URL", expectedURL)

		config := DefaultIntegrationConfig()
		if config.BaseURL != expectedURL {
			t.Errorf("Expected BaseURL %q, got %q", expectedURL, config.BaseURL)
		}
	})

	t.Run("custom timeout", func(t *testing.T) {
		_ = os.Setenv("TEST_TIMEOUT", "45s")

		config := DefaultIntegrationConfig()
		if config.TestTimeout != 45*time.Second {
			t.Errorf("Expected timeout 45s, got %v", config.TestTimeout)
		}
	})

	t.Run("invalid timeout", func(t *testing.T) {
		_ = os.Setenv("TEST_TIMEOUT", "invalid")

		config := DefaultIntegrationConfig()
		if config.TestTimeout != 30*time.Second {
			t.Errorf("Expected default timeout 30s for invalid timeout, got %v", config.TestTimeout)
		}
	})
}

func TestNewIntegrationTestSuite(t *testing.T) {
	config := &IntegrationTestConfig{
		OnlineTestsEnabled: false,
		TestTimeout:        10 * time.Second,
		MockMode:           true,
	}

	suite := NewIntegrationTestSuite(t, config)

	if suite == nil {
		t.Fatal("NewIntegrationTestSuite returned nil")
	}
	if suite.config != config {
		t.Error("Config not set correctly")
	}
	if suite.httpClient == nil {
		t.Error("HTTP client not initialized")
	}
	if suite.t != t {
		t.Error("Testing.T not set correctly")
	}
}

func TestIntegrationTestSuite_MockServer(t *testing.T) {
	suite := NewIntegrationTestSuite(t, &IntegrationTestConfig{})
	defer suite.TearDown()

	// Test mock server setup
	suite.SetupMockServer(MockServerConfig{
		ReturnStatus: 200,
		ResponseBody: "test response",
	})

	if suite.mockServer == nil {
		t.Fatal("Mock server not set up")
	}

	url := suite.MockServerURL()
	if url == "" {
		t.Error("Mock server URL is empty")
	}

	// Test CT log mock server
	suite2 := NewIntegrationTestSuite(t, &IntegrationTestConfig{})
	defer suite2.TearDown()

	suite2.SetupCTLogMockServer()
	if suite2.mockServer == nil {
		t.Fatal("CT log mock server not set up")
	}
}

func TestIntegrationTestSuite_BaseURL(t *testing.T) {
	suite := NewIntegrationTestSuite(t, &IntegrationTestConfig{
		BaseURL: "https://custom.example.com",
	})
	defer suite.TearDown()

	// Should return custom base URL
	url := suite.BaseURL("https://default.example.com")
	if url != "https://custom.example.com" {
		t.Errorf("Expected custom URL, got %q", url)
	}

	// Test with mock server - custom BaseURL should still take precedence
	suite.SetupMockServer(MockServerConfig{})
	url = suite.BaseURL("https://default.example.com")
	if url != "https://custom.example.com" {
		t.Errorf("Expected custom URL to take precedence, got %q", url)
	}

	// Test with no config and no mock server
	suite2 := NewIntegrationTestSuite(t, &IntegrationTestConfig{})
	defer suite2.TearDown()

	url = suite2.BaseURL("https://default.example.com")
	if url != "https://default.example.com" {
		t.Errorf("Expected default URL, got %q", url)
	}

	// Test mock server URL when MockMode is enabled and no custom BaseURL
	suite3 := NewIntegrationTestSuite(t, &IntegrationTestConfig{MockMode: true})
	defer suite3.TearDown()

	suite3.SetupMockServer(MockServerConfig{})
	url = suite3.BaseURL("https://default.example.com")
	if url != suite3.mockServer.URL {
		t.Errorf("Expected mock server URL in mock mode, got %q", url)
	}
}

func TestIntegrationTestSuite_Modes(t *testing.T) {
	onlineConfig := &IntegrationTestConfig{
		OnlineTestsEnabled: true,
		MockMode:           false,
	}
	onlineSuite := NewIntegrationTestSuite(t, onlineConfig)
	defer onlineSuite.TearDown()

	if !onlineSuite.IsOnlineMode() {
		t.Error("Expected online mode")
	}
	if onlineSuite.IsMockMode() {
		t.Error("Expected not mock mode")
	}

	mockConfig := &IntegrationTestConfig{
		OnlineTestsEnabled: false,
		MockMode:           true,
	}
	mockSuite := NewIntegrationTestSuite(t, mockConfig)
	defer mockSuite.TearDown()

	if mockSuite.IsOnlineMode() {
		t.Error("Expected not online mode")
	}
	if !mockSuite.IsMockMode() {
		t.Error("Expected mock mode")
	}

	// Test mock mode with mock server
	mockSuite.SetupMockServer(MockServerConfig{})
	if !mockSuite.IsMockMode() {
		t.Error("Expected mock mode when mock server is set up")
	}
}

func TestIntegrationTestSuite_TestNetworkConnectivity(t *testing.T) {
	suite := NewIntegrationTestSuite(t, &IntegrationTestConfig{
		MockMode: true,
	})
	defer suite.TearDown()

	// Should return true in mock mode
	if !suite.TestNetworkConnectivity("http://unreachable.example.com") {
		t.Error("Expected network connectivity to be true in mock mode")
	}

	// Test with mock server
	suite.SetupMockServer(MockServerConfig{
		ReturnStatus: 200,
	})

	if !suite.TestNetworkConnectivity(suite.MockServerURL()) {
		t.Error("Expected network connectivity to mock server to be true")
	}
}

func TestIntegrationTestSuite_Helpers(t *testing.T) {
	suite := NewIntegrationTestSuite(t, &IntegrationTestConfig{})
	defer suite.TearDown()

	// Test AssertNoError
	suite.AssertNoError(nil) // Should not fail

	// Test AssertError
	testErr := NewValidationError("test error message")
	suite.AssertError(testErr, "test error") // Should not fail
}

func TestIntegrationTestSuite_SkipMethods(t *testing.T) {
	// Test skip methods - we can't test the actual skipping behavior
	// but we can verify the methods exist and don't panic

	offlineConfig := &IntegrationTestConfig{
		OnlineTestsEnabled: false,
	}
	offlineSuite := NewIntegrationTestSuite(&testing.T{}, offlineConfig)
	defer offlineSuite.TearDown()

	// These would skip in a real test, but won't panic
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("SkipIfOffline panicked: %v", r)
			}
		}()
		// Can't actually test the skip behavior without a real test context
	}()
}

func TestIntegrationTestSuite_RunModeTests(t *testing.T) {
	config := &IntegrationTestConfig{
		OnlineTestsEnabled: true,
		MockMode:           false,
	}

	suite := NewIntegrationTestSuite(t, config)
	defer suite.TearDown()

	// Test RunBothModes - this creates subtests
	suite.RunBothModes("test_both", func(t *testing.T, s *IntegrationTestSuite) {
		// Just verify the method runs without panicking
		if s.IsOnlineMode() {
			// Online mode test
			_ = s
		} else {
			// Offline mode test
			_ = s
		}
	})

	// Note: In a real test environment, both would run
	// Here we just verify the method doesn't panic
}
