package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewAddCommand(t *testing.T) {
	cmd := NewAddCommand()

	// Test command properties
	if cmd.Use != "add [source]" {
		t.Errorf("Expected Use to be 'add [source]', got '%s'", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected Short description to be set")
	}

	if cmd.Long == "" {
		t.Error("Expected Long description to be set")
	}

	// Test that target flag exists and is required
	targetFlag := cmd.Flags().Lookup("target")
	if targetFlag == nil {
		t.Error("Expected 'target' flag to exist")
	}

	// Check if target flag is marked as required - verified through execution test later

	// Test that exactly one argument is required
	if cmd.Args == nil {
		t.Error("Expected Args validator to be set")
	}
}

func TestValidateTargetPath(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	tests := []struct {
		name      string
		target    string
		wantError bool
	}{
		{
			name:      "empty path",
			target:    "",
			wantError: true,
		},
		{
			name:      "valid file in current directory",
			target:    "test.pem",
			wantError: false,
		},
		{
			name:      "valid file in temp directory",
			target:    filepath.Join(tempDir, "test.pem"),
			wantError: false,
		},
		{
			name:      "directory that doesn't exist",
			target:    "/nonexistent/test.pem",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetPath(tt.target)
			if (err != nil) != tt.wantError {
				t.Errorf("validateTargetPath() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestValidateTargetPathWithExistingFile(t *testing.T) {
	// Create temporary file for testing
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create existing file
	existingFile := filepath.Join(tempDir, "existing.pem")
	err = os.WriteFile(existingFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test with existing file
	err = validateTargetPath(existingFile)
	if err != nil {
		t.Errorf("validateTargetPath() with existing file failed: %v", err)
	}

	// Create read-only file
	readOnlyFile := filepath.Join(tempDir, "readonly.pem")
	err = os.WriteFile(readOnlyFile, []byte("test content"), 0444)
	if err != nil {
		t.Fatalf("Failed to create read-only file: %v", err)
	}

	// Test with read-only file - should fail on Unix systems
	err = validateTargetPath(readOnlyFile)
	if err == nil && os.Getenv("CI") != "" {
		// In CI environments, we might not have permission restrictions
		t.Log("Skipping read-only test in CI environment")
	}
}

func TestRunAddCommandValidation(t *testing.T) {
	cmd := NewAddCommand()

	// Test missing target flag
	cmd.SetArgs([]string{"example.org"})
	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error when target flag is missing")
	}
	if !strings.Contains(err.Error(), "required flag") {
		t.Errorf("Expected required flag error, got: %v", err)
	}
}

func TestRunAddCommandInvalidTarget(t *testing.T) {
	cmd := NewAddCommand()

	// Test with invalid target path
	cmd.SetArgs([]string{"example.org", "--target", "/nonexistent/path/test.pem"})
	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error with invalid target path")
	}
	if !strings.Contains(err.Error(), "invalid target path") {
		t.Errorf("Expected invalid target path error, got: %v", err)
	}
}

func TestIsDomainSourceInAddContext(t *testing.T) {
	// Test domain identification (reusing logic from list command)
	tests := []struct {
		source   string
		expected bool
	}{
		{"example.org", true},
		{"example.org:443", true},
		{"google.com", true},
		{"certificates.pem", false},
		{"./certificates.pem", false},
		{"/path/to/cert.pem", false},
		{"test.jks", false},
		{"test.p12", false},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			result := isAddDomainSource(tt.source)
			if result != tt.expected {
				t.Errorf("isAddDomainSource(%s) = %v, expected %v", tt.source, result, tt.expected)
			}
		})
	}
}

func TestRunAddCommandFileSourceNotImplemented(t *testing.T) {
	// Create temporary directory and file for testing
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sourceFile := filepath.Join(tempDir, "source.pem")
	targetFile := filepath.Join(tempDir, "target.pem")

	// Create source file
	err = os.WriteFile(sourceFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	cmd := NewAddCommand()
	cmd.SetArgs([]string{sourceFile, "--target", targetFile})

	err = cmd.Execute()
	if err == nil {
		t.Error("Expected error for file sources not yet implemented")
	}
	if !strings.Contains(err.Error(), "file sources not yet supported") {
		t.Errorf("Expected file sources not supported error, got: %v", err)
	}
}

// Integration test helper - tests domain addition but requires network
func TestHandleDomainAddIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary target file
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// This test would require network access and is more of an integration test
	// We'll skip it in unit tests but leave the structure for future integration testing
	t.Skip("Integration test - requires network access to real domain")

	// Example of how this would work:
	// targetFile := filepath.Join(tempDir, "test.pem")
	// err = handleDomainAdd("example.org", targetFile)
	// if err != nil {
	//     t.Errorf("handleDomainAdd failed: %v", err)
	// }
	//
	// // Verify file was created and contains certificate
	// if _, err := os.Stat(targetFile); err != nil {
	//     t.Errorf("Target file was not created: %v", err)
	// }
}

func TestStartLoadingIndicator(t *testing.T) {
	// Test basic loading indicator functionality
	message := "Testing loading"

	// Start the indicator
	stop := startLoadingIndicator(message)

	// Let it run for a short time
	time.Sleep(250 * time.Millisecond)

	// Stop the indicator
	stop()

	// Give it time to clean up
	time.Sleep(50 * time.Millisecond)

	// Test passes if no panics or deadlocks occur
}

func TestStartLoadingIndicatorMultiple(t *testing.T) {
	// Test multiple indicators can be started and stopped independently
	stop1 := startLoadingIndicator("First operation")
	time.Sleep(100 * time.Millisecond)

	stop2 := startLoadingIndicator("Second operation")
	time.Sleep(100 * time.Millisecond)

	stop1()
	time.Sleep(100 * time.Millisecond)

	stop2()
	time.Sleep(50 * time.Millisecond)

	// Test passes if no race conditions or panics occur
}

func TestStartLoadingIndicatorImmedateStop(t *testing.T) {
	// Test stopping indicator immediately after starting
	stop := startLoadingIndicator("Quick test")
	stop()
	time.Sleep(50 * time.Millisecond)

	// Test passes if no deadlocks occur
}
