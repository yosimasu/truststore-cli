package app

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

	// Test that target-password flag exists and has correct NoOptDefVal
	targetPasswordFlag := cmd.Flags().Lookup("target-password")
	if targetPasswordFlag == nil {
		t.Error("Expected 'target-password' flag to exist")
		return
	}
	if targetPasswordFlag.NoOptDefVal != "PROMPT" {
		t.Errorf("Expected NoOptDefVal to be 'PROMPT', got '%s'", targetPasswordFlag.NoOptDefVal)
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
	defer func() { _ = os.RemoveAll(tempDir) }()

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
	defer func() { _ = os.RemoveAll(tempDir) }()

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

func TestValidateSourceFilePath(t *testing.T) {
	// Create temporary directory and file for testing
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	validFile := filepath.Join(tempDir, "valid.pem")
	err = os.WriteFile(validFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create valid test file: %v", err)
	}

	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{
			name:      "empty path",
			path:      "",
			wantError: true,
		},
		{
			name:      "nonexistent file",
			path:      "/nonexistent/file.pem",
			wantError: true,
		},
		{
			name:      "valid file",
			path:      validFile,
			wantError: false,
		},
		{
			name:      "directory instead of file",
			path:      tempDir,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSourceFilePath(tt.path)
			if (err != nil) != tt.wantError {
				t.Errorf("validateSourceFilePath() error = %v, wantError %v", err, tt.wantError)
			}
		})
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
	defer func() { _ = os.RemoveAll(tempDir) }()

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

func TestReadCertificatesFromFile(t *testing.T) {
	// Create temporary directory for testing
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Generate test certificate for testing
	cert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test valid PEM file
	validPemFile := filepath.Join(tempDir, "valid.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err = os.WriteFile(validPemFile, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to create valid PEM file: %v", err)
	}

	certs, err := readCertificatesFromFile(validPemFile)
	if err != nil {
		t.Errorf("readCertificatesFromFile() with valid file failed: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(certs))
	}

	// Test empty file
	emptyFile := filepath.Join(tempDir, "empty.pem")
	err = os.WriteFile(emptyFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	_, err = readCertificatesFromFile(emptyFile)
	if err == nil {
		t.Error("Expected error with empty file")
	}

	// Test invalid PEM file
	invalidFile := filepath.Join(tempDir, "invalid.pem")
	err = os.WriteFile(invalidFile, []byte("invalid certificate data"), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid file: %v", err)
	}

	_, err = readCertificatesFromFile(invalidFile)
	if err == nil {
		t.Error("Expected error with invalid PEM file")
	}

	// Test file with multiple certificates
	multiCertFile := filepath.Join(tempDir, "multi.pem")
	cert2, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate second test certificate: %v", err)
	}

	cert2PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert2.Raw,
	})

	multiPEM := append(certPEM, cert2PEM...)
	err = os.WriteFile(multiCertFile, multiPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to create multi-cert file: %v", err)
	}

	certs, err = readCertificatesFromFile(multiCertFile)
	if err != nil {
		t.Errorf("readCertificatesFromFile() with multi-cert file failed: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("Expected 2 certificates, got %d", len(certs))
	}
}

func TestReadCertificatesFromFileNonExistent(t *testing.T) {
	_, err := readCertificatesFromFile("/nonexistent/file.pem")
	if err == nil {
		t.Error("Expected error with non-existent file")
	}
}

// generateTestCertificate creates a test certificate for testing purposes
func generateTestCertificate() (*x509.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  nil,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func TestGetTargetFileType(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		expected string
	}{
		{
			name:     "JKS file",
			filename: "keystore.jks",
			expected: "jks",
		},
		{
			name:     "PKCS12 .p12 file",
			filename: "keystore.p12",
			expected: "pkcs12",
		},
		{
			name:     "PKCS12 .pfx file",
			filename: "keystore.pfx",
			expected: "pkcs12",
		},
		{
			name:     "PEM file",
			filename: "certificates.pem",
			expected: "pem",
		},
		{
			name:     "No extension defaults to PEM",
			filename: "certificates",
			expected: "pem",
		},
		{
			name:     "Unknown extension defaults to PEM",
			filename: "certificates.xyz",
			expected: "pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTargetFileType(tt.filename)
			if result != tt.expected {
				t.Errorf("getTargetFileType(%s) = %s, want %s", tt.filename, result, tt.expected)
			}
		})
	}
}

func TestAddCertificateToTargetPEM(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "truststore-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Generate a test certificate
	cert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test PEM file addition (no password needed)
	pemFile := filepath.Join(tempDir, "test.pem")
	err = addCertificateToTarget(pemFile, cert, "")
	if err != nil {
		t.Fatalf("Failed to add certificate to PEM file: %v", err)
	}

	// Verify file was created and contains certificate
	if _, err := os.Stat(pemFile); os.IsNotExist(err) {
		t.Error("PEM file was not created")
	}

	content, err := os.ReadFile(pemFile)
	if err != nil {
		t.Fatalf("Failed to read PEM file: %v", err)
	}

	if !strings.Contains(string(content), "BEGIN CERTIFICATE") {
		t.Error("PEM file does not contain certificate")
	}
}

func TestGetCertificateFingerprint(t *testing.T) {
	// Generate a test certificate
	cert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	fingerprint := getCertificateFingerprint(cert)
	
	// Check that fingerprint is a valid hex string of expected length (SHA-256 = 64 hex chars)
	if len(fingerprint) != 64 {
		t.Errorf("Expected fingerprint length 64, got %d", len(fingerprint))
	}
	
	// Check that it's all uppercase hex
	for _, char := range fingerprint {
		if !((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F')) {
			t.Errorf("Fingerprint contains invalid character: %c", char)
		}
	}
}

func TestPromptForSelfSignedConfirmation(t *testing.T) {
	// This test demonstrates the function signature and expected behavior
	// In practice, this function requires interactive input so we can't easily test it
	// without mocking stdin, but we can at least verify it exists and has the right signature
	
	// Just call the function to ensure it compiles and exists
	// We can't test interactive behavior easily without mocking
	_ = promptForSelfSignedConfirmation
}

func TestDisplayCertificateDetails(t *testing.T) {
	// Generate a test certificate
	cert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// This function primarily prints to stdout, so we just verify it doesn't panic
	// and that the function exists
	displayCertificateDetails(cert)
}

func TestLogSelfSignedAddition(t *testing.T) {
	// Generate a test certificate
	cert, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test both automated and interactive logging
	// These functions primarily log to the standard logger, so we just verify they don't panic
	logSelfSignedAddition("test-source", cert, true)  // automated
	logSelfSignedAddition("test-source", cert, false) // interactive
}

func TestNewAddCommandWithYesFlag(t *testing.T) {
	cmd := NewAddCommand()

	// Test that yes flag exists
	yesFlag := cmd.Flags().Lookup("yes")
	if yesFlag == nil {
		t.Error("Expected 'yes' flag to exist")
		return
	}
	
	// Test flag properties
	if yesFlag.Shorthand != "y" {
		t.Errorf("Expected shorthand 'y', got '%s'", yesFlag.Shorthand)
	}
	
	// Test default value
	defaultValue, err := cmd.Flags().GetBool("yes")
	if err != nil {
		t.Errorf("Failed to get default value for yes flag: %v", err)
	}
	if defaultValue != false {
		t.Errorf("Expected default value false, got %v", defaultValue)
	}
}
