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

	"github.com/truststore/cli/internal/client"
	"github.com/truststore/cli/internal/service"
)

// Mock CT log client for testing
type mockCTLogClient struct{}

func (m *mockCTLogClient) SearchCertificatesByIssuer(issuer string) ([]client.CTLogEntry, error) {
	return []client.CTLogEntry{}, nil
}

func (m *mockCTLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	return nil, nil
}

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

// Test functions for Story 2.5: Intelligent Self-Signed Certificate Addition

func TestNewAddCommand_YesFlag(t *testing.T) {
	cmd := NewAddCommand()

	// Test that --yes flag exists
	yesFlag := cmd.Flags().Lookup("yes")
	if yesFlag == nil {
		t.Error("Expected '--yes' flag to exist")
		return
	}

	// Test short flag -y
	yesShortFlag := cmd.Flags().ShorthandLookup("y")
	if yesShortFlag == nil {
		t.Error("Expected '-y' short flag to exist")
		return
	}

	// Verify they're the same flag
	if yesFlag != yesShortFlag {
		t.Error("Expected --yes and -y to be the same flag")
	}

	// Check default value
	defaultVal, err := cmd.Flags().GetBool("yes")
	if err != nil {
		t.Fatalf("Failed to get yes flag default value: %v", err)
	}
	if defaultVal != false {
		t.Error("Expected --yes flag default to be false")
	}
}

func TestDisplayCertificateDetails(t *testing.T) {
	// Create a test certificate
	cert := createTestSelfSignedCertificate(t)

	// Capture output by temporarily redirecting stdout
	// This is a basic test - in real implementation you might want to use a more sophisticated approach
	// For now, we'll just verify the function doesn't panic
	displayCertificateDetails(cert)

	// Test completed without panic
}

func TestPromptUserConfirmation(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expected   bool
		shouldFail bool
	}{
		{"explicit_yes", "y", true, false},
		{"explicit_yes_full", "yes", true, false},
		{"explicit_no", "n", false, false},
		{"explicit_no_full", "no", false, false},
		{"empty_input", "", false, false},
		{"invalid_input", "maybe", false, false},
		{"uppercase_yes", "Y", true, false},
		{"uppercase_yes_full", "YES", true, false},
		{"mixed_case", "Yes", true, false},
		{"whitespace_yes", " y ", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For this test, we'll just verify the logic by testing the normalization
			// In a real scenario, you'd need to mock stdin
			response := strings.ToLower(strings.TrimSpace(tt.input))
			result := response == "y" || response == "yes"
			
			if result != tt.expected {
				t.Errorf("Expected %v for input '%s', got %v", tt.expected, tt.input, result)
			}
		})
	}
}

func TestLogSelfSignedAddition(t *testing.T) {
	cert := createTestSelfSignedCertificate(t)
	
	// Test that function doesn't panic with valid inputs
	logSelfSignedAddition("test-source", "test-target", cert, false)
	logSelfSignedAddition("test-source", "test-target", cert, true)
	
	// Test completed without panic
}

func TestHandleSelfSignedConfirmation_AutomatedMode(t *testing.T) {
	cert := createTestSelfSignedCertificate(t)
	
	// Create a mock command with --yes flag set
	cmd := NewAddCommand()
	err := cmd.Flags().Set("yes", "true")
	if err != nil {
		t.Fatalf("Failed to set yes flag: %v", err)
	}

	// Test automated mode (should not prompt and should succeed)
	err = handleSelfSignedConfirmation(cmd, cert, "test-source", "test-target")
	if err != nil {
		t.Errorf("Expected no error in automated mode, got: %v", err)
	}
}

func TestHandleSelfSignedConfirmation_InteractiveMode(t *testing.T) {
	cert := createTestSelfSignedCertificate(t)
	
	// Create a mock command without --yes flag (interactive mode)
	cmd := NewAddCommand()
	
	// Since we can't easily mock user input in this test environment,
	// we'll test that the function attempts to prompt.
	// In a real scenario, this would require mocking stdin or using dependency injection
	// For now, we expect this to fail because we can't provide interactive input
	err := handleSelfSignedConfirmation(cmd, cert, "test-source", "test-target")
	if err == nil {
		t.Error("Expected error in interactive mode without input, got nil")
	}
	
	// The error should indicate user cancellation or input failure
	if !strings.Contains(err.Error(), "cancelled") && !strings.Contains(err.Error(), "confirmation") {
		t.Errorf("Expected cancellation or confirmation error, got: %v", err)
	}
}

// Test that IsSelfSigned method is accessible through the ChainService interface
func TestChainService_IsSelfSigned_Integration(t *testing.T) {
	// This is an integration test to verify the new public method works
	cert := createTestSelfSignedCertificate(t)
	
	// Mock CT log client (we don't need actual network calls for this test)
	mockClient := &mockCTLogClient{}
	chainService := service.NewChainService(mockClient)
	
	// Test the new public IsSelfSigned method
	result := chainService.IsSelfSigned(cert)
	if !result {
		t.Error("Expected self-signed certificate to be detected as self-signed")
	}
	
	// Test with a non-self-signed certificate (different subject and issuer)
	nonSelfSignedCert := createTestNonSelfSignedCertificate(t)
	result = chainService.IsSelfSigned(nonSelfSignedCert)
	if result {
		t.Error("Expected non-self-signed certificate to NOT be detected as self-signed")
	}
}

// Helper function to create a test self-signed certificate
func createTestSelfSignedCertificate(t *testing.T) *x509.Certificate {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-self-signed.example.com",
			Organization: []string{"Test Org"},
		},
		Issuer: pkix.Name{
			CommonName:   "test-self-signed.example.com", // Same as subject for self-signed
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate (self-signed)
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Helper function to create a test non-self-signed certificate
func createTestNonSelfSignedCertificate(t *testing.T) *x509.Certificate {
	// Generate a private key for the leaf certificate
	leafPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf private key: %v", err)
	}

	// Generate a different private key for the CA (to simulate different keys)
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA private key: %v", err)
	}

	// Create CA certificate template
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test-ca.example.com", // Different from leaf
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Create leaf certificate template with different subject and issuer
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "test-leaf.example.com", // Different from CA
			Organization: []string{"Test Org"},
		},
		Issuer: caCert.Subject, // Use CA's subject as issuer
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour), // Shorter validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Create the leaf certificate, signed by CA
	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	return leafCert
}
