package service

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/truststore/cli/internal/client"
)

// TestChainServiceIntegration demonstrates how to use the chain service
// in an integrated manner with the CT log client
func TestChainServiceIntegration(t *testing.T) {
	t.Run("chain service with CT log client integration", func(t *testing.T) {
		// Create real CT log client
		ctLogClient := client.NewCTLogClient()
		
		// Create chain service with real client
		chainService := NewChainService(ctLogClient)
		
		// Verify services are properly created
		if chainService == nil {
			t.Fatal("Chain service creation failed")
		}
		
		// Test service usage pattern with mock certificate
		// In a real scenario, this would be a certificate from file or remote server
		testCert, err := createMockLeafCertificate()
		if err != nil {
			t.Fatalf("Failed to create test certificate: %v", err)
		}
		
		// Complete the certificate chain
		// Note: This will likely return just the original certificate since
		// the test certificate won't be found in crt.sh
		chain, err := chainService.CompleteCertificateChain(testCert)
		if err != nil {
			t.Fatalf("Chain completion failed: %v", err)
		}
		
		// Verify we got at least the original certificate back
		if len(chain) == 0 {
			t.Error("Expected at least one certificate in chain")
		}
		
		if chain[0] != testCert {
			t.Error("First certificate should be the original certificate")
		}
		
		// Demonstrate service interface usage
		var service ChainService = chainService
		_, err = service.CompleteCertificateChain(testCert)
		if err != nil {
			t.Errorf("Interface usage failed: %v", err)
		}
	})
}

// TestServiceDependencyInjection demonstrates proper dependency injection pattern
func TestServiceDependencyInjection(t *testing.T) {
	t.Run("service follows dependency injection pattern", func(t *testing.T) {
		// Mock CT log client
		mockClient := &mockCTLogClient{
			searchResults: map[string][]client.CTLogEntry{},
			certificates:  map[int]*x509.Certificate{},
		}
		
		// Inject mock client into service
		chainService := NewChainService(mockClient)
		
		// Verify service can be used through interface
		var service ChainService = chainService
		
		// Test with mock certificate
		testCert, err := createMockLeafCertificate()
		if err != nil {
			t.Fatalf("Failed to create test certificate: %v", err)
		}
		
		chain, err := service.CompleteCertificateChain(testCert)
		if err != nil {
			t.Errorf("Service with injected dependency failed: %v", err)
		}
		
		if len(chain) != 1 {
			t.Errorf("Expected 1 certificate in chain, got %d", len(chain))
		}
	})
}

// createMockLeafCertificate creates a test certificate for integration testing
func createMockLeafCertificate() (*x509.Certificate, error) {
	// Create a proper test certificate using the existing helper
	subject := pkix.Name{
		CommonName:   "integration-test.example.com",
		Organization: []string{"Integration Test Org"},
	}
	
	cert, _, err := createTestCertificate(subject, subject, false, nil, nil)
	return cert, err
}