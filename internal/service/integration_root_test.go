package service

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/truststore/cli/internal/client"
	"github.com/truststore/cli/internal/store"
)

// TestFindRootCertificate_IntegrationWithTruststores tests that the FindRootCertificate
// function works correctly when integrated with actual truststore operations
func TestFindRootCertificate_IntegrationWithTruststores(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := ioutil.TempDir("", "truststore_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Run("PEM file integration", func(t *testing.T) {
		testRootSelectionIntegration(t, tempDir, "test.pem", "")
	})

	t.Run("JKS file integration", func(t *testing.T) {
		testRootSelectionIntegration(t, tempDir, "test.jks", "testpassword")
	})

	t.Run("PKCS12 file integration", func(t *testing.T) {
		testRootSelectionIntegration(t, tempDir, "test.p12", "testpassword")
	})
}

// testRootSelectionIntegration performs integration testing with different truststore formats
func testRootSelectionIntegration(t *testing.T, tempDir, filename, password string) {
	// Create a complete certificate chain for testing
	// Root -> Intermediate -> Leaf
	rootSubject := pkix.Name{CommonName: "Test Root CA"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create root certificate: %v", err)
	}

	intermSubject := pkix.Name{CommonName: "Test Intermediate CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create intermediate certificate: %v", err)
	}

	leafSubject := pkix.Name{CommonName: "test.example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	// Create chain service with mock client
	mockClient := &mockCTLogClient{
		searchResults: map[string][]client.CTLogEntry{},
		certificates:  map[int]*x509.Certificate{},
	}
	chainService := NewChainService(mockClient)

	// Test the complete chain
	chain := []*x509.Certificate{leafCert, intermCert, rootCert}

	// Use FindRootCertificate to select the correct root
	selectedRoot := chainService.FindRootCertificate(chain)

	// Verify that the root certificate was correctly selected
	if selectedRoot != rootCert {
		t.Errorf("Expected root certificate to be selected, got %s", selectedRoot.Subject.CommonName)
	}

	// Test integration with truststore handlers
	filePath := filepath.Join(tempDir, filename)
	
	// Get appropriate handler for file type
	var handler store.Truststore
	switch filepath.Ext(filename) {
	case ".pem", ".crt", ".cer":
		handler = store.NewPemHandler()
	case ".jks":
		handler = store.NewJksHandler()
	case ".p12", ".pfx":
		handler = store.NewPkcs12Handler()
	default:
		handler = store.NewPemHandler() // Default to PEM
	}

	// Add the selected root certificate to the truststore
	err = handler.AddCertificate(filePath, selectedRoot, password)
	if err != nil {
		t.Fatalf("Failed to add root certificate to %s: %v", filename, err)
	}

	// Verify the certificate was added correctly
	certs, err := handler.ReadCertificates(filePath, password)
	if err != nil {
		t.Fatalf("Failed to read certificates from %s: %v", filename, err)
	}

	if len(certs) != 1 {
		t.Fatalf("Expected 1 certificate in %s, got %d", filename, len(certs))
	}

	// Verify the correct certificate was stored
	storedCert := certs[0]
	if storedCert.Subject.CommonName != rootCert.Subject.CommonName {
		t.Errorf("Expected stored certificate to be %s, got %s", 
			rootCert.Subject.CommonName, storedCert.Subject.CommonName)
	}

	// Verify certificate validity
	if storedCert.NotBefore != rootCert.NotBefore || storedCert.NotAfter != rootCert.NotAfter {
		t.Error("Stored certificate has different validity period than original")
	}
}

// TestFindRootCertificate_WorkflowIntegration tests the complete workflow
// from chain building to root selection to truststore storage
func TestFindRootCertificate_WorkflowIntegration(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "workflow_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	t.Run("complete workflow simulation", func(t *testing.T) {
		// Step 1: Create certificate chain (simulates CompleteCertificateChain result)
		rootSubject := pkix.Name{CommonName: "Global Root CA"}
		rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate: %v", err)
		}

		intermSubject := pkix.Name{CommonName: "Regional Intermediate CA"}
		intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
		if err != nil {
			t.Fatalf("Failed to create intermediate certificate: %v", err)
		}

		leafSubject := pkix.Name{CommonName: "service.company.com"}
		leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
		if err != nil {
			t.Fatalf("Failed to create leaf certificate: %v", err)
		}

		// Step 2: Build chain (simulate what would come from CT logs)
		chain := []*x509.Certificate{leafCert, intermCert, rootCert}

		// Step 3: Use chain service to find correct root
		mockClient := &mockCTLogClient{}
		chainService := NewChainService(mockClient)
		
		selectedRoot := chainService.FindRootCertificate(chain)

		// Step 4: Verify correct root was selected
		if selectedRoot != rootCert {
			t.Fatalf("Expected root certificate to be selected, got %s", selectedRoot.Subject.CommonName)
		}

		// Step 5: Test with multiple truststore formats (simulate add command)
		testFiles := []struct {
			name     string
			password string
		}{
			{"ca-bundle.pem", ""},
			{"truststore.jks", "password123"},
			{"certificates.p12", "password123"},
		}

		for _, testFile := range testFiles {
			filePath := filepath.Join(tempDir, testFile.name)
			
			// Get handler for file type
			var handler store.Truststore
			ext := filepath.Ext(testFile.name)
			switch ext {
			case ".pem", ".crt", ".cer":
				handler = store.NewPemHandler()
			case ".jks":
				handler = store.NewJksHandler()
			case ".p12", ".pfx":
				handler = store.NewPkcs12Handler()
			}

			// Add the selected root to truststore
			err = handler.AddCertificate(filePath, selectedRoot, testFile.password)
			if err != nil {
				t.Errorf("Failed to add certificate to %s: %v", testFile.name, err)
				continue
			}

			// Verify certificate was added
			certs, err := handler.ReadCertificates(filePath, testFile.password)
			if err != nil {
				t.Errorf("Failed to read certificates from %s: %v", testFile.name, err)
				continue
			}

			if len(certs) != 1 {
				t.Errorf("Expected 1 certificate in %s, got %d", testFile.name, len(certs))
				continue
			}

			// Verify it's the correct certificate
			if certs[0].Subject.CommonName != "Global Root CA" {
				t.Errorf("Wrong certificate stored in %s: got %s", 
					testFile.name, certs[0].Subject.CommonName)
			}
		}
	})
}

// TestBackwardCompatibility ensures that existing workflows still work
func TestBackwardCompatibility(t *testing.T) {
	t.Run("IsSelfSigned method still works", func(t *testing.T) {
		mockClient := &mockCTLogClient{}
		chainService := NewChainService(mockClient)

		// Create self-signed certificate
		subject := pkix.Name{CommonName: "Legacy Test CA"}
		selfSigned, _, err := createTestCertificate(subject, subject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create self-signed certificate: %v", err)
		}

		// Test that IsSelfSigned still works
		if !chainService.IsSelfSigned(selfSigned) {
			t.Error("IsSelfSigned should return true for self-signed certificate")
		}

		// Test that it's consistent with DetectCertificateType
		certType := chainService.DetectCertificateType(selfSigned)
		isSelfSigned := chainService.IsSelfSigned(selfSigned)

		if (certType == SELF_SIGNED) != isSelfSigned {
			t.Error("IsSelfSigned and DetectCertificateType should be consistent")
		}
	})

	t.Run("FindRootCertificate consistent with IsSelfSigned for single cert", func(t *testing.T) {
		mockClient := &mockCTLogClient{}
		chainService := NewChainService(mockClient)

		// Create self-signed certificate
		subject := pkix.Name{CommonName: "Single Cert Test"}
		cert, _, err := createTestCertificate(subject, subject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		// Test single certificate chain
		chain := []*x509.Certificate{cert}
		selectedRoot := chainService.FindRootCertificate(chain)

		// Should return the same certificate
		if selectedRoot != cert {
			t.Error("FindRootCertificate should return the single certificate")
		}

		// Should be consistent with IsSelfSigned
		if chainService.IsSelfSigned(cert) != (chainService.DetectCertificateType(selectedRoot) == SELF_SIGNED) {
			t.Error("Results should be consistent between methods")
		}
	})
}

// TestPerformanceBenchmark ensures the FindRootCertificate function performs well
func TestPerformanceBenchmark(t *testing.T) {
	// This is a functional test that measures performance characteristics
	// to ensure the algorithm completes quickly even with complex chains
	
	mockClient := &mockCTLogClient{}
	chainService := NewChainService(mockClient)

	// Create a long certificate chain (10 certificates)
	var chain []*x509.Certificate
	var currentCert *x509.Certificate
	var currentKey *rsa.PrivateKey

	for i := 0; i < 10; i++ {
		var subject, issuer pkix.Name
		var parent *x509.Certificate
		var parentKey *rsa.PrivateKey

		if i == 0 {
			// Root certificate
			subject = pkix.Name{CommonName: "Root CA"}
			issuer = subject
		} else {
			// Intermediate or leaf certificate
			subject = pkix.Name{CommonName: "Intermediate CA " + string(rune('A'+i-1))}
			issuer = currentCert.Subject
			parent = currentCert
			parentKey = currentKey
		}

		cert, key, err := createTestCertificate(subject, issuer, i < 9, parent, parentKey)
		if err != nil {
			t.Fatalf("Failed to create certificate %d: %v", i, err)
		}

		chain = append([]*x509.Certificate{cert}, chain...) // Prepend to simulate leaf->root order
		currentCert = cert
		currentKey = key
	}

	// Measure time to find root certificate
	start := time.Now()
	selectedRoot := chainService.FindRootCertificate(chain)
	duration := time.Since(start)

	// Should complete quickly (under 10ms for this test)
	if duration > 10*time.Millisecond {
		t.Errorf("FindRootCertificate took too long: %v", duration)
	}

	// Should select the actual root (last certificate we created, which is self-signed)
	if selectedRoot.Subject.CommonName != "Root CA" {
		t.Errorf("Expected 'Root CA' to be selected, got %s", selectedRoot.Subject.CommonName)
	}

	// Verify it's self-signed
	if chainService.DetectCertificateType(selectedRoot) != SELF_SIGNED {
		t.Error("Selected root should be self-signed")
	}
}