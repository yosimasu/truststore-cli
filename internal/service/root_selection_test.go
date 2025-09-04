package service

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

// Tests for specific scenarios mentioned in Story 2.7
func TestFindRootCertificate_ExampleComScenario(t *testing.T) {
	service := &chainService{}
	
	// Create a chain simulating example.com scenario
	// Expected: Should select "CN=DigiCert Global Root G3" (not intermediate)
	
	// Create DigiCert Global Root G3 (self-signed root)
	rootSubject := pkix.Name{CommonName: "DigiCert Global Root G3"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create DigiCert Global Root G3: %v", err)
	}
	
	// Create DigiCert TLS RSA SHA256 2020 CA1 (intermediate)
	intermSubject := pkix.Name{CommonName: "DigiCert TLS RSA SHA256 2020 CA1"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create DigiCert intermediate: %v", err)
	}
	
	// Create example.com leaf certificate
	leafSubject := pkix.Name{CommonName: "example.com"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create example.com certificate: %v", err)
	}
	
	// Chain as it would come from example.com
	chain := []*x509.Certificate{leafCert, intermCert, rootCert}
	result := service.FindRootCertificate(chain)
	
	if result.Subject.CommonName != "DigiCert Global Root G3" {
		t.Errorf("Expected 'DigiCert Global Root G3' for example.com scenario, got '%s'", result.Subject.CommonName)
	}
	
	// Verify it's the actual root and not the intermediate
	if result == intermCert {
		t.Error("Should not select intermediate certificate for example.com scenario")
	}
}

func TestFindRootCertificate_IoTAuomeshScenario(t *testing.T) {
	service := &chainService{}
	
	// Create a chain simulating iot.auomesh.io scenario
	// Expected: Should select "CN=USERTrust RSA Certification Authority"
	
	// Create USERTrust RSA Certification Authority (self-signed root)
	rootSubject := pkix.Name{CommonName: "USERTrust RSA Certification Authority"}
	rootCert, rootKey, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create USERTrust RSA Certification Authority: %v", err)
	}
	
	// Create Sectigo RSA Domain Validation Secure Server CA (intermediate)
	intermSubject := pkix.Name{CommonName: "Sectigo RSA Domain Validation Secure Server CA"}
	intermCert, intermKey, err := createTestCertificate(intermSubject, rootSubject, true, rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to create Sectigo intermediate: %v", err)
	}
	
	// Create iot.auomesh.io leaf certificate
	leafSubject := pkix.Name{CommonName: "iot.auomesh.io"}
	leafCert, _, err := createTestCertificate(leafSubject, intermSubject, false, intermCert, intermKey)
	if err != nil {
		t.Fatalf("Failed to create iot.auomesh.io certificate: %v", err)
	}
	
	// Chain as it would come from iot.auomesh.io
	chain := []*x509.Certificate{leafCert, intermCert, rootCert}
	result := service.FindRootCertificate(chain)
	
	if result.Subject.CommonName != "USERTrust RSA Certification Authority" {
		t.Errorf("Expected 'USERTrust RSA Certification Authority' for iot.auomesh.io scenario, got '%s'", result.Subject.CommonName)
	}
}

func TestFindRootCertificate_MqttAuomeshScenario(t *testing.T) {
	service := &chainService{}
	
	// Create a chain simulating mqtt.auomesh.io scenario
	// Expected: Should select the self-signed "CN=ROOT"
	
	// Create self-signed ROOT certificate
	rootSubject := pkix.Name{CommonName: "ROOT"}
	rootCert, _, err := createTestCertificate(rootSubject, rootSubject, true, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create ROOT certificate: %v", err)
	}
	
	// For self-signed scenario, the chain would just be the single certificate
	chain := []*x509.Certificate{rootCert}
	result := service.FindRootCertificate(chain)
	
	if result.Subject.CommonName != "ROOT" {
		t.Errorf("Expected 'ROOT' for mqtt.auomesh.io scenario, got '%s'", result.Subject.CommonName)
	}
	
	// Verify it's detected as self-signed
	if service.DetectCertificateType(result) != SELF_SIGNED {
		t.Error("ROOT certificate should be detected as SELF_SIGNED")
	}
}

func TestFindRootCertificate_EdgeCases(t *testing.T) {
	service := &chainService{}
	
	t.Run("incomplete chain with multiple potential roots", func(t *testing.T) {
		// Create two potential roots that both have CA capabilities
		root1Subject := pkix.Name{CommonName: "Root CA 1"}
		root1Cert, _, err := createTestCertificate(root1Subject, root1Subject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate 1: %v", err)
		}
		
		root2Subject := pkix.Name{CommonName: "Root CA 2"}
		root2Cert, _, err := createLongValidityCertificate(root2Subject, root2Subject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create root certificate 2: %v", err)
		}
		
		// Both are self-signed, but root2 has longer validity
		chain := []*x509.Certificate{root1Cert, root2Cert}
		result := service.FindRootCertificate(chain)
		
		// Should prefer the one with longer validity period
		if result != root2Cert {
			t.Error("Should select root certificate with longer validity period")
		}
	})
	
	t.Run("cross-signed certificates", func(t *testing.T) {
		// Create two root CAs
		oldRootSubject := pkix.Name{CommonName: "Old Root CA"}
		oldRootCert, oldRootKey, err := createTestCertificate(oldRootSubject, oldRootSubject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create old root certificate: %v", err)
		}
		
		newRootSubject := pkix.Name{CommonName: "New Root CA"}
		newRootCert, newRootKey, err := createTestCertificate(newRootSubject, newRootSubject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create new root certificate: %v", err)
		}
		
		// Create cross-signed certificate: New Root CA signed by Old Root CA's key
		crossSignedSubject := pkix.Name{CommonName: "New Root CA"}
		crossSignedCert, _, err := createTestCertificate(crossSignedSubject, oldRootSubject, true, oldRootCert, oldRootKey)
		if err != nil {
			t.Fatalf("Failed to create cross-signed certificate: %v", err)
		}
		
		// Create leaf signed by new root
		leafSubject := pkix.Name{CommonName: "example.com"}
		leafCert, _, err := createTestCertificate(leafSubject, newRootSubject, false, newRootCert, newRootKey)
		if err != nil {
			t.Fatalf("Failed to create leaf certificate: %v", err)
		}
		
		// Chain with cross-signed certificate
		chain := []*x509.Certificate{leafCert, crossSignedCert, oldRootCert, newRootCert}
		result := service.FindRootCertificate(chain)
		
		// Should prefer self-signed roots over cross-signed ones
		// Both oldRootCert and newRootCert are self-signed, the algorithm should pick one
		selfSignedCount := 0
		for _, cert := range []*x509.Certificate{oldRootCert, newRootCert} {
			if cert == result && service.DetectCertificateType(cert) == SELF_SIGNED {
				selfSignedCount++
			}
		}
		
		if selfSignedCount == 0 {
			t.Error("Should select a self-signed root certificate, not cross-signed")
		}
	})
	
	t.Run("malformed chain with invalid certificates", func(t *testing.T) {
		// Create a valid certificate
		validSubject := pkix.Name{CommonName: "Valid Cert"}
		validCert, _, err := createTestCertificate(validSubject, validSubject, true, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create valid certificate: %v", err)
		}
		
		// Create malformed certificate using the helper
		malformedCert := createMalformedCertificate()
		
		chain := []*x509.Certificate{malformedCert, validCert}
		result := service.FindRootCertificate(chain)
		
		// Should select the valid certificate
		if result != validCert {
			t.Error("Should select valid certificate over malformed one")
		}
	})
}