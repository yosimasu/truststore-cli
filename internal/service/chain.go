package service

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/truststore/cli/internal/client"
)

// CertificateType represents the type of a certificate based on its signing characteristics
type CertificateType int

const (
	// SELF_SIGNED indicates a certificate that is signed by its own private key (root certificate)
	SELF_SIGNED CertificateType = iota
	// CA_SIGNED indicates a certificate that is signed by a Certificate Authority
	CA_SIGNED
	// UNKNOWN indicates a certificate type that cannot be determined due to validation errors or edge cases
	UNKNOWN
)

// String returns a string representation of the certificate type for debugging and logging
func (ct CertificateType) String() string {
	switch ct {
	case SELF_SIGNED:
		return "SELF_SIGNED"
	case CA_SIGNED:
		return "CA_SIGNED"
	case UNKNOWN:
		return "UNKNOWN"
	default:
		return "UNKNOWN"
	}
}

// ChainService handles certificate chain completion operations
type ChainService interface {
	CompleteCertificateChain(cert *x509.Certificate) ([]*x509.Certificate, error)
	IsSelfSigned(cert *x509.Certificate) bool
	DetectCertificateType(cert *x509.Certificate) CertificateType
}

// chainService implements ChainService
type chainService struct {
	ctLogClient client.CTLogClient
}

// NewChainService creates a new chain service with CT log client
func NewChainService(ctLogClient client.CTLogClient) ChainService {
	return &chainService{
		ctLogClient: ctLogClient,
	}
}

// CompleteCertificateChain takes a certificate and builds its complete chain
func (s *chainService) CompleteCertificateChain(cert *x509.Certificate) ([]*x509.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}

	// Detect certificate type first to optimize processing
	certType := s.DetectCertificateType(cert)

	// For self-signed certificates, return immediately with single-certificate chain
	// This skips unnecessary CT log calls and improves performance
	if certType == SELF_SIGNED {
		return []*x509.Certificate{cert}, nil
	}

	// For CA-signed certificates, use existing CT log completion logic
	// For unknown certificates, default to CA-signed behavior with warning logged
	if certType == UNKNOWN {
		// Log warning for unknown certificate type (in production, this would use a proper logger)
		fmt.Printf("Warning: Certificate type could not be determined, defaulting to CA-signed behavior\n")
	}

	// Start with the provided certificate
	chain := []*x509.Certificate{cert}

	// Track visited certificates by subject key ID to prevent cycles
	visited := make(map[string]bool)
	if len(cert.SubjectKeyId) > 0 {
		visited[string(cert.SubjectKeyId)] = true
	}

	// Iteratively build the chain
	current := cert
	maxDepth := 10 // Prevent infinite loops with a reasonable depth limit

	for depth := 0; depth < maxDepth; depth++ {
		// Check if current certificate is self-signed (root)
		if s.DetectCertificateType(current) == SELF_SIGNED {
			break
		}

		// Find the issuer certificate
		issuer, err := s.findIssuerCertificate(current, visited)
		if err != nil {
			// Log the error but don't fail - return partial chain
			break
		}

		if issuer == nil {
			// No issuer found, return what we have
			break
		}

		// Add issuer to chain
		chain = append(chain, issuer)

		// Mark issuer as visited to prevent cycles
		if len(issuer.SubjectKeyId) > 0 {
			if visited[string(issuer.SubjectKeyId)] {
				// Cycle detected, stop here
				break
			}
			visited[string(issuer.SubjectKeyId)] = true
		}

		// Move to next level
		current = issuer
	}

	return chain, nil
}

// DetectCertificateType analyzes a certificate to determine if it's self-signed, CA-signed, or unknown
func (s *chainService) DetectCertificateType(cert *x509.Certificate) CertificateType {
	if cert == nil {
		return UNKNOWN
	}

	// First check: compare subject and issuer distinguished names
	subjectMatches := cert.Subject.String() == cert.Issuer.String()

	// Second check: verify if the certificate can validate against its own public key
	signatureValid := cert.CheckSignatureFrom(cert) == nil

	// Self-signed detection: both subject equals issuer AND certificate validates against its own public key
	if subjectMatches && signatureValid {
		return SELF_SIGNED
	}

	// CA-signed detection: subject differs from issuer OR certificate cannot validate against its own public key
	if !subjectMatches || !signatureValid {
		return CA_SIGNED
	}

	// Edge case: if we somehow get here, return UNKNOWN
	return UNKNOWN
}

// IsSelfSigned checks if a certificate is self-signed (root certificate)
// This method is kept for backward compatibility
func (s *chainService) IsSelfSigned(cert *x509.Certificate) bool {
	return s.DetectCertificateType(cert) == SELF_SIGNED
}

// findIssuerCertificate searches for the issuer of the given certificate
func (s *chainService) findIssuerCertificate(cert *x509.Certificate, visited map[string]bool) (*x509.Certificate, error) {
	// Get issuer name from certificate
	issuerName := cert.Issuer.CommonName
	if issuerName == "" {
		// Try to use organization if CN is empty
		if len(cert.Issuer.Organization) > 0 {
			issuerName = cert.Issuer.Organization[0]
		} else {
			return nil, fmt.Errorf("issuer has no common name or organization")
		}
	}

	// Search for certificates with this issuer name as subject
	entries, err := s.ctLogClient.SearchCertificatesByIssuer(issuerName)
	if err != nil {
		return nil, fmt.Errorf("failed to search for issuer certificates: %w", err)
	}

	// Try each candidate certificate
	for _, entry := range entries {
		// Skip if we've already seen this certificate
		candidateID := fmt.Sprintf("id_%d", entry.ID)
		if visited[candidateID] {
			continue
		}

		// Download the candidate certificate
		candidate, err := s.ctLogClient.DownloadCertificate(entry.ID)
		if err != nil {
			// Log error but continue trying other candidates
			continue
		}

		// Check if this candidate can verify the original certificate
		if s.canVerifyCertificate(cert, candidate) {
			// Mark this candidate as visited using its ID
			visited[candidateID] = true
			return candidate, nil
		}
	}

	return nil, nil // No valid issuer found
}

// canVerifyCertificate checks if the candidate can verify the subject certificate
func (s *chainService) canVerifyCertificate(subject, candidate *x509.Certificate) bool {
	// First check: does the candidate's subject match the subject's issuer?
	if !s.namesMatch(candidate.Subject.String(), subject.Issuer.String()) {
		return false
	}

	// Second check: can the candidate actually verify the subject's signature?
	err := subject.CheckSignatureFrom(candidate)
	return err == nil
}

// namesMatch compares two distinguished names, handling minor formatting differences
func (s *chainService) namesMatch(name1, name2 string) bool {
	// Normalize both names for comparison
	normalized1 := s.normalizeDN(name1)
	normalized2 := s.normalizeDN(name2)

	return normalized1 == normalized2
}

// normalizeDN normalizes a distinguished name for comparison
func (s *chainService) normalizeDN(dn string) string {
	// Convert to lowercase and remove extra spaces
	normalized := strings.ToLower(strings.TrimSpace(dn))

	// Remove spaces around commas and equals signs
	normalized = strings.ReplaceAll(normalized, " = ", "=")
	normalized = strings.ReplaceAll(normalized, " =", "=")
	normalized = strings.ReplaceAll(normalized, "= ", "=")
	normalized = strings.ReplaceAll(normalized, " , ", ",")
	normalized = strings.ReplaceAll(normalized, " ,", ",")
	normalized = strings.ReplaceAll(normalized, ", ", ",")

	return normalized
}
