package service

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/truststore/cli/internal/client"
)

// ChainService handles certificate chain completion operations
type ChainService interface {
	CompleteCertificateChain(cert *x509.Certificate) ([]*x509.Certificate, error)
	IsSelfSigned(cert *x509.Certificate) bool
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
		if s.isSelfSigned(current) {
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

// IsSelfSigned checks if a certificate is self-signed (root certificate)
func (s *chainService) IsSelfSigned(cert *x509.Certificate) bool {
	return s.isSelfSigned(cert)
}

// isSelfSigned checks if a certificate is self-signed (root certificate)
func (s *chainService) isSelfSigned(cert *x509.Certificate) bool {
	// Check if subject equals issuer
	if cert.Subject.String() == cert.Issuer.String() {
		return true
	}

	// Additional check: verify the certificate was signed by its own public key
	// This is more reliable than just comparing names
	err := cert.CheckSignatureFrom(cert)
	return err == nil
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