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
	OptimizeExistingChain(existingChain []*x509.Certificate) ([]*x509.Certificate, error)
	IsSelfSigned(cert *x509.Certificate) bool
	DetectCertificateType(cert *x509.Certificate) CertificateType
	FindRootCertificate(chain []*x509.Certificate) *x509.Certificate
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
// This method now uses an optimized approach that only fetches missing certificates
// and stops as soon as a root certificate is found
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

	// For CA-signed certificates, use optimized CT log completion logic
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

	// Iteratively build the chain - but stop at first root certificate found
	current := cert
	maxDepth := 8 // Reasonable depth limit for certificate chains

	for depth := 0; depth < maxDepth; depth++ {
		// Check if current certificate is self-signed (root)
		if s.DetectCertificateType(current) == SELF_SIGNED {
			break
		}

		// Find the FIRST valid issuer certificate (don't explore all possibilities)
		issuer, err := s.findFirstValidIssuer(current, visited)
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

		// OPTIMIZATION: Stop immediately if we find a self-signed certificate
		if s.DetectCertificateType(issuer) == SELF_SIGNED {
			break
		}
	}

	return chain, nil
}

// OptimizeExistingChain takes an existing certificate chain and completes it intelligently
// This method checks if issuers are already present in the chain before querying CT logs
// This is more efficient than CompleteCertificateChain which starts from a single certificate
func (s *chainService) OptimizeExistingChain(existingChain []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(existingChain) == 0 {
		return nil, fmt.Errorf("existing chain cannot be empty")
	}

	// Start with the existing chain
	optimizedChain := make([]*x509.Certificate, len(existingChain))
	copy(optimizedChain, existingChain)

	// Track visited certificates to prevent cycles
	visited := make(map[string]bool)
	for _, cert := range existingChain {
		if len(cert.SubjectKeyId) > 0 {
			visited[string(cert.SubjectKeyId)] = true
		}
	}

	// Check if we already have a self-signed certificate (root)
	for _, cert := range optimizedChain {
		if s.DetectCertificateType(cert) == SELF_SIGNED {
			// We already have a root certificate, no need to extend the chain
			return optimizedChain, nil
		}
	}

	// Find the certificate that appears to be the highest in the chain
	// (the one whose issuer is not the subject of any other certificate in the chain)
	topCert := s.findTopCertificateInChain(optimizedChain)
	if topCert == nil {
		// Fallback to the last certificate in the chain
		topCert = optimizedChain[len(optimizedChain)-1]
	}

	// Only if we don't have a complete chain to root, try to extend it
	maxDepth := 5 // Limit additional fetches
	current := topCert

	for depth := 0; depth < maxDepth; depth++ {
		// Check if current certificate is self-signed (root)
		if s.DetectCertificateType(current) == SELF_SIGNED {
			break
		}

		// First, check if the issuer is already in our existing chain
		issuer := s.findIssuerInChain(current, optimizedChain)
		if issuer != nil {
			// Issuer already exists in chain, no need to fetch from CT logs
			// Reorganize chain if needed to ensure proper order
			continue
		}

		// Only query CT logs if issuer is NOT in the existing chain
		issuer, err := s.findFirstValidIssuer(current, visited)
		if err != nil || issuer == nil {
			// No more issuers found, stop here
			break
		}

		// Add the new issuer to the chain
		optimizedChain = append(optimizedChain, issuer)

		// Mark issuer as visited to prevent cycles
		if len(issuer.SubjectKeyId) > 0 {
			if visited[string(issuer.SubjectKeyId)] {
				break // Cycle detected
			}
			visited[string(issuer.SubjectKeyId)] = true
		}

		// Move to next level
		current = issuer

		// Stop if we found a root certificate
		if s.DetectCertificateType(issuer) == SELF_SIGNED {
			break
		}
	}

	return optimizedChain, nil
}

// findTopCertificateInChain finds the certificate in the chain that appears to be highest
// (its issuer is not the subject of any other certificate in the chain)
func (s *chainService) findTopCertificateInChain(chain []*x509.Certificate) *x509.Certificate {
	for _, candidate := range chain {
		isTop := true
		for _, other := range chain {
			if candidate == other {
				continue
			}
			// If another certificate's subject matches this certificate's issuer,
			// then this certificate is not at the top
			if s.namesMatch(other.Subject.String(), candidate.Issuer.String()) {
				isTop = false
				break
			}
		}
		if isTop {
			return candidate
		}
	}
	return nil // No clear top certificate found
}

// findIssuerInChain searches for the issuer of a certificate within the existing chain
func (s *chainService) findIssuerInChain(cert *x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	for _, candidate := range chain {
		if s.canVerifyCertificate(cert, candidate) {
			return candidate
		}
	}
	return nil // Issuer not found in existing chain
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

// findFirstValidIssuer searches for the first valid issuer of the given certificate
// This is an optimized version that returns the first valid issuer found, rather than
// exploring all possibilities. This leads to more predictable and consistent chain building.
func (s *chainService) findFirstValidIssuer(cert *x509.Certificate, visited map[string]bool) (*x509.Certificate, error) {
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

	// Limit the search to reasonable number of candidates for predictable behavior
	maxCandidates := 15 // Increased from 5 to improve success rate
	candidatesChecked := 0

	// Try each candidate certificate, but limit the search for predictability
	for _, entry := range entries {
		if candidatesChecked >= maxCandidates {
			break // Stop after checking limited number of candidates
		}

		// Skip if we've already seen this certificate
		candidateID := fmt.Sprintf("id_%d", entry.ID)
		if visited[candidateID] {
			continue
		}

		candidatesChecked++

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
			// RETURN IMMEDIATELY - don't look for other possibilities
			return candidate, nil
		}
	}

	return nil, nil // No valid issuer found in the limited search
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

// FindRootCertificate analyzes a certificate chain to correctly identify and select the actual root certificate
func (s *chainService) FindRootCertificate(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) == 0 {
		return nil
	}

	// If only one certificate, return it
	if len(chain) == 1 {
		return chain[0]
	}

	// Step 1: Find all self-signed certificates (where subject equals issuer)
	var selfSignedCerts []*x509.Certificate
	for _, cert := range chain {
		if s.DetectCertificateType(cert) == SELF_SIGNED {
			selfSignedCerts = append(selfSignedCerts, cert)
		}
	}

	// Step 2: If we have self-signed certificates, select the best one
	if len(selfSignedCerts) > 0 {
		return s.selectBestRootFromCandidates(selfSignedCerts, chain)
	}

	// Step 3: No self-signed certificates found, use fallback logic
	// Select certificate with longest validity period that can verify others in the chain
	return s.selectFallbackRoot(chain)
}

// selectBestRootFromCandidates selects the best root certificate from self-signed candidates
func (s *chainService) selectBestRootFromCandidates(candidates []*x509.Certificate, chain []*x509.Certificate) *x509.Certificate {
	if len(candidates) == 1 {
		return candidates[0]
	}

	// Multiple self-signed certificates - select the one that can verify the most certificates in the chain
	bestCandidate := candidates[0]
	maxVerifications := s.countVerifiableCertificates(bestCandidate, chain)

	for _, candidate := range candidates[1:] {
		verifications := s.countVerifiableCertificates(candidate, chain)
		if verifications > maxVerifications {
			bestCandidate = candidate
			maxVerifications = verifications
		} else if verifications == maxVerifications {
			// Tie-breaker: select certificate with longest validity period
			if candidate.NotAfter.After(bestCandidate.NotAfter) {
				bestCandidate = candidate
			}
		}
	}

	return bestCandidate
}

// selectFallbackRoot selects a root certificate when no self-signed certificates are found
func (s *chainService) selectFallbackRoot(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) == 0 {
		return nil
	}

	// Find the certificate with the longest validity period that can verify others
	bestCandidate := chain[0]
	maxVerifications := s.countVerifiableCertificates(bestCandidate, chain)
	longestValidity := bestCandidate.NotAfter.Sub(bestCandidate.NotBefore)

	for _, candidate := range chain[1:] {
		verifications := s.countVerifiableCertificates(candidate, chain)
		validity := candidate.NotAfter.Sub(candidate.NotBefore)

		// Prefer certificates that can verify more certificates in the chain
		if verifications > maxVerifications {
			bestCandidate = candidate
			maxVerifications = verifications
			longestValidity = validity
		} else if verifications == maxVerifications {
			// Tie-breaker: select certificate with longest validity period
			if validity > longestValidity {
				bestCandidate = candidate
				longestValidity = validity
			}
		}
	}

	return bestCandidate
}

// countVerifiableCertificates counts how many certificates in the chain can be verified by the given certificate
func (s *chainService) countVerifiableCertificates(candidate *x509.Certificate, chain []*x509.Certificate) int {
	count := 0
	for _, cert := range chain {
		if cert == candidate {
			continue // Don't count self-verification
		}
		if s.canVerifyCertificate(cert, candidate) {
			count++
		}
	}
	return count
}
