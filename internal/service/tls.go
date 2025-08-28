package service

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// TLSService handles TLS connections and certificate retrieval
type TLSService interface {
	GetCertificateChain(domain string) ([]*x509.Certificate, error)
}

// tlsService implements TLSService
type tlsService struct {
	timeout time.Duration
}

// NewTLSService creates a new TLS service with 15-second timeout
func NewTLSService() TLSService {
	return &tlsService{
		timeout: 15 * time.Second,
	}
}

// GetCertificateChain connects to a domain and retrieves the TLS certificate chain
func (s *tlsService) GetCertificateChain(domain string) ([]*x509.Certificate, error) {
	// Parse domain and port
	host, port, err := s.parseDomainPort(domain)
	if err != nil {
		return nil, fmt.Errorf("invalid domain format %q: %w", domain, err)
	}

	// Create address
	address := net.JoinHostPort(host, port)

	// Set up TLS configuration
	config := &tls.Config{
		ServerName: host,
	}

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	// Get the connection state
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates received from server %s", address)
	}

	return state.PeerCertificates, nil
}

// parseDomainPort parses a domain string and returns host and port
func (s *tlsService) parseDomainPort(domain string) (string, string, error) {
	if domain == "" {
		return "", "", fmt.Errorf("domain cannot be empty")
	}

	// Check if port is specified
	if strings.Contains(domain, ":") {
		host, portStr, err := net.SplitHostPort(domain)
		if err != nil {
			return "", "", fmt.Errorf("invalid host:port format: %w", err)
		}

		// Validate port
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return "", "", fmt.Errorf("invalid port number: %s", portStr)
		}

		return host, portStr, nil
	}

	// Default to port 443 for HTTPS
	return domain, "443", nil
}
