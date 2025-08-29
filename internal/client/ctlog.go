package client

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CTLogClient provides access to Certificate Transparency logs via crt.sh API
type CTLogClient interface {
	SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error)
	DownloadCertificate(id int) (*x509.Certificate, error)
}

// CTLogEntry represents a certificate entry from crt.sh search results
type CTLogEntry struct {
	ID           int    `json:"id"`
	CommonName   string `json:"common_name"`
	IssuerName   string `json:"issuer_name"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
}

// ctLogClient implements CTLogClient for crt.sh API
type ctLogClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewCTLogClient creates a new CT log client with 15-second timeout
func NewCTLogClient() CTLogClient {
	return &ctLogClient{
		baseURL: "https://crt.sh/",
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// SearchCertificatesByIssuer searches for certificates by issuer common name
func (c *ctLogClient) SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error) {
	if issuerName == "" {
		return nil, fmt.Errorf("issuer name cannot be empty")
	}

	// Build search URL
	params := url.Values{}
	params.Add("CN", issuerName)
	params.Add("output", "json")
	params.Add("exclude", "expired")
	
	searchURL := c.baseURL + "?" + params.Encode()

	// Make HTTP request
	resp, err := c.httpClient.Get(searchURL)
	if err != nil {
		return nil, fmt.Errorf("failed to search certificates for issuer %q: %w", issuerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh API returned status %d for issuer %q", resp.StatusCode, issuerName)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle empty results
	if len(body) == 0 || strings.TrimSpace(string(body)) == "" {
		return []CTLogEntry{}, nil
	}

	// Parse JSON response
	var entries []CTLogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse search results for issuer %q: %w", issuerName, err)
	}

	return entries, nil
}

// DownloadCertificate downloads a certificate by its crt.sh ID
func (c *ctLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	if id <= 0 {
		return nil, fmt.Errorf("invalid certificate ID: %d", id)
	}

	// Build download URL
	downloadURL := fmt.Sprintf("%s?d=%d", c.baseURL, id)

	// Make HTTP request
	resp, err := c.httpClient.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download certificate with ID %d: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh API returned status %d for certificate ID %d", resp.StatusCode, id)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate data: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("received empty certificate data for ID %d", id)
	}

	// Parse PEM-encoded certificate
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate data for ID %d", id)
	}

	// Parse x509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate for ID %d: %w", id, err)
	}

	return cert, nil
}