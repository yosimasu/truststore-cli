package client

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	baseURL         string
	httpClient      HTTPClient
	responseHandler *ResponseHandler
}

// NewCTLogClient creates a new CT log client with 15-second timeout
func NewCTLogClient() CTLogClient {
	return NewCTLogClientWithHTTPClient(nil)
}

// NewCTLogClientWithHTTPClient creates a new CT log client with custom HTTP client
func NewCTLogClientWithHTTPClient(httpClient HTTPClient) CTLogClient {
	if httpClient == nil {
		config := &Config{
			Timeout:    15 * time.Second,
			MaxRetries: 3,
			BaseDelay:  100 * time.Millisecond,
			MaxDelay:   5 * time.Second,
		}
		httpClient = NewHTTPClient(config)
	}

	return &ctLogClient{
		baseURL:         "https://crt.sh/",
		httpClient:      httpClient,
		responseHandler: NewResponseHandler(),
	}
}

// SearchCertificatesByIssuer searches for certificates by issuer common name
func (c *ctLogClient) SearchCertificatesByIssuer(issuerName string) ([]CTLogEntry, error) {
	if issuerName == "" {
		return nil, NewValidationError("issuer name cannot be empty")
	}

	// Build search URL
	params := url.Values{}
	params.Add("CN", issuerName)
	params.Add("output", "json")
	params.Add("exclude", "expired")
	
	searchURL := c.baseURL + "?" + params.Encode()

	// Make HTTP request using new infrastructure
	resp, err := c.httpClient.Get(searchURL)
	if err != nil {
		classifiedErr := ClassifyError(err, searchURL)
		return nil, fmt.Errorf("failed to search certificates for issuer %q: %w", issuerName, classifiedErr)
	}

	// Use response handler for processing
	var body string
	if err := c.responseHandler.ProcessResponse(resp, &body, http.StatusOK); err != nil {
		return nil, fmt.Errorf("failed to process search response for issuer %q: %w", issuerName, err)
	}

	// Handle empty results
	if strings.TrimSpace(body) == "" {
		return []CTLogEntry{}, nil
	}

	// Parse JSON response
	var entries []CTLogEntry
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return nil, NewParsingError(fmt.Sprintf("failed to parse search results for issuer %q", issuerName), err)
	}

	return entries, nil
}

// DownloadCertificate downloads a certificate by its crt.sh ID
func (c *ctLogClient) DownloadCertificate(id int) (*x509.Certificate, error) {
	if id <= 0 {
		return nil, NewValidationError(fmt.Sprintf("invalid certificate ID: %d", id))
	}

	// Build download URL
	downloadURL := fmt.Sprintf("%s?d=%d", c.baseURL, id)

	// Make HTTP request using new infrastructure
	resp, err := c.httpClient.Get(downloadURL)
	if err != nil {
		classifiedErr := ClassifyError(err, downloadURL)
		return nil, fmt.Errorf("failed to download certificate with ID %d: %w", id, classifiedErr)
	}

	// Use response handler for processing
	var body string
	if err := c.responseHandler.ProcessResponse(resp, &body, http.StatusOK); err != nil {
		return nil, fmt.Errorf("failed to process download response for certificate ID %d: %w", id, err)
	}

	if body == "" {
		return nil, NewParsingError(fmt.Sprintf("received empty certificate data for ID %d", id), nil)
	}

	// Parse PEM-encoded certificate
	block, _ := pem.Decode([]byte(body))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, NewParsingError(fmt.Sprintf("invalid PEM certificate data for ID %d", id), nil)
	}

	// Parse x509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, NewParsingError(fmt.Sprintf("failed to parse certificate for ID %d", id), err)
	}

	return cert, nil
}