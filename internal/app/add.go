package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/truststore/cli/internal/client"
	"github.com/truststore/cli/internal/service"
	"github.com/truststore/cli/internal/store"
)

// NewAddCommand creates the add subcommand
func NewAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [source]",
		Short: "Add root certificate from a source to a truststore file",
		Long: `Add root certificates from various sources to truststore files:
  - Remote servers (e.g., example.org, example.org:443) 
  - Local certificate files (e.g., ca.pem, cert.crt)

The command identifies the root certificate in the chain and adds it to the target file.
If the target file doesn't exist, it will be created.

Examples:
  truststore add example.org --target trusted_certs.pem
  truststore add ca.pem --target trusted_certs.pem
  truststore add /path/to/certificate.crt --target trusted_certs.pem`,
		Args:         cobra.ExactArgs(1),
		RunE:         runAddCommand,
		SilenceUsage: true, // Don't show usage on errors
	}

	// Add target flag - required
	cmd.Flags().StringP("target", "t", "", "Target truststore file path (required)")
	cmd.MarkFlagRequired("target")

	return cmd
}

// runAddCommand implements the add command logic
func runAddCommand(cmd *cobra.Command, args []string) error {
	source := args[0]
	target, _ := cmd.Flags().GetString("target")

	// Validate target path
	if err := validateTargetPath(target); err != nil {
		return fmt.Errorf("invalid target path: %w", err)
	}

	// Determine if source is a domain or file path
	if isAddDomainSource(source) {
		return handleDomainAdd(source, target)
	}

	// Handle file sources
	return handleFileAdd(source, target)
}

// handleDomainAdd adds root certificate from a remote server to target file
func handleDomainAdd(domain, target string) error {
	// Start loading indicator for TLS certificate retrieval
	stopTLS := startLoadingIndicator(fmt.Sprintf("Retrieving certificate from %s", domain))

	cert, err := retrieveCertificateFromDomain(domain)
	stopTLS()

	if err != nil {
		return fmt.Errorf("failed to retrieve certificate from %s: %w", domain, err)
	}

	fmt.Printf("✓ Certificate retrieved from %s\n", domain)

	// Start loading indicator for certificate chain completion
	stopChain := startLoadingIndicator("Completing certificate chain via CT logs")

	ctLogClient := client.NewCTLogClient()
	chainService := service.NewChainService(ctLogClient)

	chain, err := chainService.CompleteCertificateChain(cert)
	stopChain()

	if err != nil {
		return fmt.Errorf("failed to complete certificate chain: %w", err)
	}

	fmt.Printf("✓ Certificate chain completed (%d certificates found)\n", len(chain))

	if len(chain) == 0 {
		return fmt.Errorf("no certificates found in chain")
	}

	// Get the root certificate (last in chain)
	rootCert := chain[len(chain)-1]

	// Add root certificate to target PEM file
	pemHandler := store.NewPemHandler()
	err = pemHandler.AddCertificate(target, rootCert, "")
	if err != nil {
		return fmt.Errorf("failed to add certificate to %s: %w", target, err)
	}

	// Print success message
	fmt.Printf("Successfully added root certificate to %s\n", target)
	fmt.Printf("Certificate Subject: %s\n", rootCert.Subject.String())
	fmt.Printf("Serial Number: %s\n", rootCert.SerialNumber.String())

	return nil
}

// handleFileAdd adds root certificate from a local file to target file
func handleFileAdd(sourcePath, target string) error {
	// Validate that source file exists
	if err := validateSourceFilePath(sourcePath); err != nil {
		return fmt.Errorf("invalid source file: %w", err)
	}

	// Read certificate(s) from the source file
	stopRead := startLoadingIndicator(fmt.Sprintf("Reading certificate from %s", sourcePath))
	certs, err := readCertificatesFromFile(sourcePath)
	stopRead()

	if err != nil {
		return fmt.Errorf("failed to read certificates from %s: %w", sourcePath, err)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no valid certificates found in %s", sourcePath)
	}

	fmt.Printf("✓ Read %d certificate(s) from %s\n", len(certs), sourcePath)

	// Use the first certificate for chain completion
	cert := certs[0]

	// Start loading indicator for certificate chain completion
	stopChain := startLoadingIndicator("Completing certificate chain via CT logs")

	ctLogClient := client.NewCTLogClient()
	chainService := service.NewChainService(ctLogClient)

	chain, err := chainService.CompleteCertificateChain(cert)
	stopChain()

	if err != nil {
		return fmt.Errorf("failed to complete certificate chain: %w", err)
	}

	fmt.Printf("✓ Certificate chain completed (%d certificates found)\n", len(chain))

	if len(chain) == 0 {
		return fmt.Errorf("no certificates found in chain")
	}

	// Get the root certificate (last in chain)
	rootCert := chain[len(chain)-1]

	// Add root certificate to target PEM file
	pemHandler := store.NewPemHandler()
	err = pemHandler.AddCertificate(target, rootCert, "")
	if err != nil {
		return fmt.Errorf("failed to add certificate to %s: %w", target, err)
	}

	// Print success message
	fmt.Printf("Successfully added root certificate to %s\n", target)
	fmt.Printf("Certificate Subject: %s\n", rootCert.Subject.String())
	fmt.Printf("Serial Number: %s\n", rootCert.SerialNumber.String())

	return nil
}

// retrieveCertificateFromDomain gets the certificate from a remote server
func retrieveCertificateFromDomain(domain string) (*x509.Certificate, error) {
	// Add default port if not specified
	host := domain
	if !strings.Contains(domain, ":") {
		host = domain + ":443"
	}

	// Connect to the server and get certificate
	conn, err := tls.Dial("tcp", host, &tls.Config{
		ServerName: domain, // Use original domain for SNI
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", host, err)
	}
	defer conn.Close()

	// Get the peer certificate chain
	peerCerts := conn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return nil, fmt.Errorf("no certificates received from %s", domain)
	}

	// Return the first certificate (leaf certificate)
	return peerCerts[0], nil
}

// validateTargetPath validates the target file path
func validateTargetPath(target string) error {
	if target == "" {
		return fmt.Errorf("target path cannot be empty")
	}

	// Check if the directory exists and is writable
	dir := filepath.Dir(target)
	if dir != "." {
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("directory %s does not exist", dir)
			}
			return fmt.Errorf("cannot access directory %s: %w", dir, err)
		}

		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
	}

	// Check if target file exists and is writable, or if it can be created
	if _, err := os.Stat(target); err == nil {
		// File exists, check if writable
		file, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return fmt.Errorf("cannot write to existing file %s: %w", target, err)
		}
		file.Close()
	} else if os.IsNotExist(err) {
		// File doesn't exist, check if we can create it
		file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("cannot create file %s: %w", target, err)
		}
		file.Close()
		// Remove the test file
		os.Remove(target)
	} else {
		return fmt.Errorf("cannot access file %s: %w", target, err)
	}

	return nil
}

// isAddDomainSource determines if the source is a domain name or file path
func isAddDomainSource(source string) bool {
	// Check if it's a file path (exists on filesystem)
	if _, err := os.Stat(source); err == nil {
		return false
	}

	// Check if it has a file extension that suggests it's a file
	ext := strings.ToLower(filepath.Ext(source))
	fileExtensions := []string{".pem", ".crt", ".cer", ".jks", ".p12", ".pfx"}
	for _, fileExt := range fileExtensions {
		if ext == fileExt {
			return false
		}
	}

	// Check if it contains path separators
	if strings.Contains(source, "/") || strings.Contains(source, "\\") {
		return false
	}

	// If none of the above, treat as domain
	return true
}

// startLoadingIndicator displays a spinning loading indicator with the given message
// Returns a function to stop the indicator
func startLoadingIndicator(message string) func() {
	done := make(chan bool)

	go func() {
		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		i := 0

		for {
			select {
			case <-done:
				// Clear the loading line
				fmt.Printf("\r%s\r", strings.Repeat(" ", len(message)+4))
				return
			default:
				// Display spinner with message
				fmt.Printf("\r%s %s", spinner[i%len(spinner)], message)
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// Return stop function
	return func() {
		done <- true
		// Small delay to ensure the goroutine clears the line
		time.Sleep(10 * time.Millisecond)
	}
}

// validateSourceFilePath validates that the source file exists and is readable
func validateSourceFilePath(sourcePath string) error {
	if sourcePath == "" {
		return fmt.Errorf("source path cannot be empty")
	}

	// Check if file exists
	info, err := os.Stat(sourcePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file %s does not exist", sourcePath)
		}
		return fmt.Errorf("cannot access file %s: %w", sourcePath, err)
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", sourcePath)
	}

	// Check if file is readable
	file, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("cannot read file %s: %w", sourcePath, err)
	}
	file.Close()

	return nil
}

// readCertificatesFromFile reads and parses certificates from a PEM file
func readCertificatesFromFile(sourcePath string) ([]*x509.Certificate, error) {
	// Read the file content
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var certificates []*x509.Certificate

	// Parse all PEM blocks in the file
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break // No more PEM blocks
		}

		// Only process CERTIFICATE blocks
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				// Log warning but continue processing other certificates
				fmt.Printf("Warning: Failed to parse certificate block: %v\n", err)
			} else {
				certificates = append(certificates, cert)
			}
		}

		rest = remaining
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no valid certificate blocks found in file")
	}

	return certificates, nil
}
