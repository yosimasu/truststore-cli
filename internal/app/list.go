package app

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/truststore/cli/internal/client"
	"github.com/truststore/cli/internal/service"
	"github.com/truststore/cli/internal/store"
	"golang.org/x/term"
)

// NewListCommand creates the list subcommand
func NewListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [source]",
		Short: "List certificates from a source",
		Long: `List certificates from various sources including remote servers and local files.

SUPPORTED SOURCE TYPES:
• Remote Servers: Connect via TLS and retrieve certificate chains
  - Domain names: example.org, google.com
  - Domain with port: example.org:443, localhost:8443
  
• Local PEM Files: Plain-text certificate files (no password required)
  - Extensions: .pem, .crt, .cer
  - Example: certificates.pem, ca-bundle.crt
  
• Local JKS Files: Java KeyStore format (password usually required)
  - Extensions: .jks
  - Example: keystore.jks, truststore.jks
  
• Local PKCS12 Files: Industry standard format (password usually required)  
  - Extensions: .p12, .pfx
  - Example: keystore.p12, certificate.pfx

FLAGS:
  -p, --password string   Password for protected keystores (JKS/PKCS12)
                         Use --password=secret or --password for interactive prompt

PASSWORD HANDLING:
• Command line: --password=mysecret
• Interactive prompt: --password (without value - more secure)
• Not required for PEM files (they are not password-protected)

EXAMPLES:
  # List from remote servers  
  truststore list example.org
  truststore list example.org:443
  
  # List from PEM files (no password needed)
  truststore list certificates.pem
  truststore list /path/to/ca-bundle.crt
  
  # List from protected keystores
  truststore list keystore.jks --password=secret
  truststore list keystore.p12 --password        # Interactive prompt
  truststore list keystore.jks -p=secret
  truststore list keystore.p12 -p               # Interactive prompt

LOADING INDICATORS:
During execution, you'll see progress indicators:
  🔍 Connecting to [server]           - Establishing TLS connection
  📋 Retrieving certificate from [server] - Downloading certificates  
  📂 Reading certificates from [file] - Loading from local file`,
		Args:         cobra.ExactArgs(1),
		RunE:         runListCommand,
		SilenceUsage: true, // Don't show usage on errors
	}

	// Add flags for password-protected keystores
	cmd.Flags().StringP("password", "p", "", "Password for protected keystores (JKS/PKCS12)")
	// Allow password flag to be used without providing a value (will prompt)
	cmd.Flags().Lookup("password").NoOptDefVal = "PROMPT"

	return cmd
}

// runListCommand implements the list command logic
func runListCommand(cmd *cobra.Command, args []string) error {
	source := args[0]
	password, _ := cmd.Flags().GetString("password")

	// Check if password flag was provided but set to PROMPT - prompt for password
	if cmd.Flags().Changed("password") && password == "PROMPT" {
		promptedPassword, err := promptForPassword()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = promptedPassword
	}

	// Determine if source is a domain or file path
	if isDomainSource(source) {
		return handleDomainSource(source)
	}

	// Handle file sources (will be implemented in future stories)
	return handleFileSource(source, password)
}

// isDomainSource determines if the source is a domain name or file path
func isDomainSource(source string) bool {
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

// handleDomainSource handles certificate listing from a remote domain
func handleDomainSource(domain string) error {
	// Create services
	tlsService := service.NewTLSService()
	formatter := service.NewCertificateFormatter()

	// Retrieve certificate chain
	certificates, err := tlsService.GetCertificateChain(domain)
	if err != nil {
		// Translate technical errors to user-friendly messages
		return fmt.Errorf("failed to retrieve certificates from %s: %w", domain, err)
	}

	// Format and display certificates
	output := formatter.FormatCertificateChain(certificates, domain)
	fmt.Print(output)

	return nil
}

// handleFileSource handles certificate listing from local files
func handleFileSource(source, password string) error {
	// Determine file type based on extension
	ext := strings.ToLower(filepath.Ext(source))

	switch ext {
	case ".pem", ".crt", ".cer":
		return handlePemFile(source)
	case ".jks":
		return handleJksFile(source, password)
	case ".p12", ".pfx":
		return handlePkcs12File(source, password)
	default:
		// Try to detect format by file header if no extension match
		return handleUnknownFile(source, password)
	}
}

// handlePemFile handles certificate listing from PEM files
func handlePemFile(filepath string) error {
	// Create PEM handler and formatter service
	pemHandler := store.NewPemHandler()
	formatter := service.NewCertificateFormatter()
	ctLogClient := client.NewCTLogClient()
	chainService := service.NewChainService(ctLogClient)

	// Read certificates from PEM file
	certificates, err := pemHandler.ReadCertificates(filepath, "")
	if err != nil {
		return fmt.Errorf("failed to read certificates from PEM file %s: %w", filepath, err)
	}

	// If we have certificates, complete the chain and find the root
	if len(certificates) > 0 {
		// Build complete certificate chain starting from the first certificate
		completedChain, err := chainService.CompleteCertificateChain(certificates[0])
		if err != nil {
			// If chain completion fails, fall back to using certificates as-is
			completedChain = certificates
		}
		
		// Find the actual root certificate
		rootCert := chainService.FindRootCertificate(completedChain)
		if rootCert != nil {
			// Display just the root certificate
			certificates = []*x509.Certificate{rootCert}
		}
	}

	// Format and display certificates
	output := formatter.FormatCertificateChain(certificates, filepath)
	fmt.Print(output)

	return nil
}

// handleJksFile handles certificate listing from JKS files
func handleJksFile(filepath, password string) error {
	// Create JKS handler and formatter service
	jksHandler := store.NewJksHandler()
	formatter := service.NewCertificateFormatter()
	ctLogClient := client.NewCTLogClient()
	chainService := service.NewChainService(ctLogClient)

	// Read certificates from JKS file
	certificates, err := jksHandler.ReadCertificates(filepath, password)
	if err != nil {
		return fmt.Errorf("failed to read certificates from JKS file %s: %w", filepath, err)
	}

	// If we have certificates, complete the chain and find the root
	if len(certificates) > 0 {
		// Build complete certificate chain starting from the first certificate
		completedChain, err := chainService.CompleteCertificateChain(certificates[0])
		if err != nil {
			// If chain completion fails, fall back to using certificates as-is
			completedChain = certificates
		}
		
		// Find the actual root certificate
		rootCert := chainService.FindRootCertificate(completedChain)
		if rootCert != nil {
			// Display just the root certificate
			certificates = []*x509.Certificate{rootCert}
		}
	}

	// Format and display certificates
	output := formatter.FormatCertificateChain(certificates, filepath)
	fmt.Print(output)

	return nil
}

// handlePkcs12File handles certificate listing from PKCS12 files
func handlePkcs12File(filepath, password string) error {
	// Create PKCS12 handler and formatter service
	pkcs12Handler := store.NewPkcs12Handler()
	formatter := service.NewCertificateFormatter()
	ctLogClient := client.NewCTLogClient()
	chainService := service.NewChainService(ctLogClient)

	// Read certificates from PKCS12 file
	certificates, err := pkcs12Handler.ReadCertificates(filepath, password)
	if err != nil {
		return fmt.Errorf("failed to read certificates from PKCS12 file %s: %w", filepath, err)
	}

	// If we have certificates, complete the chain and find the root
	if len(certificates) > 0 {
		// Build complete certificate chain starting from the first certificate
		completedChain, err := chainService.CompleteCertificateChain(certificates[0])
		if err != nil {
			// If chain completion fails, fall back to using certificates as-is
			completedChain = certificates
		}
		
		// Find the actual root certificate
		rootCert := chainService.FindRootCertificate(completedChain)
		if rootCert != nil {
			// Display just the root certificate
			certificates = []*x509.Certificate{rootCert}
		}
	}

	// Format and display certificates
	output := formatter.FormatCertificateChain(certificates, filepath)
	fmt.Print(output)

	return nil
}

// handleUnknownFile attempts to detect file format and handle accordingly
func handleUnknownFile(source, password string) error {
	// Try to detect file format by reading file header
	format, err := detectFileFormat(source)
	if err != nil {
		return fmt.Errorf("failed to detect file format for %s: %w", source, err)
	}

	switch format {
	case "PEM":
		return handlePemFile(source)
	case "JKS":
		return handleJksFile(source, password)
	case "PKCS12":
		return handlePkcs12File(source, password)
	default:
		// Default to PEM as fallback
		return handlePemFile(source)
	}
}

// detectFileFormat attempts to detect file format by examining file headers
func detectFileFormat(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", filepath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log file close error but don't fail the operation
			_ = err
		}
	}()

	// Read first few bytes to detect format
	header := make([]byte, 16)
	n, err := file.Read(header)
	if err != nil {
		return "", fmt.Errorf("failed to read file header from %s: %w", filepath, err)
	}

	// Check for JKS magic number (0xFEEDFEED)
	if n >= 4 && header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFE && header[3] == 0xED {
		return "JKS", nil
	}

	// Check for PKCS12 format (starts with 0x30 for ASN.1 SEQUENCE)
	if n >= 1 && header[0] == 0x30 {
		// Could be PKCS12 or other ASN.1 format, check more bytes
		if n >= 2 {
			// PKCS12 typically has specific ASN.1 structure
			// This is a simplified check - in real scenarios might need more sophisticated detection
			return "PKCS12", nil
		}
	}

	// Check for PEM format (starts with "-----BEGIN")
	headerStr := string(header[:n])
	if strings.HasPrefix(headerStr, "-----BEGIN") {
		return "PEM", nil
	}

	// Default to unknown (will fallback to PEM)
	return "UNKNOWN", nil
}

// promptForPassword securely prompts the user for a password
func promptForPassword() (string, error) {
	// Check if stdin is a terminal
	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", fmt.Errorf("password prompt requires an interactive terminal")
	}

	fmt.Print("Enter password: ")

	// Read password from terminal without echoing
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	// Print newline after password input
	fmt.Println()

	return string(passwordBytes), nil
}
