package app

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/truststore/cli/internal/client"
	"github.com/truststore/cli/internal/service"
	"github.com/truststore/cli/internal/store"
)

// NewRmCommand creates the rm subcommand
func NewRmCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rm [source]",
		Short: "Remove root certificate from a truststore file by identifying it via source",
		Long: `Remove root certificates from truststore files by identifying them through their 
source. The command uses the source to identify the root certificate in the certificate 
chain, then searches for and removes that specific certificate from the target truststore.

HOW IT WORKS:
1. Identifies root certificate from the source (server or file)
2. Searches for matching certificate in target truststore  
3. Removes the certificate if found
4. Reports success or error if certificate not found

SUPPORTED SOURCE TYPES (for identification):
• Remote Servers: Use TLS connection to identify root certificate
  - Domain names: example.org, google.com
  - Domain with port: example.org:443, localhost:8443
  
• Local Certificate Files: Read certificate to identify root in chain
  - PEM files: ca.pem, cert.crt, certificate.cer
  - JKS files: keystore.jks (requires --password)  
  - PKCS12 files: keystore.p12, cert.pfx (requires --password)

SUPPORTED TARGET FORMATS (for removal):
• PEM Files: Plain-text certificate files
  - Extensions: .pem, .crt, .cer
  
• JKS Files: Java KeyStore format (requires --target-password)
  - Extensions: .jks
  
• PKCS12 Files: Industry standard format (requires --target-password)  
  - Extensions: .p12, .pfx

REQUIRED FLAGS:
  -t, --target string          Target truststore file path (required, must exist)

OPTIONAL FLAGS:
  -p, --password string        Password for source keystore (JKS/PKCS12 sources only)
      --target-password string Password for target keystore (JKS/PKCS12 targets only)
                               Use flag=value or flag for interactive prompt

CERTIFICATE IDENTIFICATION PROCESS:
The command uses Certificate Transparency logs to complete certificate chains 
from the source, ensuring accurate identification of the root certificate to 
remove, even when working with intermediate certificates.

EXAMPLES:
  # Remove by identifying via remote server
  truststore rm example.org --target trusted_certs.pem
  truststore rm example.org:443 --target ca-bundle.pem
  
  # Remove by identifying via local certificate file
  truststore rm ca.pem --target trusted_certs.pem  
  truststore rm /path/to/certificate.crt --target trusted_certs.pem
  
  # Remove from password-protected target
  truststore rm example.org --target keystore.jks --target-password=secret
  truststore rm ca.pem --target keystore.p12 --target-password
  
  # Use password-protected source for identification
  truststore rm source.jks --password=secret --target trusted_certs.pem
  truststore rm source.p12 --password --target keystore.jks --target-password
  
  # Both source and target password-protected
  truststore rm source.jks --password=src_pass --target target.p12 --target-password=tgt_pass

LOADING INDICATORS:
During execution, you'll see progress indicators:
  🔍 Connecting to [server]              - Establishing TLS connection
  📋 Retrieving certificate from [server] - Downloading certificate
  🔗 Completing certificate chain via CT logs - Finding root certificate
  📂 Reading certificates from [file]    - Loading from source file  
  🔍 Searching for certificate in [target] - Finding certificate to remove
  🗑️ Removing certificate from [target] - Deleting certificate from truststore

ERROR HANDLING:
• "certificate not found in target truststore" - The identified root certificate 
  doesn't exist in the target file. Use 'truststore list' to see what's there.
• Network errors - Connection issues when identifying from remote servers
• File permission errors - Cannot read source or write to target files
• Password errors - Incorrect password for protected keystores`,
		Args:         cobra.ExactArgs(1),
		RunE:         runRmCommand,
		SilenceUsage: true, // Don't show usage on errors
	}

	// Add target flag - required
	cmd.Flags().StringP("target", "t", "", "Target truststore file path (required)")
	if err := cmd.MarkFlagRequired("target"); err != nil {
		panic(fmt.Sprintf("failed to mark target flag as required: %v", err))
	}

	// Add password flag for reading source keystore files
	cmd.Flags().StringP("password", "p", "", "Password for source keystore (required when source is JKS/PKCS12). Use --password=<password> or --password for interactive prompt")
	cmd.Flags().Lookup("password").NoOptDefVal = "PROMPT"

	// Add target-password flag for JKS/PKCS12 files
	cmd.Flags().StringP("target-password", "", "", "Password for target keystore (required for JKS/PKCS12). Use --target-password=<password> or --target-password for interactive prompt")
	cmd.Flags().Lookup("target-password").NoOptDefVal = "PROMPT"

	return cmd
}

// runRmCommand implements the rm command logic
func runRmCommand(cmd *cobra.Command, args []string) error {
	source := args[0]
	target, _ := cmd.Flags().GetString("target")

	// Validate target file exists
	if err := validateTargetFileExists(target); err != nil {
		return fmt.Errorf("invalid target file: %w", err)
	}

	// Get and validate password for target file type
	targetPassword, err := getTargetPassword(cmd, target)
	if err != nil {
		return fmt.Errorf("target password error: %w", err)
	}

	// Get source password if needed
	sourcePassword, err := getSourcePassword(cmd, source)
	if err != nil {
		return fmt.Errorf("source password error: %w", err)
	}

	// Determine if source is a domain or file path
	if isRmDomainSource(source) {
		return handleDomainRm(source, target, targetPassword)
	}

	// Handle file sources
	return handleFileRm(source, target, sourcePassword, targetPassword)
}

// handleDomainRm removes root certificate identified from remote server from target file
func handleDomainRm(domain, target, targetPassword string) error {
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

	// Get the root certificate using proper root selection algorithm
	rootCert := chainService.FindRootCertificate(chain)

	// Search and remove root certificate from target file
	return searchAndRemoveCertificate(target, rootCert, targetPassword)
}

// handleFileRm removes root certificate identified from local file from target file
func handleFileRm(sourcePath, target, sourcePassword, targetPassword string) error {
	// Validate that source file exists
	if err := validateSourceFilePath(sourcePath); err != nil {
		return fmt.Errorf("invalid source file: %w", err)
	}

	// Read certificate(s) from the source file using appropriate handler
	stopRead := startLoadingIndicator(fmt.Sprintf("Reading certificate from %s", sourcePath))
	certs, err := readCertificatesFromSourceFile(sourcePath, sourcePassword)
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

	// Get the root certificate using proper root selection algorithm
	rootCert := chainService.FindRootCertificate(chain)

	// Search and remove root certificate from target file
	return searchAndRemoveCertificate(target, rootCert, targetPassword)
}

// searchAndRemoveCertificate searches for and removes the specified root certificate from the target truststore
func searchAndRemoveCertificate(target string, rootCert *x509.Certificate, password string) error {
	// Start loading indicator for truststore search
	stopSearch := startLoadingIndicator(fmt.Sprintf("Searching for certificate in %s", target))

	// Read existing certificates from target truststore
	targetCerts, err := readCertificatesFromTargetFile(target, password)
	stopSearch()

	if err != nil {
		return fmt.Errorf("failed to read certificates from target %s: %w", target, err)
	}

	// Find matching certificate
	found := false
	for _, targetCert := range targetCerts {
		if certificatesEqual(rootCert, targetCert) {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("root certificate not found in target truststore %s", target)
	}

	fmt.Printf("✓ Root certificate found in %s\n", target)

	// Start loading indicator for certificate removal
	stopRemove := startLoadingIndicator("Removing certificate from truststore")

	// Remove certificate from target file using appropriate handler
	err = removeCertificateFromTarget(target, rootCert, password)
	stopRemove()

	if err != nil {
		return fmt.Errorf("failed to remove certificate from %s: %w", target, err)
	}

	// Print success message
	printRemovalSuccessMessage(target, rootCert)

	return nil
}

// isRmDomainSource determines if the source is a domain name or file path (same logic as add)
func isRmDomainSource(source string) bool {
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

// validateTargetFileExists validates that the target file exists (different from add command)
func validateTargetFileExists(target string) error {
	if target == "" {
		return fmt.Errorf("target path cannot be empty")
	}

	// Check if file exists
	info, err := os.Stat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("target file %s does not exist", target)
		}
		return fmt.Errorf("cannot access target file %s: %w", target, err)
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", target)
	}

	// Check if file is writable
	file, err := os.OpenFile(target, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("cannot write to target file %s: %w", target, err)
	}
	if err := file.Close(); err != nil {
		// Log file close error but don't fail - operation already completed
		_ = err
	}

	return nil
}

// readCertificatesFromTargetFile reads certificates from target file using appropriate handler
func readCertificatesFromTargetFile(target, password string) ([]*x509.Certificate, error) {
	targetType := getTargetFileType(target)

	switch targetType {
	case "pem":
		pemHandler := store.NewPemHandler()
		return pemHandler.ReadCertificates(target, "")
	case "jks":
		jksHandler := store.NewJksHandler()
		return jksHandler.ReadCertificates(target, password)
	case "pkcs12":
		pkcs12Handler := store.NewPkcs12Handler()
		return pkcs12Handler.ReadCertificates(target, password)
	default:
		return nil, fmt.Errorf("unsupported target file type: %s", targetType)
	}
}

// removeCertificateFromTarget removes a certificate from the target file using the appropriate handler
func removeCertificateFromTarget(target string, cert *x509.Certificate, password string) error {
	targetType := getTargetFileType(target)

	switch targetType {
	case "pem":
		pemHandler := store.NewPemHandler()
		return pemHandler.RemoveCertificate(target, cert, "")
	case "jks":
		jksHandler := store.NewJksHandler()
		return jksHandler.RemoveCertificate(target, cert, password)
	case "pkcs12":
		pkcs12Handler := store.NewPkcs12Handler()
		return pkcs12Handler.RemoveCertificate(target, cert, password)
	default:
		return fmt.Errorf("unsupported target file type: %s", targetType)
	}
}

// certificatesEqual compares two certificates for equality using cryptographically secure comparison
func certificatesEqual(cert1, cert2 *x509.Certificate) bool {
	// Use the built-in Equal method which performs full cryptographic comparison
	// This is more secure than comparing only serial number + issuer as it validates
	// the entire certificate content including signature and all extensions
	return cert1.Equal(cert2)
}

// printRemovalSuccessMessage prints formatted success message for certificate removal
func printRemovalSuccessMessage(target string, cert *x509.Certificate) {
	targetType := getTargetFileType(target)

	fmt.Printf("Successfully removed root certificate from %s\n", target)
	fmt.Printf("Certificate Subject: %s\n", cert.Subject.String())
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber.String())

	// Include format-specific information
	switch targetType {
	case "jks":
		fmt.Printf("Certificate removed from JKS keystore\n")
	case "pkcs12":
		fmt.Printf("Certificate removed from PKCS12 keystore\n")
	case "pem":
		fmt.Printf("Certificate removed from PEM file\n")
	}
}
