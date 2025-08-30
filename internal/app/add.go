package app

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/truststore/cli/internal/client"
	"github.com/truststore/cli/internal/service"
	"github.com/truststore/cli/internal/store"
	"golang.org/x/term"
)

// NewAddCommand creates the add subcommand
func NewAddCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add [source]",
		Short: "Add root certificate from a source to a truststore file",
		Long: `Add root certificates from various sources to truststore files. The command 
automatically identifies the root certificate in the certificate chain and adds it 
to the target truststore file. If the target file doesn't exist, it will be created.

SUPPORTED SOURCE TYPES:
• Remote Servers: Retrieve certificate via TLS connection
  - Domain names: example.org, google.com
  - Domain with port: example.org:443, localhost:8443
  
• Local Certificate Files: Read certificates from local files
  - PEM files: ca.pem, cert.crt, certificate.cer  
  - JKS files: keystore.jks (requires --password)
  - PKCS12 files: keystore.p12, cert.pfx (requires --password)

SUPPORTED TARGET FORMATS:
• PEM Files: Plain-text format, will be created if doesn't exist
  - Extensions: .pem, .crt, .cer
  
• JKS Files: Java KeyStore format (requires --target-password)
  - Extensions: .jks
  
• PKCS12 Files: Industry standard format (requires --target-password)
  - Extensions: .p12, .pfx

REQUIRED FLAGS:
  -t, --target string          Target truststore file path (required)

OPTIONAL FLAGS:  
  -p, --password string        Password for source keystore (JKS/PKCS12 sources only)
      --target-password string Password for target keystore (JKS/PKCS12 targets only)
                               Use flag=value or flag for interactive prompt

CERTIFICATE CHAIN COMPLETION:
The command uses Certificate Transparency logs to complete partial certificate 
chains and identify the proper root certificate. This ensures you always get 
the correct root certificate even from intermediate certificates.

EXAMPLES:
  # Add from remote servers to PEM file
  truststore add example.org --target trusted_certs.pem
  truststore add example.org:443 --target ca-bundle.pem
  
  # Add from local certificate files to PEM file  
  truststore add ca.pem --target trusted_certs.pem
  truststore add /path/to/certificate.crt --target trusted_certs.pem
  
  # Add from protected source keystore
  truststore add source.jks --password=secret --target trusted_certs.pem
  truststore add source.p12 --password --target trusted_certs.pem
  
  # Add to protected target keystore
  truststore add example.org --target keystore.jks --target-password=secret
  truststore add ca.pem --target keystore.p12 --target-password
  
  # Source and target both password-protected  
  truststore add source.jks --password=src_pass --target target.p12 --target-password=tgt_pass

LOADING INDICATORS:
During execution, you'll see progress indicators:
  🔍 Connecting to [server]              - Establishing TLS connection
  📋 Retrieving certificate from [server] - Downloading certificate
  🔗 Completing certificate chain via CT logs - Finding root certificate  
  📂 Reading certificates from [file]    - Loading from source file
  ✏️ Adding certificate to [file]       - Writing to target truststore`,
		Args:         cobra.ExactArgs(1),
		RunE:         runAddCommand,
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

// runAddCommand implements the add command logic
func runAddCommand(cmd *cobra.Command, args []string) error {
	source := args[0]
	target, _ := cmd.Flags().GetString("target")

	// Validate target path
	if err := validateTargetPath(target); err != nil {
		return fmt.Errorf("invalid target path: %w", err)
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
	if isAddDomainSource(source) {
		return handleDomainAdd(source, target, targetPassword)
	}

	// Handle file sources
	return handleFileAdd(source, target, sourcePassword, targetPassword)
}

// handleDomainAdd adds root certificate from a remote server to target file
func handleDomainAdd(domain, target, targetPassword string) error {
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

	// Add root certificate to target file using appropriate handler
	err = addCertificateToTarget(target, rootCert, targetPassword)
	if err != nil {
		return fmt.Errorf("failed to add certificate to %s: %w", target, err)
	}

	// Print success message with enhanced feedback
	printEnhancedSuccessMessage(target, rootCert)

	return nil
}

// handleFileAdd adds root certificate from a local file to target file
func handleFileAdd(sourcePath, target, sourcePassword, targetPassword string) error {
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

	// Get the root certificate (last in chain)
	rootCert := chain[len(chain)-1]

	// Add root certificate to target file using appropriate handler
	err = addCertificateToTarget(target, rootCert, targetPassword)
	if err != nil {
		return fmt.Errorf("failed to add certificate to %s: %w", target, err)
	}

	// Print success message with enhanced feedback
	printEnhancedSuccessMessage(target, rootCert)

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
	defer func() {
		if err := conn.Close(); err != nil {
			// Log connection close error but don't fail the operation
			_ = err
		}
	}()

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
		if err := file.Close(); err != nil {
			// Log but don't fail - file operations already completed
			_ = err
		}
	} else if os.IsNotExist(err) {
		// File doesn't exist, check if we can create it
		file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("cannot create file %s: %w", target, err)
		}
		if err := file.Close(); err != nil {
			// Log but don't fail - file operations already completed
			_ = err
		}
		// Remove the test file
		if err := os.Remove(target); err != nil {
			// Ignore removal error - the file creation test already succeeded
			_ = err // Explicitly acknowledge we're ignoring the error
		}
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
	if err := file.Close(); err != nil {
		// Log but don't fail - file operations already completed
		_ = err
	}

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

// getTargetPassword determines and validates the password for the target file
func getTargetPassword(cmd *cobra.Command, target string) (string, error) {
	// Determine target file type
	targetType := getTargetFileType(target)
	
	// PEM files don't need passwords
	if targetType == "pem" {
		return "", nil
	}

	// JKS and PKCS12 files require passwords
	passwordFlag := cmd.Flags().Lookup("target-password")
	if passwordFlag == nil {
		return "", fmt.Errorf("target-password flag not found")
	}

	// Check if flag was provided
	if !passwordFlag.Changed {
		return "", fmt.Errorf("password required for %s files. Use --target-password=<password> or --target-password to prompt interactively", targetType)
	}

	// Get password value
	password, _ := cmd.Flags().GetString("target-password")
	
	// If password is empty string or "PROMPT", it means flag was provided without value - prompt interactively
	if password == "" || password == "PROMPT" {
		fmt.Printf("Enter password for target %s file: ", targetType)
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println() // Add newline after password input
		password = string(passwordBytes)
	}

	// Validate password is not empty after interactive input
	if password == "" {
		return "", fmt.Errorf("password cannot be empty for %s files", targetType)
	}

	return password, nil
}

// getTargetFileType determines the file type based on extension
func getTargetFileType(target string) string {
	ext := strings.ToLower(filepath.Ext(target))
	switch ext {
	case ".jks":
		return "jks"
	case ".p12", ".pfx":
		return "pkcs12"
	default:
		return "pem"
	}
}

// addCertificateToTarget adds a certificate to the target file using the appropriate handler
func addCertificateToTarget(target string, cert *x509.Certificate, password string) error {
	targetType := getTargetFileType(target)
	
	switch targetType {
	case "pem":
		pemHandler := store.NewPemHandler()
		return pemHandler.AddCertificate(target, cert, "")
	case "jks":
		jksHandler := store.NewJksHandler()
		return jksHandler.AddCertificate(target, cert, password)
	case "pkcs12":
		pkcs12Handler := store.NewPkcs12Handler()
		return pkcs12Handler.AddCertificate(target, cert, password)
	default:
		return fmt.Errorf("unsupported target file type: %s", targetType)
	}
}

// printEnhancedSuccessMessage prints formatted success message with enhanced information
func printEnhancedSuccessMessage(target string, cert *x509.Certificate) {
	targetType := getTargetFileType(target)
	
	fmt.Printf("Successfully added root certificate to %s\n", target)
	fmt.Printf("Certificate Subject: %s\n", cert.Subject.String())
	fmt.Printf("Serial Number: %s\n", cert.SerialNumber.String())
	
	// Include format-specific information
	switch targetType {
	case "jks":
		fmt.Printf("Certificate stored in JKS keystore with auto-generated alias\n")
	case "pkcs12":
		fmt.Printf("Certificate stored in PKCS12 keystore with auto-generated alias\n")
	case "pem":
		fmt.Printf("Certificate appended to PEM file\n")
	}
}

// getSourcePassword determines and validates the password for the source file
func getSourcePassword(cmd *cobra.Command, source string) (string, error) {
	// Determine source file type
	sourceType := getTargetFileType(source) // Reuse the same function
	
	// PEM files don't need passwords
	if sourceType == "pem" {
		return "", nil
	}

	// JKS and PKCS12 files require passwords
	passwordFlag := cmd.Flags().Lookup("password")
	if passwordFlag == nil {
		return "", fmt.Errorf("password flag not found")
	}

	// Check if flag was provided
	if !passwordFlag.Changed {
		return "", fmt.Errorf("password required for %s source files. Use --password=<password> or --password to prompt interactively", sourceType)
	}

	// Get password value
	password, _ := cmd.Flags().GetString("password")
	
	// If password is empty string or "PROMPT", it means flag was provided without value - prompt interactively
	if password == "" || password == "PROMPT" {
		fmt.Printf("Enter password for source %s file: ", sourceType)
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println() // Add newline after password input
		password = string(passwordBytes)
	}

	// Validate password is not empty after interactive input
	if password == "" {
		return "", fmt.Errorf("password cannot be empty for %s files", sourceType)
	}

	return password, nil
}

// readCertificatesFromSourceFile reads certificates from any supported source file type
func readCertificatesFromSourceFile(sourcePath, password string) ([]*x509.Certificate, error) {
	sourceType := getTargetFileType(sourcePath) // Reuse the same function
	
	switch sourceType {
	case "pem":
		return readCertificatesFromFile(sourcePath) // Use existing PEM reader
	case "jks":
		jksHandler := store.NewJksHandler()
		return jksHandler.ReadCertificates(sourcePath, password)
	case "pkcs12":
		pkcs12Handler := store.NewPkcs12Handler()
		return pkcs12Handler.ReadCertificates(sourcePath, password)
	default:
		// Default to PEM for unknown extensions
		return readCertificatesFromFile(sourcePath)
	}
}
