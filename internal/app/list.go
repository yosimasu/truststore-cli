package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/truststore/cli/internal/service"
)

// NewListCommand creates the list subcommand
func NewListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list [source]",
		Short: "List certificates from a source",
		Long: `List certificates from various sources including:
  - Remote servers (e.g., example.org, example.org:443)
  - Local PEM files (e.g., certificates.pem)  
  - Local JKS files (e.g., keystore.jks)
  - Local PKCS12 files (e.g., keystore.p12)

Examples:
  truststore list example.org
  truststore list example.org:443
  truststore list certificates.pem
  truststore list keystore.jks --password secret
  truststore list keystore.p12 --password secret`,
		Args: cobra.ExactArgs(1),
		RunE: runListCommand,
	}

	// Add flags for password-protected keystores
	cmd.Flags().StringP("password", "p", "", "Password for protected keystores (JKS/PKCS12)")

	return cmd
}

// runListCommand implements the list command logic
func runListCommand(cmd *cobra.Command, args []string) error {
	source := args[0]
	password, _ := cmd.Flags().GetString("password")

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
	// Placeholder for future stories (1.3 and 1.4)
	fmt.Printf("🔍 Listing certificates from file: %s\n", source)
	if password != "" {
		fmt.Println("🔐 Using provided password for protected keystore")
	}
	fmt.Println("📋 File-based certificate listing will be implemented in future stories")

	return nil
}
