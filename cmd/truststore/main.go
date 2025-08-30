package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/truststore/cli/internal/app"
)

var (
	// Version information - will be set during build
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// newRootCommand creates and configures the root command
func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "truststore",
		Short: "A command-line tool for managing digital certificates and truststores",
		Long: `truststore is a cross-platform CLI tool for managing digital certificates 
and truststores across multiple formats (PEM, JKS, PKCS12).

FEATURES:
• List certificates from remote servers and local truststore files
• Add root certificates from various sources to truststore files  
• Remove certificates by identifying them through their source
• Support for PEM, JKS, and PKCS12 formats
• Interactive password prompts for protected keystores
• Cross-platform support (macOS, Linux, Windows)

COMMON WORKFLOWS:
  # List certificates from a remote server
  truststore list example.org

  # Add root certificate from server to PEM file  
  truststore add example.org --target trusted_certs.pem

  # Remove certificate by identifying via server
  truststore rm example.org --target trusted_certs.pem

  # Work with password-protected keystores
  truststore list keystore.jks --password
  truststore add ca.pem --target keystore.p12 --target-password

Use "truststore [command] --help" for detailed information about each command.`,
		Version: version,
	}

	// Register subcommands
	cmd.AddCommand(app.NewListCommand())
	cmd.AddCommand(app.NewAddCommand())
	cmd.AddCommand(app.NewRmCommand())

	return cmd
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = newRootCommand()

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.truststore.yaml)")
}

func main() {
	Execute()
}
