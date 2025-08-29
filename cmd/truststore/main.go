package main

import (
	"fmt"
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

It provides unified operations for listing, adding, and removing certificates 
from various sources including remote servers and local files.`,
		Version: version,
	}

	// Register subcommands
	cmd.AddCommand(app.NewListCommand())
	cmd.AddCommand(app.NewAddCommand())

	return cmd
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = newRootCommand()

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
