package main

import (
	"strings"
	"testing"
)

func TestRootCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "help flag",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "truststore is a cross-platform CLI tool",
		},
		{
			name:     "version flag",
			args:     []string{"--version"},
			wantErr:  false,
			contains: "truststore version",
		},
		{
			name:     "no arguments shows help",
			args:     []string{},
			wantErr:  false,
			contains: "Available Commands",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh root command for each test
			cmd := newRootCommand()
			cmd.SetArgs(tt.args)

			// Capture output
			var output strings.Builder
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Execute()

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.contains != "" {
				got := output.String()
				if !strings.Contains(got, tt.contains) {
					t.Errorf("Execute() output = %q, want containing %q", got, tt.contains)
				}
			}
		})
	}
}

func TestRootCommandStructure(t *testing.T) {
	cmd := newRootCommand()

	// Test command properties
	if cmd.Use != "truststore" {
		t.Errorf("Expected Use to be 'truststore', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected Short description to be non-empty")
	}

	if cmd.Long == "" {
		t.Error("Expected Long description to be non-empty")
	}

	if cmd.Version != version {
		t.Errorf("Expected Version to be %q, got %q", version, cmd.Version)
	}

	// Test that subcommands are registered
	listCmd, _, err := cmd.Find([]string{"list"})
	if err != nil {
		t.Errorf("Expected to find 'list' subcommand, got error: %v", err)
	}

	if listCmd == nil || listCmd.Use != "list [source]" {
		t.Error("Expected 'list' subcommand to be properly registered")
	}
}
