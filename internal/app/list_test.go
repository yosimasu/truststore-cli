package app

import (
	"strings"
	"testing"
)

func TestNewListCommand(t *testing.T) {
	cmd := NewListCommand()

	// Test command properties
	if cmd.Use != "list [source]" {
		t.Errorf("Expected Use to be 'list [source]', got %q", cmd.Use)
	}

	if cmd.Short == "" {
		t.Error("Expected Short description to be non-empty")
	}

	if cmd.Long == "" {
		t.Error("Expected Long description to be non-empty")
	}

	// Test that password flag is available
	passwordFlag := cmd.Flags().Lookup("password")
	if passwordFlag == nil {
		t.Error("Expected 'password' flag to be available")
	}

	if passwordFlag.Shorthand != "p" {
		t.Errorf("Expected password flag shorthand to be 'p', got %q", passwordFlag.Shorthand)
	}
}

func TestListCommandExecution(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantErr  bool
		contains string
	}{
		{
			name:     "list help",
			args:     []string{"--help"},
			wantErr:  false,
			contains: "List certificates from various sources",
		},
		{
			name:    "list with domain",
			args:    []string{"example.org"},
			wantErr: false,
		},
		{
			name:    "list with domain and port",
			args:    []string{"example.org:443"},
			wantErr: false,
		},
		{
			name:    "list with password flag",
			args:    []string{"keystore.jks", "--password", "secret"},
			wantErr: false,
		},
		{
			name:    "list with password shorthand",
			args:    []string{"keystore.p12", "-p", "secret"},
			wantErr: false,
		},
		{
			name:    "list without arguments",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "list with too many arguments",
			args:    []string{"arg1", "arg2"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewListCommand()
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

func TestRunListCommand(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		password string
		wantErr  bool
	}{
		{
			name:     "run with domain",
			args:     []string{"example.org"},
			password: "",
			wantErr:  false,
		},
		{
			name:     "run with domain and password",
			args:     []string{"keystore.jks"},
			password: "secret",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewListCommand()
			if tt.password != "" {
				cmd.SetArgs(append(tt.args, "--password", tt.password))
			} else {
				cmd.SetArgs(tt.args)
			}

			err := runListCommand(cmd, tt.args)

			if (err != nil) != tt.wantErr {
				t.Errorf("runListCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
