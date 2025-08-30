# truststore CLI

A cross-platform command-line tool for managing digital certificates and truststores across multiple formats (PEM, JKS, PKCS12).

[![Build Status](https://github.com/truststore/cli/actions/workflows/release.yml/badge.svg)](https://github.com/truststore/cli/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/truststore/cli)](https://goreportcard.com/report/github.com/truststore/cli)

## Features

- **Unified certificate management** across PEM, JKS, and PKCS12 formats
- **List certificates** from remote servers and local truststore files
- **Add root certificates** from various sources to truststore files
- **Remove certificates** by identifying them through their source
- **Cross-platform support** for macOS, Linux, and Windows
- **Interactive password prompts** for protected keystores
- **Loading indicators** during network operations and file processing
- **Certificate chain completion** using Certificate Transparency logs

## Installation

### Binary Downloads

Download pre-built binaries from the [releases page](https://github.com/truststore/cli/releases).

#### macOS

```bash
# Intel Macs
curl -L -o truststore https://github.com/truststore/cli/releases/latest/download/truststore-darwin-amd64
chmod +x truststore
sudo mv truststore /usr/local/bin/

# Apple Silicon Macs
curl -L -o truststore https://github.com/truststore/cli/releases/latest/download/truststore-darwin-arm64
chmod +x truststore
sudo mv truststore /usr/local/bin/
```

#### Linux

```bash
# x64
curl -L -o truststore https://github.com/truststore/cli/releases/latest/download/truststore-linux-amd64
chmod +x truststore
sudo mv truststore /usr/local/bin/

# ARM64
curl -L -o truststore https://github.com/truststore/cli/releases/latest/download/truststore-linux-arm64
chmod +x truststore
sudo mv truststore /usr/local/bin/
```

#### Windows

```powershell
# Download truststore.exe from releases page and add to PATH
# Or using PowerShell:
Invoke-WebRequest -Uri "https://github.com/truststore/cli/releases/latest/download/truststore-windows-amd64.exe" -OutFile "truststore.exe"
# Move truststore.exe to a directory in your PATH
```

### From Source

```bash
# Requires Go 1.25.0+
go install github.com/truststore/cli/cmd/truststore@latest
```

## Quick Start

### List Certificates

```bash
# List certificates from a remote server
truststore list example.org

# List certificates from a PEM file
truststore list certificates.pem

# List certificates from a password-protected JKS file
truststore list keystore.jks --password=secret

# List certificates from a PKCS12 file (interactive password prompt)
truststore list keystore.p12 --password
```

### Add Root Certificates

```bash
# Add root certificate from remote server to PEM file
truststore add example.org --target trusted_certs.pem

# Add root certificate from local certificate file
truststore add ca.pem --target trusted_certs.pem

# Add to password-protected JKS file
truststore add example.org --target keystore.jks --target-password=secret
```

### Remove Certificates

```bash
# Remove root certificate by identifying it via remote server
truststore rm example.org --target trusted_certs.pem

# Remove root certificate by identifying it via local certificate file
truststore rm ca.pem --target trusted_certs.pem

# Remove from password-protected PKCS12 file
truststore rm example.org --target keystore.p12 --target-password
```

## Command Reference

### `truststore list [source]`

List certificates from various sources.

**Sources:**
- **Remote servers**: `example.org`, `example.org:443`
- **PEM files**: `certificates.pem`, `ca-bundle.pem`
- **JKS files**: `keystore.jks`, `truststore.jks`
- **PKCS12 files**: `keystore.p12`, `certificate.pfx`

**Flags:**
- `--password`, `-p`: Password for protected keystores (JKS/PKCS12)

**Examples:**
```bash
truststore list google.com
truststore list certificates.pem
truststore list keystore.jks --password=secret
truststore list keystore.p12 -p  # Interactive password prompt
```

### `truststore add [source]`

Add root certificate from a source to a truststore file. The command automatically identifies the root certificate in the chain and adds it to the target file.

**Sources:**
- **Remote servers**: `example.org`, `example.org:443`
- **Local certificate files**: `ca.pem`, `cert.crt`

**Flags:**
- `--target`, `-t`: Target truststore file path (required)
- `--password`, `-p`: Password for source keystore (JKS/PKCS12 sources only)
- `--target-password`: Password for target keystore (JKS/PKCS12 targets only)

**Examples:**
```bash
truststore add example.org --target trusted_certs.pem
truststore add ca.pem --target trusted_certs.pem
truststore add source.jks --password=secret --target keystore.jks --target-password=secret
```

### `truststore rm [source]`

Remove root certificate from a truststore file by identifying it via its source. The command identifies the root certificate through the source and removes it from the target file.

**Sources:**
- **Remote servers**: `example.org`, `example.org:443`
- **Local certificate files**: `ca.pem`, `cert.crt`

**Flags:**
- `--target`, `-t`: Target truststore file path (required)
- `--password`, `-p`: Password for source keystore (JKS/PKCS12 sources only)
- `--target-password`: Password for target keystore (JKS/PKCS12 targets only)

**Examples:**
```bash
truststore rm example.org --target trusted_certs.pem
truststore rm ca.pem --target trusted_certs.pem
truststore rm example.org --target keystore.jks --target-password
```

## Password Handling

The CLI supports multiple ways to provide passwords for protected keystores:

- **Command line**: `--password=secret` or `--target-password=secret`
- **Interactive prompt**: `--password` or `--target-password` (without value)
- **Environment variables**: Not supported for security reasons

Passwords are only held in memory during operations and are never logged or persisted.

## Loading Indicators

The CLI displays loading indicators during long-running operations:

- **🔍 Connecting to [server]**: Establishing TLS connection to remote server
- **📋 Retrieving certificate from [server]**: Downloading certificate from server
- **🔗 Completing certificate chain via CT logs**: Querying Certificate Transparency logs
- **📂 Reading certificates from [file]**: Loading certificates from local file
- **🔍 Searching for certificate in [file]**: Finding specific certificate in truststore
- **✏️ Adding certificate to [file]**: Writing certificate to truststore
- **🗑️ Removing certificate from [file]**: Deleting certificate from truststore

## Supported Formats

### PEM Files
- **Extensions**: `.pem`, `.crt`, `.cer`
- **Description**: Text-based format containing base64-encoded certificates
- **Password**: Not required (PEM files are not password-protected)

### JKS (Java KeyStore)
- **Extensions**: `.jks`
- **Description**: Java's proprietary binary keystore format
- **Password**: Usually required (use `--password` or `--target-password`)

### PKCS#12
- **Extensions**: `.p12`, `.pfx`
- **Description**: Industry-standard binary format for certificates and keys
- **Password**: Usually required (use `--password` or `--target-password`)

## Troubleshooting

### Common Issues

**"connection refused" or "timeout"**
- Check network connectivity
- Verify the server address and port (default is 443 for HTTPS)
- Check firewall settings

**"invalid password" or "keystore was tampered with"**
- Verify the password is correct
- Try using interactive password prompt: `--password` (without value)
- Ensure the file is not corrupted

**"permission denied" when accessing files**
- Check file permissions: `ls -la filename`
- Ensure you have read access to source files and write access to target files
- On Windows, check if the file is locked by another application

**"certificate not found in target truststore"**
- The certificate identified from the source doesn't exist in the target file
- Use `truststore list` to verify certificates in the target truststore
- Ensure you're using the correct source identifier

**"failed to complete certificate chain"**
- Network connectivity issues with Certificate Transparency logs
- Certificate may not be logged in CT logs (rare for public certificates)
- Try again later as CT logs may be temporarily unavailable

### Debug Information

For detailed error information, the CLI provides specific error messages and suggestions. If you encounter persistent issues:

1. Verify file formats are supported
2. Check network connectivity for remote operations
3. Validate file permissions and access rights
4. Ensure passwords are correct for protected files

### Getting Help

Use the built-in help system for detailed information:

```bash
truststore --help                 # General help and available commands
truststore list --help           # Detailed help for list command
truststore add --help            # Detailed help for add command  
truststore rm --help             # Detailed help for rm command
```

## Contributing

We welcome contributions! Here's how to get started:

### Development Setup

1. **Install Go 1.25.0** using asdf:
   ```bash
   asdf install golang 1.25.0
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/truststore/cli.git
   cd cli
   ```

3. **Install dependencies**:
   ```bash
   make deps
   ```

4. **Build the project**:
   ```bash
   make build
   ```

### Development Workflow

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Build for all platforms
make build-all

# Clean build artifacts
make clean
```

### Code Standards

- Follow standard Go conventions and idioms
- All code must pass `golangci-lint` (run `make lint`)
- Write tests for new functionality (`*_test.go` files)
- Maintain >80% test coverage
- Never discard errors - handle or wrap them appropriately

### Testing

- **Unit tests**: Located alongside source code in `*_test.go` files
- **Integration tests**: Test actual CLI command execution
- **Manual testing**: Validate examples in documentation work correctly

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes following the code standards
4. Run tests and linting: `make test lint`
5. Commit your changes with descriptive messages
6. Push to your fork and submit a pull request

### Project Structure

```
├── cmd/truststore/        # CLI entry point and root command
├── internal/app/          # Command implementations (list, add, rm)
├── internal/service/      # Business logic services
├── internal/client/       # External API clients (CT logs)
├── internal/store/        # Truststore format handlers (PEM, JKS, PKCS12)
├── docs/                  # Documentation and architecture
├── dist/                  # Build output (generated)
└── Makefile              # Development tasks
```

## License

[Add your license here]

## Version

Current version: `dev` (development)

For release versions, see the [releases page](https://github.com/truststore/cli/releases).