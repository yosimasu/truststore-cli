# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

The `truststore` CLI is a cross-platform command-line tool for managing digital certificates and truststores. It provides unified operations for listing, adding, and removing certificates across multiple formats (PEM, JKS, PKCS12) and sources (remote servers, local files).

## Development Commands

### Setup
```bash
# Install Go 1.25.0 via asdf
asdf install golang 1.25.0

# Initialize Go module and dependencies
go mod tidy
```

### Build & Test
```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Run all tests
make test

# Run linting
make lint

# Clean build artifacts
make clean
```

### Testing Commands
```bash
# Run unit tests with coverage
go test -v -cover ./...

# Run specific test
go test -v ./internal/store -run TestPemHandler

# Run integration tests (when implemented)
go test -v ./test/...

# Run tests without network dependencies
go test -v -tags=unit ./...
```

## Architecture Overview

### Core Architecture Pattern
The project follows a **layered architecture** with **strategy pattern** for truststore format handling:

- **CLI Layer**: Cobra commands (`internal/app/`)
- **Service Layer**: Business logic orchestration (`internal/service/`)
- **Data Access Layer**: Format-specific handlers (`internal/store/`)
- **External Clients**: Certificate Transparency API integration (`internal/client/`)

### Key Components
- **Truststore Service**: Central orchestrator that determines file formats and delegates operations
- **Certificate Chain Service**: Builds complete certificate chains using CT logs
- **Truststore Handlers**: Strategy pattern implementations for PEM, JKS, PKCS12 formats
- **CT Log Client**: HTTP client for certificate transparency log queries

### Technology Stack
- **Go 1.25.0** (managed via asdf)
- **CLI Framework**: `github.com/spf13/cobra` v1.8.0
- **JKS Support**: `github.com/pavlo-v-chernykh/keystore-go` v4.5.0
- **PKCS12 Support**: `software.sslmate.com/src/go-pkcs12` v0.6.0

## Critical Implementation Rules

### Error Handling
- Never discard errors with `_`
- Use `fmt.Errorf` with `%w` verb for error wrapping
- Return errors up the call stack until handled at command level

### Interface Usage
All major services must be implemented via interfaces:
- `TruststoreService`
- `JksHandler`, `PemHandler`, `Pkcs12Handler`
- Enables dependency injection and testing

### Security Requirements
- Passwords must only exist in memory during operations
- Never log passwords or sensitive certificate details
- Use HTTPS/TLS for all external API communications

## Testing Strategy

### Test Organization
- **Unit Tests**: `*_test.go` files co-located with source
- **Integration Tests**: Located in `test/` directory
- **Test Data**: Stored in `testdata/` subdirectories within packages

### Coverage Goals
- Target: >80% unit test coverage
- Use Go's built-in `testing` package
- Mock external dependencies using interfaces

### External API Testing
- Mock `crt.sh` API using `net/http/httptest`
- End-to-end tests run separately (not in standard test suite)

## Build Output Structure

```
dist/
├── truststore              # Current platform binary
├── darwin/
│   ├── amd64/truststore    # macOS Intel
│   └── arm64/truststore    # macOS ARM
├── linux/
│   ├── amd64/truststore    # Linux x64
│   └── arm64/truststore    # Linux ARM
└── windows/
    └── amd64/truststore.exe # Windows x64
```

## External Dependencies

The project integrates with Certificate Transparency logs via `crt.sh`:
- Search: `GET https://crt.sh/?CN=<name>&output=json&exclude=expired`
- Download: `GET https://crt.sh/?d=<id>`

This enables automatic certificate chain completion for add/remove operations.

## Documentation

Complete architectural documentation is available in `docs/architecture/` with detailed sections on:
- Component design and interactions
- Security requirements and data protection
- Deployment strategy and CI/CD pipeline
- Detailed coding standards and patterns