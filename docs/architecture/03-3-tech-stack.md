### 3. Tech Stack

#### Cloud Infrastructure

This project is a self-contained CLI tool that runs on a user's local machine. It does not require dedicated cloud infrastructure. It only makes outbound requests to public services (remote servers for TLS certificates and Certificate Transparency log APIs), which does not necessitate provisioning our own cloud resources.

#### Technology Stack Table

The following table lists the specific technologies and versions that will be used to build the project. These choices are considered final and will be the single source of truth for development.

| Category | Technology | Version | Purpose | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Language** | Go | 1.25.0 | Primary development language | As per PRD: excellent for fast, cross-platform, single-binary CLIs with strong networking/crypto libraries. |
| **CLI Framework** | `github.com/spf13/cobra` | v1.8.0 | Building the CLI command structure | The most popular and robust CLI library for Go. Provides commands, flags, and help text generation. |
| **JKS Library** | `github.com/pavlo-v-chernykh/keystore-go` | v4.5.0 | Reading/writing JKS files | A well-maintained, pure Go library that supports the required Java Keystore format. |
| **PKCS12 Library** | `software.sslmate.com/src/go-pkcs12` | v0.6.0 | Reading/writing PKCS12 files | A specialized, robust library from a trusted source (SSLMate) for handling the PKCS12 format. |
| **Testing** | Go Standard Library (`testing`) | 1.25.0 | Unit and Integration testing | Go's built-in testing package is simple, powerful, and the standard for the ecosystem. No external framework needed. |
| **Linting** | `golangci-lint` | v1.59.1 | Code quality and style enforcement | The de-facto standard meta-linter for Go projects. Enforces idiomatic code and catches common errors. |
| **Dev Tooling** | `asdf` | 0.18.0 | Tool version management | Ensures consistent development environments across the team for all languages and tools. |
| **Dev Tooling** | `asdf-golang` | (managed by asdf) | `asdf` plugin for Go | Manages the project's Go version via the `.tool-versions` file, ensuring consistency. |
| **Dev Tooling** | `java` (Temurin) | 17.0.16+8 | JKS test data generation | Provides `keytool` for generating JKS test files during development and testing. |
| **CI/CD** | GitHub Actions | N/A | Automation of testing and releases | As per PRD: Native to GitHub, excellent integration for building, testing, and deploying binaries to GitHub Releases. |
