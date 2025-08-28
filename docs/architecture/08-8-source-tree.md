# Source Tree

```plaintext
/
├── .github/
│   └── workflows/
│       └── release.yml       # GitHub Actions workflow for building/releasing binaries
├── cmd/
│   └── truststore/
│       └── main.go           # Entry point, Cobra command setup & wiring
├── dist/                     # Build output directory (gitignored)
│   ├── truststore            # Current platform binary (symlink or copy)
│   ├── darwin/
│   │   ├── amd64/truststore  # macOS Intel binary
│   │   └── arm64/truststore  # macOS Apple Silicon binary
│   ├── linux/
│   │   ├── amd64/truststore  # Linux x64 binary
│   │   └── arm64/truststore  # Linux ARM64 binary
│   └── windows/
│       └── amd64/truststore.exe  # Windows x64 binary
├── docs/
│   ├── prd.md
│   └── architecture.md
├── internal/
│   ├── app/                  # Connects CLI commands to services
│   │   ├── list.go
│   │   ├── add.go
│   │   └── rm.go
│   ├── service/
│   │   ├── truststore.go     # Truststore Service orchestrator
│   │   └── chain.go          # Certificate Chain Completion Service
│   ├── client/
│   │   └── ctlog.go          # Client for the crt.sh API
│   └── store/
│       ├── interface.go      # The Truststore interface definition
│       ├── pem.go            # PEM file handler
│       ├── jks.go            # JKS file handler
│       └── pkcs12.go         # PKCS12 file handler
├── .gitignore
├── go.mod                    # Go module definition
├── go.sum
├── Makefile                  # For common development tasks (build, test, lint, clean)
├── README.md
└── .tool-versions            # For asdf to manage Go version
```
