### 13. Security

#### Input Validation

* **Validation Library:** None required. We will use custom validation functions.
* **Validation Location:** All user-provided input (file paths, domain names) will be validated at the beginning of each command's execution.
* **Required Rules:**
  * File paths must be validated for existence and correct permissions before being used.
  * Domain names must be validated to be syntactically correct.

#### Authentication & Authorization

* N/A. The tool operates on local files and public APIs. It does not have its own user authentication system and relies on the user's underlying OS-level file permissions.

#### Secrets Management

* **Code Requirements:**
  * The tool handles user-provided passwords for truststores via command-line flags. These passwords must ONLY exist in memory for the minimum time required for the operation and MUST NEVER be logged or stored.

#### API Security

* N/A. The tool is a client of external APIs; it does not expose an API itself.

#### Data Protection

* **Encryption in Transit:** All communication with external APIs (`crt.sh`, remote TLS servers) MUST use HTTPS/TLS.
* **Logging Restrictions:** Do not log file contents or full certificate details unless the `--verbose` flag is enabled. Never log passwords.

#### Dependency Security

* **Scanning Tool:** We will integrate Go's official vulnerability scanner, `govulncheck`, into the CI pipeline to scan for known vulnerabilities in our dependencies.
* **Update Policy:** Dependencies will be reviewed and updated on a regular basis.

#### Security Testing

* **SAST Tool:** We will use the `gosec` static analysis tool, integrated into our `golangci-lint` configuration, to automatically scan for security issues in the Go code on every CI run.
