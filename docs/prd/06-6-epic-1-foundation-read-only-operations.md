### 6. Epic 1: Foundation & Read-Only Operations

**Goal:** This epic lays the groundwork for the entire application. It will establish the basic CLI command structure, handle argument parsing, and implement the complete read-only `list` functionality. By the end of this epic, a user will have a functional tool that can inspect certificate chains from both remote servers and all supported local truststore file types.

***

#### **Story 1.1: Basic CLI Scaffolding**

*As a developer,*
*I want to set up the basic Go project structure and a CLI framework,*
*so that I have a foundation for adding commands and arguments.*

**Acceptance Criteria:**

1. A Go project is initialized with a standard directory layout.
2. A CLI framework (e.g., Cobra) is integrated to handle commands and flags.
3. A root `truststore` command with a functional `--help` flag is created.
4. A placeholder `list` subcommand is created.

***

#### **Story 1.2: List Certificates from a Remote Server**

*As a system administrator,*
*I want to run `truststore list example.org`,*
*so that I can quickly inspect the TLS certificate chain of a live server.*

**Acceptance Criteria:**

1. The `list` command accepts a domain name (with optional port) as an argument.
2. The CLI connects to the server over TLS and successfully retrieves the certificate chain.
3. Certificate details (e.g., Subject, Issuer, Validity) for each certificate in the chain are printed to the console in a clear, human-readable format.
4. Connection errors (e.g., DNS lookup failed, connection refused) are handled gracefully and reported to the user.

***

#### **Story 1.3: List Certificates from a PEM file**

*As a developer,*
*I want to run `truststore list my_certs.pem`,*
*so that I can verify the contents of a PEM-formatted certificate file.*

**Acceptance Criteria:**

1. The `list` command can distinguish between a domain and a local file path argument.
2. The CLI can read and parse one or more certificates from a specified PEM file.
3. Certificate details are printed to the console in the same format used for remote lookups.
4. File-not-found and parsing errors are handled gracefully.

***

#### **Story 1.4: List Certificates from JKS and PKCS12 files**

*As a Java developer,*
*I want to run `truststore list keystore.jks --password mysecret`,*
*so that I can inspect the contents of my application's keystore without using `keytool`.*

**Acceptance Criteria:**

1. The `list` command accepts a `--password` flag for protected truststores.
2. The CLI can successfully read and parse certificates from a JKS file.
3. The CLI can successfully read and parse certificates from a PKCS12 file.
4. The output format is consistent with all other `list` commands.
5. Clear error messages are provided for incorrect passwords or corrupted files.
