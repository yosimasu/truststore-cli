# truststore CLI Product Requirements Document (PRD)

### 1. Goals and Background Context

#### Goals
*   Create a command-line interface (CLI) tool named `truststore`.
*   The tool will allow users to list certificate chains from a remote server or a local truststore file.
*   The tool will enable adding root certificates from a remote server or a local file to a specified target truststore.
*   The tool will enable removing root certificates from a specified target truststore.
*   The tool will support common truststore formats, including PEM, JKS, and PKCS12, including password protection.
*   The tool will ensure operational integrity by fetching missing issuer certificates (via Certificate Transparency logs) before adding or removing root certificates.
*   The final product will be a self-contained, cross-platform binary compatible with macOS, Linux, and Windows.

#### Background Context
Managing digital certificates and truststores is a frequent and critical task for developers, DevOps engineers, and system administrators. However, existing tools like Java's `keytool` or `openssl` are often overly complex, platform-specific, and have inconsistent interfaces for different formats (JKS, PEM, PKCS12). This complexity creates a steep learning curve, leads to frequent errors, and wastes valuable time on a crucial security procedure.

The `truststore` CLI directly addresses this problem by providing a single, intuitive, and cross-platform tool. It aims to dramatically simplify and streamline TLS/SSL configuration by offering a unified interface for inspecting, adding, and removing certificates from any supported source or target. The goal is to make proper certificate management more accessible, efficient, and less error-prone.

#### Change Log
| Date | Version | Description | Author |
| :--- | :--- | :--- | :--- |
| 2025-08-26 | 1.0 | Initial draft. Updated context after 5 Whys. | John (PM) |

### 2. Requirements

#### Functional
*   **FR1:** The CLI MUST be able to retrieve and display the certificate chain from a specified remote server (e.g., `example.org:443`).
*   **FR2:** The CLI MUST be able to read and display the certificate chain from a local truststore file in PEM, JKS, or PKCS12 format.
*   **FR3:** The CLI MUST support password-protected JKS and PKCS12 files.
*   **FR4:** The CLI MUST be able to add the root certificate from a remote server's chain to a new or existing target truststore file (PEM, JKS, PKCS12).
*   **FR5:** The CLI MUST be able to add a root certificate from a local source file to a new or existing target truststore file.
*   **FR6:** The CLI MUST be able to remove a root certificate from a target truststore by identifying the certificate chain via a source (remote server or local file).
*   **FR7:** The CLI MUST provide clear, human-readable output for certificate details (e.g., subject, issuer, validity).
*   **FR8:** Before adding or removing a root certificate, the CLI SHOULD attempt to build a complete certificate chain by fetching missing issuer certificates from a public Certificate Transparency log service (e.g., crt.sh).

#### Non-Functional
*   **NFR1:** The CLI MUST be distributed as a single, self-contained binary for macOS, Linux, and Windows.
*   **NFR2:** The CLI SHOULD have a fast startup time, with operations completing in under 2 seconds for typical use cases.
*   **NFR3:** The CLI MUST provide helpful error messages for common issues (e.g., connection failed, file not found, incorrect password).
*   **NFR4:** The command-line arguments and flags SHOULD follow common POSIX conventions.

### 3. User Interface Design Goals

#### Overall UX Vision
The CLI should feel simple, reliable, and powerful. It should follow the "principle of least surprise," behaving in a way that experienced CLI users would expect. The user experience should be fast and responsive, providing immediate and clear feedback.

#### Key Interaction Paradigms
The CLI will use a standard `command subcommand [arguments] --flags` structure. This is a well-understood and predictable paradigm for command-line tools.
*Example:* `truststore add cacert.pem --target truststore.jks`

#### Core Screens and Views
This refers to the primary output formats the user will see.
*   **Certificate List View:** A clear, well-formatted table or list showing key certificate details (e.g., Subject, Issuer, Validity, Algorithm).
*   **Success/Error Messages:** Concise, human-readable, and helpful messages that confirm success or guide the user in correcting errors.
*   **Help View:** A standard `--help` output for the main command and all subcommands, detailing usage, arguments, and flags.

#### Accessibility: WCAG AA
Output will be plain text by default for maximum compatibility with terminals and screen readers. If colors are used to enhance readability, they will be optional and tested for high contrast (WCAG AA).

#### Branding
The tool will be consistently named `truststore` in all lowercase.

#### Target Device and Platforms: Cross-Platform
The CLI will be a native binary for use in terminals on macOS, Linux, and Windows.

### 4. Technical Assumptions

#### Repository Structure: Single Repository
A single repository will be used to house all the code for this project. This is straightforward and appropriate for a self-contained tool.

#### Service Architecture: Monolith
The application will be a single monolithic binary. This is the standard and most efficient architecture for a command-line tool.

#### Testing Requirements: Unit + Integration
The project will require both unit tests for individual functions and integration tests that run actual CLI commands to verify interactions with the file system and network.

#### Additional Technical Assumptions and Requests
*   **Language:** **Go (Golang)** is recommended. It excels at creating fast, self-contained, cross-platform binaries and has a strong standard library for networking and file I/O, making it a perfect fit for this project.
*   **Libraries:** We will prefer the Go standard library where possible to minimize external dependencies.
*   **Deployment:** Binaries for macOS, Linux, and Windows will be built and attached to releases on GitHub.

### 5. Epic List

*   **Epic 1: Foundation & Read-Only Operations:** Establish the core CLI structure, argument parsing, and implement the `list` command for both remote servers and local files to provide initial inspection capabilities.
*   **Epic 2: Certificate Write Operations:** Implement the `add` command to enable users to add certificates from various sources into target truststores, delivering the core modification feature.
*   **Epic 3: Certificate Removal & Finalization:** Implement the `rm` (remove) command, and finalize the project with comprehensive testing, user documentation, and automated cross-platform builds.

### 6. Epic 1: Foundation & Read-Only Operations

**Goal:** This epic lays the groundwork for the entire application. It will establish the basic CLI command structure, handle argument parsing, and implement the complete read-only `list` functionality. By the end of this epic, a user will have a functional tool that can inspect certificate chains from both remote servers and all supported local truststore file types.

---

#### **Story 1.1: Basic CLI Scaffolding**
*As a developer,*
*I want to set up the basic Go project structure and a CLI framework,*
*so that I have a foundation for adding commands and arguments.*

**Acceptance Criteria:**
1.  A Go project is initialized with a standard directory layout.
2.  A CLI framework (e.g., Cobra) is integrated to handle commands and flags.
3.  A root `truststore` command with a functional `--help` flag is created.
4.  A placeholder `list` subcommand is created.

---

#### **Story 1.2: List Certificates from a Remote Server**
*As a system administrator,*
*I want to run `truststore list example.org`,*
*so that I can quickly inspect the TLS certificate chain of a live server.*

**Acceptance Criteria:**
1.  The `list` command accepts a domain name (with optional port) as an argument.
2.  The CLI connects to the server over TLS and successfully retrieves the certificate chain.
3.  Certificate details (e.g., Subject, Issuer, Validity) for each certificate in the chain are printed to the console in a clear, human-readable format.
4.  Connection errors (e.g., DNS lookup failed, connection refused) are handled gracefully and reported to the user.

---

#### **Story 1.3: List Certificates from a PEM file**
*As a developer,*
*I want to run `truststore list my_certs.pem`,*
*so that I can verify the contents of a PEM-formatted certificate file.*

**Acceptance Criteria:**
1.  The `list` command can distinguish between a domain and a local file path argument.
2.  The CLI can read and parse one or more certificates from a specified PEM file.
3.  Certificate details are printed to the console in the same format used for remote lookups.
4.  File-not-found and parsing errors are handled gracefully.

---

#### **Story 1.4: List Certificates from JKS and PKCS12 files**
*As a Java developer,*
*I want to run `truststore list keystore.jks --password mysecret`,*
*so that I can inspect the contents of my application's keystore without using `keytool`.*

**Acceptance Criteria:**
1.  The `list` command accepts a `--password` flag for protected truststores.
2.  The CLI can successfully read and parse certificates from a JKS file.
3.  The CLI can successfully read and parse certificates from a PKCS12 file.
4.  The output format is consistent with all other `list` commands.
5.  Clear error messages are provided for incorrect passwords or corrupted files.

### Epic 2: Root Certificate Write Operations

**Goal:** This epic introduces the core modification capabilities of the tool. It will build upon the foundation of Epic 1 by implementing the `add` command, allowing users to insert new root certificates into all supported truststore formats. This transforms the tool from a simple inspection utility into a powerful management solution.

---

#### **Story 2.1: Certificate Chain Completion Service**
*As a developer,*
*I want to create an internal service that can take a certificate and build its complete chain by fetching missing issuers,*
*so that the `add` and `rm` commands can operate on a full, validated chain.*

**Acceptance Criteria:**
1.  A new internal function/service is created that takes a certificate as input.
2.  If the certificate's issuer is not available, it queries a public Certificate Transparency log service (like `crt.sh`).
3.  It recursively fetches issuer certificates until a self-signed root is found or no more issuers can be found.
4.  The function returns a complete (or most complete possible) certificate chain.
5.  The service gracefully handles network errors and cases where the issuer cannot be found in the CT log.
6.  A loading indicator is displayed during network operations when querying Certificate Transparency logs.

---

#### **Story 2.2: Add Root Certificate from Remote Server to PEM File**
*As a DevOps engineer,*
*I want to run `truststore add example.org --target trusted_certs.pem`,*
*so that I can quickly add a new server's root CA certificate to my application's trust list.*

**Acceptance Criteria:**
1.  A new `add` subcommand is created within the CLI framework.
2.  The command accepts a source (remote server) and a `--target` file path.
3.  The CLI uses the Certificate Chain Completion Service (Story 2.1) to retrieve and validate the full certificate chain.
4.  The identified root certificate is appended to the target PEM file. If the file doesn't exist, it is created.
5.  A clear success message is printed to the console.
6.  File write permissions and other I/O errors are handled gracefully.
7.  A loading indicator is displayed while retrieving certificates from remote servers and completing certificate chains.

---

#### **Story 2.3: Add Root Certificate from a Local File to PEM File**
*As a developer,*
*I want to run `truststore add new_ca.pem --target existing_truststore.pem`,*
*so that I can add a CA certificate from a file to my truststore.*

**Acceptance Criteria:**
1.  The `add` command accepts a local file path as a source.
2.  The CLI reads the certificate from the source file.
3.  The CLI uses the Certificate Chain Completion Service (Story 2.1) to validate the certificate and its chain.
4.  The identified root certificate is appended to the target PEM file.
5.  A success message confirms the operation.
6.  A loading indicator is displayed during certificate chain completion and validation operations.

---

#### **Story 2.4: Add Root Certificate to JKS and PKCS12 Files**
*As a Java developer,*
*I want to run `truststore add ca.pem --target keystore.jks --target-password mysecret`,*
*so that I can import a new Certificate Authority into my application's keystore without complex commands.*

**Acceptance Criteria:**
1.  The `add` command supports a `--target-password` flag for the destination truststore.
2.  The CLI uses the Certificate Chain Completion Service (Story 2.1) to validate the source certificate.
3.  The CLI can add the identified root certificate (from a remote or local source) to a JKS file.
4.  The CLI can add the identified root certificate (from a remote or local source) to a PKCS12 file.
5.  If the target JKS or PKCS12 file doesn't exist, it is created with the new root certificate.
6.  The user can specify a certificate alias with a flag (e.g., `--alias my_new_cert`); if not provided, a default alias is generated.
7.  A success message is printed, including the alias of the added certificate.
8.  Handles incorrect passwords and file write errors gracefully.
9.  A loading indicator is displayed during certificate chain completion, validation, and truststore write operations.

### Epic 3: Certificate Removal & Finalization

**Goal:** This final epic completes the core functionality by implementing the `rm` (remove) command, which intelligently identifies a root certificate via a source and removes it from a target truststore. It also focuses on project finalization, including robust testing, comprehensive user documentation, and setting up an automated build and release process to deliver the cross-platform binaries.

---

#### **Story 3.1: Remove Root Certificate from Truststore via Source Identifier**
*As a security administrator,*
*I want to remove a root certificate from my truststore by specifying the server or certificate file that uses it,*
*so that I can easily remove trust for a specific entity without needing to know the exact alias in my truststore.*

**Acceptance Criteria:**
1.  The `rm` command accepts a source identifier (a remote server or a local certificate file) and a `--target` truststore file.
2.  The CLI uses the Certificate Chain Completion Service (Story 2.1) on the source identifier to find its corresponding root certificate.
3.  The CLI then searches the `--target` truststore for that specific root certificate.
4.  If the root certificate is found in the target truststore, it is removed.
5.  A clear success message is printed.
6.  A helpful error is shown if the identified root certificate is not found in the target truststore.
7.  The command works for all supported truststore formats (PEM, JKS, PKCS12), using passwords where necessary.
8.  A loading indicator is displayed during certificate chain completion, truststore searching, and certificate removal operations.

---

#### **Story 3.2: Comprehensive User Documentation**
*As a new user,*
*I want to read a `README.md` file and access comprehensive help text,*
*so that I can understand what the tool does, how to install it, and how to use all its commands without external documentation.*

**Acceptance Criteria:**

**README Documentation:**
1.  A high-quality `README.md` file is created in the project root with:
    *   Clear project description and value proposition
    *   Installation instructions for all platforms (macOS, Linux, Windows)
    *   Quick start guide with the most common use cases
    *   Complete usage examples for every command (`list`, `add`, `rm`)
    *   All flags documented with examples (e.g., `--password`, `--target`, `--alias`, `--verbose`)
    *   Loading indicator behavior and what it indicates during operations
    *   Troubleshooting section for common issues
    *   "Contributing" section outlining how developers can contribute

**Built-in Help System:**
2.  The root `truststore --help` command displays:
    *   Tool description and version
    *   Available subcommands with brief descriptions
    *   Global flags (e.g., `--verbose`, `--help`)
    *   Usage examples for common workflows

3.  Each subcommand provides comprehensive help via `truststore <command> --help`:
    *   **`truststore list --help`**: Shows all supported source types (remote server, PEM, JKS, PKCS12), required and optional flags, and usage examples
    *   **`truststore add --help`**: Documents source and target options, password handling, alias specification, complete workflow examples, and loading indicator behavior
    *   **`truststore rm --help`**: Explains source identification, target specification, removal confirmation process, and loading indicator behavior

**Help Text Quality Standards:**
4.  All help text must be:
    *   Consistent in format and terminology across all commands
    *   Include practical examples for each major use case
    *   Explain flag interactions and dependencies (e.g., `--password` with JKS/PKCS12 files)
    *   Provide clear error message explanations and resolutions

**Validation Requirements:**
5.  Manual testing confirms that:
    *   A user can accomplish any documented workflow using only the built-in help
    *   All flags and combinations mentioned in help text work correctly
    *   Help text examples can be copy-pasted and executed successfully
    *   Error messages referenced in documentation match actual CLI output

---

#### **Story 3.3: Automated Cross-Platform Builds and Releases**
*As the project maintainer,*
*I want the build and release process to be automated,*
*so that I can easily and reliably publish new versions of the tool.*

**Acceptance Criteria:**
1.  A CI/CD pipeline (e.g., using GitHub Actions) is configured.
2.  The pipeline automatically runs all unit and integration tests on every push and pull request.
3.  When a new version is tagged (e.g., `v1.1.0`), the pipeline automatically builds the binaries for macOS, Linux, and Windows.
4.  The compiled binaries are automatically attached to a new GitHub Release.
5.  The release notes are populated from the git commit history or a changelog file.

### 7. Checklist Results Report

#### Executive Summary
*   **Overall PRD completeness:** 95%
*   **MVP scope appropriateness:** Just Right
*   **Readiness for architecture phase:** Ready
*   **Most critical gaps or concerns:** None. The cross-functional requirements could be more detailed in a larger project, but are sufficient here.

#### Category Analysis Table
| Category | Status | Critical Issues |
| :--- | :--- | :--- |
| 1. Problem Definition & Context | PASS | None |
| 2. MVP Scope Definition | PASS | None |
| 3. User Experience Requirements | PASS | None |
| 4. Functional Requirements | PASS | None |
| 5. Non-Functional Requirements | PASS | None |
| 6. Epic & Story Structure | PASS | None |
| 7. Technical Guidance | PASS | None |
| 8. Cross-Functional Requirements | PARTIAL | Details on data retention/schema are implicit. Sufficient for MVP. |
| 9. Clarity & Communication | PASS | None |

#### Top Issues by Priority
*   **BLOCKERS:** None.
*   **HIGH:** None.
*   **MEDIUM:** None.
*   **LOW:** None.

#### MVP Scope Assessment
The MVP scope defined by the three epics is well-defined, realistic, and delivers incremental value. It is a true MVP.

#### Technical Readiness
The technical constraints and guidance are clear and sufficient for the architect to begin their work. No major technical risks have been identified.

#### Recommendations
No major recommendations. The PRD is solid.

#### Final Decision
*   **READY FOR ARCHITECT**: The PRD and epics are comprehensive, properly structured, and ready for architectural design.

### 8. Next Steps

#### UX Expert Prompt
This project is a command-line interface (CLI) and does not have a graphical user interface. The UI/UX goals for the CLI have been defined in the PRD. No further UX design is required at this stage.

#### Architect Prompt
*Architect, please review the attached Product Requirements Document (`docs/prd.md`). Your task is to create a comprehensive architecture document that outlines the technical design for the `truststore` CLI tool. Please adhere to the technical assumptions and constraints specified in the PRD, including the use of Go, a monolithic repository structure, and the defined testing strategy. Your architecture should detail the proposed code structure, key data structures for handling certificates, the approach for interacting with different truststore formats (PEM, JKS, PKCS12), and a plan for implementing the CI/CD pipeline.*