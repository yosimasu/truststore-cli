### 2. Requirements

#### Functional

* **FR1:** The CLI MUST be able to retrieve and display the certificate chain from a specified remote server (e.g., `example.org:443`).
* **FR2:** The CLI MUST be able to read and display the certificate chain from a local truststore file in PEM, JKS, or PKCS12 format.
* **FR3:** The CLI MUST support password-protected JKS and PKCS12 files.
* **FR4:** The CLI MUST be able to add the root certificate from a remote server's chain to a new or existing target truststore file (PEM, JKS, PKCS12).
* **FR5:** The CLI MUST be able to add a root certificate from a local source file to a new or existing target truststore file.
* **FR6:** The CLI MUST be able to remove a root certificate from a target truststore by identifying the certificate chain via a source (remote server or local file).
* **FR7:** The CLI MUST provide clear, human-readable output for certificate details (e.g., subject, issuer, validity).
* **FR8:** Before adding or removing a root certificate, the CLI SHOULD attempt to build a complete certificate chain by fetching missing issuer certificates from a public Certificate Transparency log service (e.g., crt.sh).

#### Non-Functional

* **NFR1:** The CLI MUST be distributed as a single, self-contained binary for macOS, Linux, and Windows.
* **NFR2:** The CLI SHOULD have a fast startup time, with operations completing in under 2 seconds for typical use cases.
* **NFR3:** The CLI MUST provide helpful error messages for common issues (e.g., connection failed, file not found, incorrect password).
* **NFR4:** The command-line arguments and flags SHOULD follow common POSIX conventions.
