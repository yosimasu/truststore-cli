### Epic 2: Root Certificate Write Operations

**Goal:** This epic introduces the core modification capabilities of the tool. It will build upon the foundation of Epic 1 by implementing the `add` command, allowing users to insert new root certificates into all supported truststore formats. This transforms the tool from a simple inspection utility into a powerful management solution.

***

#### **Story 2.0: External Service Integration Infrastructure**

*As a developer,*
*I want to establish robust external service integration infrastructure for Certificate Transparency logs,*
*so that I have reliable, testable, and resilient foundation for certificate chain completion operations.*

**Acceptance Criteria:**

1. Certificate Transparency log client service is created with proper error handling and resilience.
2. Cached response system is implemented for offline development and testing.
3. Graceful degradation mechanisms are established when CT logs are unavailable.
4. Rate limiting and API respect patterns are implemented for external service calls.
5. Mock CT log service is available for development and integration testing.
6. Network connectivity detection and fallback behaviors are defined.

***

#### **Story 2.1: Certificate Chain Completion Service**

*As a user of the truststore CLI,*
*I want the system to automatically complete certificate chains by finding missing issuer certificates,*
*so that I can work with complete, validated certificate chains for add and remove operations.*

**Acceptance Criteria:**

1. A certificate chain completion service is implemented using the CT log infrastructure from Story 2.0.
2. The service accepts a certificate as input and returns the most complete possible certificate chain.
3. Missing issuer certificates are automatically fetched from Certificate Transparency logs when available.
4. The service recursively builds the chain until a self-signed root is found or no more issuers can be found.
5. Network errors and CT log unavailability are handled gracefully with appropriate user messaging.
6. The service integrates with the caching and offline capabilities from Story 2.0.
7. A loading indicator is displayed during network operations when querying Certificate Transparency logs.
8. Clear user feedback is provided about chain completeness and any limitations encountered.

***

#### **Story 2.2: Add Root Certificate from Remote Server to PEM File**

*As a DevOps engineer,*
*I want to run `truststore add example.org --target trusted_certs.pem`,*
*so that I can quickly add a new server's root CA certificate to my application's trust list.*

**Acceptance Criteria:**

1. A new `add` subcommand is created within the CLI framework.
2. The command accepts a source (remote server) and a `--target` file path.
3. The CLI uses the Certificate Chain Completion Service (Story 2.1) to retrieve and validate the full certificate chain.
4. The identified root certificate is appended to the target PEM file. If the file doesn't exist, it is created.
5. A clear success message is printed to the console.
6. File write permissions and other I/O errors are handled gracefully.
7. A loading indicator is displayed while retrieving certificates from remote servers and completing certificate chains.

***

#### **Story 2.3: Add Root Certificate from a Local File to PEM File**

*As a developer,*
*I want to run `truststore add new_ca.pem --target existing_truststore.pem`,*
*so that I can add a CA certificate from a file to my truststore.*

**Acceptance Criteria:**

1. The `add` command accepts a local file path as a source.
2. The CLI reads the certificate from the source file.
3. The CLI uses the Certificate Chain Completion Service (Story 2.1) to validate the certificate and its chain.
4. The identified root certificate is appended to the target PEM file.
5. A success message confirms the operation.
6. A loading indicator is displayed during certificate chain completion and validation operations.

***

#### **Story 2.4: Add Root Certificate to JKS and PKCS12 Files**

*As a Java developer,*
*I want to run `truststore add ca.pem --target keystore.jks --target-password=mysecret`,*
*so that I can import a new Certificate Authority into my application's keystore without complex commands.*

**Acceptance Criteria:**

1. The `add` command supports a `--target-password` flag for the destination truststore. When used with `=value` (e.g., `--target-password=mysecret`), the password is provided directly. When used without a value (e.g., `--target-password`), the user is prompted to enter the password interactively.
2. The CLI uses the Certificate Chain Completion Service (Story 2.1) to validate the source certificate.
3. The CLI can add the identified root certificate (from a remote or local source) to a JKS file.
4. The CLI can add the identified root certificate (from a remote or local source) to a PKCS12 file.
5. If the target JKS or PKCS12 file doesn't exist, it is created with the new root certificate.
6. A default alias is automatically generated for the added certificate.
7. A success message is printed, including the alias of the added certificate.
8. Handles incorrect passwords and file write errors gracefully.
9. A loading indicator is displayed during certificate chain completion, validation, and truststore write operations.
