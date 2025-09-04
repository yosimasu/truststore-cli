### Epic 2: Certificate Write Operations

**Goal:** This epic introduces the core modification capabilities of the tool, implementing the `add` command with comprehensive certificate handling. Starting with basic certificate chain completion, it enhances the system with intelligent certificate type detection and correct root certificate selection to ensure users can reliably add certificates from various sources into target truststores. This transforms the tool from a simple inspection utility into a powerful and accurate management solution.

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

***

#### **Story 2.5: Intelligent Self-Signed Certificate Addition**

*As a security administrator,*\
*I want the `add` command to automatically detect when the last certificate in a chain is self-signed and prompt me for confirmation,*\
*So that I can make informed decisions about adding potentially risky self-signed certificates to my truststore.*

**Acceptance Criteria:**

**Functional Requirements:**

1. When `add` command processes a certificate, the Certificate Chain Completion Service (Story 2.1) identifies if the final certificate is self-signed using the existing `isSelfSigned()` method.
2. If self-signed certificate detected, display certificate details (subject, issuer, expiration, fingerprint) with clear security warning about self-signed certificate risks.
3. Prompt user with "Self-signed certificate detected. Add to truststore? \[y/N]" with secure default "No" requiring explicit confirmation.

**Integration Requirements:**
4\. Existing `add` command functionality for all source types (remote servers, local files) continues to work unchanged.
5\. New functionality follows existing add command error handling, loading indicator, and user interaction patterns.
6\. Integration with Certificate Chain Completion Service maintains current chain completion behavior without modification.

**Quality Requirements:**
7\. Add `--yes` flag to bypass interactive confirmation for automation scenarios and CI/CD pipelines.
8\. Security warning clearly explains risks of self-signed certificates and displays certificate fingerprint for verification.
9\. Audit logging captures self-signed certificate additions with source and target details for security compliance.

***

#### **Story 2.6: Certificate Type Detection Enhancement**

*As a DevOps engineer,*
*I want the certificate chain service to intelligently detect certificate types before processing,*
*so that self-signed certificates are handled correctly without unnecessary external API calls.*

**Acceptance Criteria:**

**Smart Detection Logic:**

1. Enhance existing certificate chain service with `detectCertificateType()` function
2. Self-signed detection criteria: subject equals issuer AND certificate validates against its own public key
3. CA-signed detection criteria: subject differs from issuer OR certificate cannot validate against its own public key
4. Function returns enum: `SELF_SIGNED`, `CA_SIGNED`, or `UNKNOWN`

**Integration with Existing Service:**
5\. For `SELF_SIGNED` certificates: Return single-certificate chain immediately, skip CT log calls
6\. For `CA_SIGNED` certificates: Use existing CT log completion logic from implemented Story 2.1
7\. For `UNKNOWN` certificates: Default to CA-signed behavior with warning logged
8\. Maintains backward compatibility with all existing certificate processing flows

**Quality Assurance:**
9\. Unit tests cover edge cases: intermediate CAs, cross-signed certificates, malformed certificates
10\. Performance testing shows detection adds minimal overhead (<10ms) to certificate processing
11\. Integration tests verify correct behavior for both self-signed and CA-signed certificate workflows
12\. Error handling for corrupted or invalid certificate data

***

#### **Story 2.7: Root Certificate Selection Algorithm Fix**

*As a system administrator,*
*I want the system to correctly identify and select the actual root certificate from certificate chains,*
*so that the proper root CA is added to my truststore instead of intermediate or leaf certificates.*

**Acceptance Criteria:**

**Correct Root Identification:**

1. Enhance existing certificate chain service with `findRootCertificate()` function
2. Root identification logic: Find certificate where subject equals issuer (self-signed root)
3. If no self-signed certificate found, select certificate highest in chain with longest validity period
4. Replace existing naive `chain[len(chain)-1]` selection logic with proper root identification

**Chain Analysis Logic:**
5\. For self-signed certificates: Return the certificate itself as both leaf and root
6\. For CA-signed certificates: Analyze complete chain to identify actual root certificate
7\. Add validation that selected certificate can verify certificates lower in the chain
8\. Handle edge cases: incomplete chains, multiple potential roots, cross-signed certificates

**Validation & Testing:**
9\. Unit tests cover specific certificate chain scenarios:

* `example.com`: Should select `CN=DigiCert Global Root G3` (not intermediate)
* `iot.auomesh.io`: Should select `CN=USERTrust RSA Certification Authority`
* `mqtt.auomesh.io`: Should select the self-signed `CN=ROOT`

10. Integration tests verify correct root certificates are added to all truststore formats
11. Backward compatibility maintained with existing add/remove command workflows
12. Error handling for malformed or incomplete certificate chains
