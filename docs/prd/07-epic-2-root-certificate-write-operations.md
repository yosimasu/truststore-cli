### Epic 2: Root Certificate Write Operations

**Goal:** This epic introduces the core modification capabilities of the tool. It will build upon the foundation of Epic 1 by implementing the `add` command, allowing users to insert new root certificates into all supported truststore formats. This transforms the tool from a simple inspection utility into a powerful management solution.

***

#### **Story 2.1: Certificate Chain Completion Service**

*As a developer,*
*I want to create an internal service that can take a certificate and build its complete chain by fetching missing issuers,*
*so that the `add` and `rm` commands can operate on a full, validated chain.*

**Acceptance Criteria:**

1. A new internal function/service is created that takes a certificate as input.
2. If the certificate's issuer is not available, it queries a public Certificate Transparency log service (like `crt.sh`).
3. It recursively fetches issuer certificates until a self-signed root is found or no more issuers can be found.
4. The function returns a complete (or most complete possible) certificate chain.
5. The service gracefully handles network errors and cases where the issuer cannot be found in the CT log.
6. A loading indicator is displayed during network operations when querying Certificate Transparency logs.

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
*I want to run `truststore add ca.pem --target keystore.jks --target-password mysecret`,*
*so that I can import a new Certificate Authority into my application's keystore without complex commands.*

**Acceptance Criteria:**

1. The `add` command supports a `--target-password` flag for the destination truststore.
2. The CLI uses the Certificate Chain Completion Service (Story 2.1) to validate the source certificate.
3. The CLI can add the identified root certificate (from a remote or local source) to a JKS file.
4. The CLI can add the identified root certificate (from a remote or local source) to a PKCS12 file.
5. If the target JKS or PKCS12 file doesn't exist, it is created with the new root certificate.
6. The user can specify a certificate alias with a flag (e.g., `--alias my_new_cert`); if not provided, a default alias is generated.
7. A success message is printed, including the alias of the added certificate.
8. Handles incorrect passwords and file write errors gracefully.
9. A loading indicator is displayed during certificate chain completion, validation, and truststore write operations.
