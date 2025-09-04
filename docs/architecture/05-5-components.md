### 5. Components

#### `CLI (Cobra Commands)`

* **Responsibility:** This is the user-facing layer of the application. It defines the `list`, `add`, and `rm` commands, parses all user input (arguments and flags), and orchestrates the workflow by calling the appropriate services.
* **Key Interfaces:** Exposes the command-line interface (e.g., `truststore add ...`) to the user in the terminal.
* **Dependencies:** `Truststore Service`.
* **Technology Stack:** `Go`, `github.com/spf13/cobra`.

#### `Truststore Service`

* **Responsibility:** Acts as a central orchestrator or façade for all truststore operations. It determines the type of truststore file (PEM, JKS, etc.) and delegates the actual read/write operations to the correct handler.
* **Key Interfaces:** `ExecuteList(source)`, `ExecuteAdd(source, target)`, `ExecuteRemove(source, target)`.
* **Dependencies:** `Truststore Handlers`, `Certificate Chain Service`.
* **Technology Stack:** `Go`.

#### `Truststore Handlers` (Strategy Pattern Implementations)

* **Responsibility:** A group of components, each implementing the `Truststore` interface for a specific file format. This isolates the file-format-specific logic.
  * `PemHandler`: Reads and writes standard PEM files.
  * `JksHandler`: Reads and writes password-protected JKS files.
  * `Pkcs12Handler`: Reads and writes password-protected PKCS12 files.
* **Key Interfaces:** Each handler implements `ReadCertificates()`, `AddCertificate()`, `RemoveCertificate()`.
* **Dependencies:** `JKS Library`, `PKCS12 Library`.
* **Technology Stack:** `Go`, `keystore-go`, `go-pkcs12`.

#### `Certificate Chain Service`

* **Responsibility:** Implements the logic for building a complete certificate chain as required by the `add` and `rm` commands. Now includes intelligent certificate type detection and conditional processing - self-signed certificates are processed immediately without CT log queries, while CA-signed certificates use recursive CT log fetching to build complete chains.
* **Key Interfaces:** `BuildChain(certificate)`, `DetectCertificateType(certificate)`, `FindRootCertificate(chain)`.
* **Dependencies:** `CT Log Client`, `Certificate Type Detector`, `Root Certificate Selector`, `Performance Monitor`.
* **Technology Stack:** `Go`.

#### `CT Log Client`

* **Responsibility:** A simple HTTP client responsible for making requests to the public Certificate Transparency log service (e.g., `crt.sh`) and parsing the JSON response to extract certificate data. Now includes caching and resilient error handling patterns.
* **Key Interfaces:** `FetchIssuersBySerial(serialNumber)`.
* **Dependencies:** Go's `net/http` client.
* **Technology Stack:** `Go`.

#### `Certificate Type Detector`

* **Responsibility:** Analyzes certificate properties to determine if certificates are self-signed or CA-signed, enabling conditional processing logic. Implements sophisticated detection algorithms including signature validation.
* **Key Interfaces:** `DetectCertificateType(certificate) CertificateType`.
* **Dependencies:** Go's `crypto/x509` package.
* **Technology Stack:** `Go`.

#### `Root Certificate Selector`

* **Responsibility:** Analyzes complete certificate chains to correctly identify and select the actual root certificate, replacing the previous naive "last certificate" selection logic.
* **Key Interfaces:** `FindRootCertificate(chain) *Certificate`, `ValidateCertificateChain(chain) bool`.
* **Dependencies:** Go's `crypto/x509` package.
* **Technology Stack:** `Go`.

#### `Performance Monitor`

* **Responsibility:** Collects metrics and timing data for certificate processing operations, providing visibility into optimization effectiveness and system performance patterns.
* **Key Interfaces:** `RecordOperation(type, duration)`, `GetMetrics() PerformanceMetrics`.
* **Dependencies:** None.
* **Technology Stack:** `Go`.

#### Component Diagram

```mermaid
graph TD
    subgraph CLI Layer
        A[Cobra Commands]
    end

    subgraph Service Layer
        B[Truststore Service]
        C[Certificate Chain Service]
        H[Certificate Type Detector]
        I[Root Certificate Selector]
        J[Performance Monitor]
    end

    subgraph Data Access Layer
        D[PEM Handler]
        E[JKS Handler]
        F[PKCS12 Handler]
    end

    subgraph External Clients
        G[CT Log Client]
    end

    A --> B
    B --> C
    B --> D
    B --> E
    B --> F
    C --> H
    C --> I
    C --> J
    H -->|CA-signed| G
    H -->|self-signed| I
    G --> I
    C --> G
```
