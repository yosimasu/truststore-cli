### 2. High Level Architecture

#### Technical Summary

The system will be a monolithic, self-contained command-line interface (CLI) tool developed in Go (Golang). Its architecture will be organized around a central command-and-control structure using the Cobra library, with distinct packages for handling different truststore formats (PEM, JKS, PKCS12) and for core functionalities like certificate chain completion via Certificate Transparency logs. The design now incorporates intelligent certificate type detection and conditional CT log processing to optimize performance and eliminate unnecessary network calls for self-signed certificates. The architecture prioritizes simplicity, reliability, performance optimization, and cross-platform compatibility, directly supporting the PRD goals of creating an intuitive and powerful certificate management tool.

#### High Level Overview

* **Architectural Style:** Monolithic CLI Application. All logic is compiled into a single, self-contained binary.
* **Repository Structure:** A single repository will be used, as specified in the PRD.
* **Primary User Interaction Flow:** The user interacts with the tool via a terminal by executing commands like `truststore list <source>`, `truststore add <source> --target <file>`, and `truststore rm <source> --target <file>`. The application processes the request, interacts with the local filesystem, remote servers, or CT log APIs as needed, and prints the result to standard output/error.
* **Key Architectural Decisions:**
  * **Go (Golang):** Chosen for its excellent support for creating single, dependency-free, cross-platform binaries and its strong standard library for cryptography and networking.
  * **Cobra Library:** A popular Go library for building modern CLIs. It simplifies command, argument, and flag parsing.
  * **Interface-based Truststore Handling:** Each truststore type (PEM, JKS, PKCS12) will implement a common `Truststore` interface, allowing for consistent handling of different file formats.
  * **Intelligent Certificate Processing:** Certificate type detection determines whether certificates are self-signed or CA-signed before deciding on CT log queries, optimizing performance and reducing external API dependencies.

#### High Level Project Diagram

```mermaid
graph TD
    subgraph User
        A[Terminal User]
    end

    subgraph truststore CLI
        B(main.go / Cobra)
        C{Command Router}
        D[list]
        E[add]
        F[rm]
        G[Certificate Chain Service]
        G1[Certificate Type Detection]
        G2[Root Certificate Selection]
        H[Truststore Handlers]
        M[Performance Monitoring]
    end

    subgraph External Services
        I[Remote Server (TLS)]
        J[CT Log API (crt.sh)]
    end

    subgraph Local Filesystem
        K[PEM/JKS/P12 Files]
    end

    A --> B
    B --> C
    C -->|list| D
    C -->|add| E
    C -->|rm| F

    D --> I
    D --> K

    E --> G
    E --> H
    F --> G
    F --> H

    G --> G1
    G1 -->|self-signed| G2
    G1 -->|CA-signed| J
    G --> G2
    G --> M
    J --> G2
    H --> K
```

#### Architectural and Design Patterns

* **Command Pattern:** The Cobra library inherently uses the command pattern to encapsulate all the information needed to perform an action. *Rationale:* This is the standard, most effective way to structure a CLI application, providing clear separation of concerns for each command.
* **Strategy Pattern:** Each truststore format (PEM, JKS, PKCS12) will be handled by a specific "strategy" (a struct that implements a common `Truststore` interface with methods like `Read`, `Add`, `Remove`). *Rationale:* This allows the core logic to remain agnostic to the file format it's operating on, making the system easy to extend with new formats in the future.
* **Dependency Injection:** Core services, like the Certificate Chain Completion service or the truststore handlers, will be initialized once and passed into the commands that need them. *Rationale:* This improves testability by allowing services to be mocked, and it clarifies the dependencies of each command.
* **Conditional Processing Pattern:** Certificate type detection drives conditional logic for CT log queries, with self-signed certificates processed locally and CA-signed certificates using external APIs. *Rationale:* Optimizes performance by eliminating unnecessary network calls and provides offline capability for self-signed certificate operations.
* **Observer Pattern (Metrics):** Performance monitoring components observe certificate processing events to collect metrics and timing data. *Rationale:* Provides visibility into optimization effectiveness without coupling monitoring logic to core business functions.
