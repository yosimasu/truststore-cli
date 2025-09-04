### 7. Core Workflows

This diagram illustrates the optimized sequence of events when a user runs the `truststore add example.org --target ...` command with Epic 4's conditional processing.

```mermaid
sequenceDiagram
    actor User
    participant CLI
    participant TruststoreService as Truststore Service
    participant ChainService as Certificate Chain Service
    participant TypeDetector as Certificate Type Detector
    participant RootSelector as Root Certificate Selector
    participant CTLogClient as CT Log Client
    participant crt_sh as crt.sh API
    participant PerfMonitor as Performance Monitor
    participant TruststoreHandler as Truststore Handler

    User->>+CLI: truststore add example.org --target ...
    CLI->>+TruststoreService: ExecuteAdd("example.org", ...)
    TruststoreService->>+ChainService: BuildChain("example.org")
    ChainService->>+TypeDetector: DetectCertificateType(cert)
    
    alt Self-Signed Certificate
        TypeDetector-->>-ChainService: SELF_SIGNED
        ChainService->>+PerfMonitor: RecordOperation("self-signed", start)
        ChainService->>+RootSelector: FindRootCertificate([cert])
        RootSelector-->>-ChainService: Root Cert (same as input)
        ChainService->>+PerfMonitor: RecordOperation("self-signed", end)
        PerfMonitor-->>-ChainService: Metrics recorded
    else CA-Signed Certificate  
        TypeDetector-->>-ChainService: CA_SIGNED
        ChainService->>+PerfMonitor: RecordOperation("ca-signed", start)
        ChainService->>+CTLogClient: FetchIssuers(...)
        CTLogClient->>+crt_sh: GET /?CN=...&output=json
        crt_sh-->>-CTLogClient: JSON response with ID
        CTLogClient->>+crt_sh: GET /?d=<ID>
        crt_sh-->>-CTLogClient: Issuer Cert PEM
        CTLogClient-->>-ChainService: Returns full chain
        ChainService->>+RootSelector: FindRootCertificate(chain)
        RootSelector-->>-ChainService: Root Cert
        ChainService->>+PerfMonitor: RecordOperation("ca-signed", end)
        PerfMonitor-->>-ChainService: Metrics recorded
    end
    
    ChainService-->>-TruststoreService: Returns Root Cert
    TruststoreService->>+TruststoreHandler: AddCertificate(Root Cert)
    TruststoreHandler-->>-TruststoreService: Success
    TruststoreService-->>-CLI: Success with metrics
    CLI-->>-User: "Successfully added certificate..." + perf info
```
