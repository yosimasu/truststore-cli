### 7. Core Workflows

This diagram illustrates the optimized sequence of events when a user runs the `truststore add example.org --target ...` command with enhanced chain completion that leverages existing TLS certificate chains.

```mermaid
sequenceDiagram
    actor User
    participant CLI
    participant TruststoreService as Truststore Service
    participant TLSService as TLS Service
    participant ChainService as Certificate Chain Service
    participant TypeDetector as Certificate Type Detector
    participant RootSelector as Root Certificate Selector
    participant CTLogClient as CT Log Client
    participant crt_sh as crt.sh API
    participant PerfMonitor as Performance Monitor
    participant TruststoreHandler as Truststore Handler

    User->>+CLI: truststore add example.org --target ...
    CLI->>+TruststoreService: ExecuteAdd("example.org", ...)
    TruststoreService->>+TLSService: GetCertificateChain("example.org")
    TLSService->>TLSService: TLS Handshake (InsecureSkipVerify: true)
    TLSService-->>-TruststoreService: Complete certificate chain from TLS
    TruststoreService->>+ChainService: OptimizeExistingChain(tlsChain)
    
    alt Chain already contains root certificate
        ChainService->>+TypeDetector: DetectCertificateType(each cert in chain)
        TypeDetector-->>-ChainService: Found self-signed root
        ChainService->>+RootSelector: FindRootCertificate(chain)
        RootSelector-->>-ChainService: Root Cert (from existing chain)
        ChainService->>+PerfMonitor: RecordOperation("optimized-existing", duration)
        PerfMonitor-->>-ChainService: Metrics recorded
    else Chain missing root certificate
        ChainService->>+PerfMonitor: RecordOperation("ct-log-completion", start)
        ChainService->>+CTLogClient: FetchIssuers(...) for missing certificates only
        CTLogClient->>+crt_sh: GET /?CN=...&output=json
        crt_sh-->>-CTLogClient: JSON response with ID
        CTLogClient->>+crt_sh: GET /?d=<ID>
        crt_sh-->>-CTLogClient: Missing Cert PEM
        CTLogClient-->>-ChainService: Returns missing certificates
        ChainService->>+RootSelector: FindRootCertificate(completedChain)
        RootSelector-->>-ChainService: Root Cert
        ChainService->>+PerfMonitor: RecordOperation("ct-log-completion", end)
        PerfMonitor-->>-ChainService: Metrics recorded
    end
    
    ChainService-->>-TruststoreService: Returns Root Cert
    TruststoreService->>+TruststoreHandler: AddCertificate(Root Cert)
    TruststoreHandler-->>-TruststoreService: Success
    TruststoreService-->>-CLI: Success with metrics
    CLI-->>-User: "Successfully added certificate..." + perf info
```
