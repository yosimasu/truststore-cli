### 4. Data Models

#### `Certificate`

* **Purpose:** To represent a single X.509 digital certificate in memory. This is the fundamental building block of our application.
* **Key Attributes:** We will use the standard `crypto/x509.Certificate` struct provided by Go's standard library. This is a comprehensive model that includes all necessary attributes, such as:
  * `Subject` and `Issuer`
  * `SerialNumber`
  * `NotBefore`, `NotAfter` (Validity Period)
  * `PublicKey` and `SignatureAlgorithm`
  * `Extensions` (including AIA for potential future use)
* **Relationships:** A `Certificate` can be an issuer for another `Certificate`, forming a chain relationship.

#### `Truststore` (Interface)

* **Purpose:** To provide a generic, abstract representation of a certificate container, regardless of its file format (PEM, JKS, or PKCS12).
* **Key Attributes:**
  * This will be defined as a Go `interface` rather than a concrete struct.
  * It will define a set of behaviors, such as `ReadCertificates()`, `AddCertificate(cert)`, and `RemoveCertificate(cert)`.
* **Relationships:** A `Truststore` implementation will contain a collection of `Certificate` objects. The specific implementation (e.g., `JksTruststore`) will handle the details of how those certificates are stored and retrieved from the file.
