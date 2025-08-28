### 6. External APIs

#### `crt.sh` Certificate Search & Download API

* **Purpose:** To find certificates by their identifiers (e.g., Common Name) and then download the certificate content by its `crt.sh` ID. This allows us to build complete certificate chains for the `add` and `rm` commands.
* **Documentation:** The service is provided via a web interface at `https://crt.sh/`. The API is community-documented.
* **Base URL:** `https://crt.sh/`
* **Authentication:** None required.
* **Rate Limits:** No officially published rate limits. Our client must be a good citizen, avoiding aggressive polling.
* **Key Endpoints Used:**
  * **Step 1 (Search):** `GET /?CN=<COMMON_NAME>&output=json&exclude=expired` - Searches for non-expired certificates matching a given Common Name. The key piece of information to be extracted from the JSON response is the certificate `id`.
  * **Step 2 (Download):** `GET /?d=<ID>` - Downloads the raw, PEM-encoded certificate for a given `crt.sh` certificate `id`.
* **Integration Notes:** The `Certificate Chain Service` will implement this two-step process. It will first search for an issuer certificate to get its ID, and then use that ID to download the certificate data. The client must be resilient to potential API changes and handle errors gracefully at both steps.
