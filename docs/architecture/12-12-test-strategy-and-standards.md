### 12. Test Strategy and Standards

#### Testing Philosophy

* **Approach:** Test-After. While TDD is valuable, a pragmatic test-after approach is sufficient. We will focus on ensuring all new functionality is covered by tests before a feature is considered complete.
* **Coverage Goals:** We will aim for >80% unit test coverage for all core packages, to be enforced by our CI pipeline.
* **Test Pyramid:** We will maintain a balanced pyramid with a wide base of fast unit tests, a smaller set of integration tests for CLI commands, and a few end-to-end tests.

#### Test Types and Organization

* **Unit Tests:**
  * **Framework:** Go's built-in `testing` package.
  * **File Convention:** `*_test.go`, co-located with the code.
  * **Mocking:** We will use Go's interfaces for mocking dependencies. No external mocking libraries are required.
  * **Scope:** Test individual functions and methods in isolation. All dependencies (like services or API clients) will be mocked.

* **Integration Tests:**
  * **Scope:** These tests will build and execute the actual CLI binary with various arguments. They will verify file system changes, `stdout`/`stderr` output, and exit codes.
  * **Location:** A separate `test/` directory at the project root will hold these tests and their required data.
  * **Test Infrastructure:**
    * **Filesystem:** Tests will create and clean up their own temporary directories and test files.
    * **External APIs (`crt.sh`):** We will use Go's `net/http/httptest` package to run a mock HTTP server that simulates the `crt.sh` API, ensuring fast and reliable tests without network dependency.

* **End-to-End Tests:**
  * **Scope:** A very small set of tests that run against the real, live `crt.sh` API.
  * **Execution:** These will be explicitly marked and will not be run as part of the standard `make test` command. They will be run manually or on a nightly schedule to catch breaking changes in the external API.

#### Test Data Management

* **Strategy:** Test data (e.g., sample PEM, JKS, PKCS12 files) will be stored in a `testdata` subdirectory within the package being tested, which is the standard convention in Go.

#### Continuous Testing

* **CI Integration:** The GitHub Actions pipeline will run `make lint` and `make test` on every push and pull request. Pull requests will be blocked from merging if the test suite fails.
