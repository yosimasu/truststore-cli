### 10. Error Handling Strategy

#### General Approach

* **Error Model:** We will use Go's standard `error` interface and idiomatic error handling patterns. Errors will be returned as the last value from functions and handled explicitly at each call site. We will use Go's error wrapping (`fmt.Errorf` with `%w`) to provide context as errors are propagated up the call stack.
* **Exception Hierarchy:** N/A. Go does not use exceptions. We will define custom error types (e.g., `ErrCertificateNotFound`) where programmatic inspection of an error is required.
* **Error Propagation:** Errors are passed up the call stack until they reach the top-level command handler. At this point, the error is inspected, and a user-friendly message is printed to `stderr`. The application will then exit with a non-zero status code to signal failure to any calling scripts.

#### Logging Standards

* **Library:** None. A formal logging library is overkill for this CLI. We will use direct writes to `stdout` and `stderr`.
* **Format:** Simple, human-readable text.
* **Levels:**
  * **Normal Output:** Successful results and standard information will be printed to `stdout`.
  * **Errors:** User-facing error messages will be printed to `stderr`.
  * **Debug/Verbose Output:** A `--verbose` flag will enable more detailed error information and step-by-step process logging to `stderr` for debugging purposes.
* **Security:** No sensitive information (like passwords) will ever be printed to `stdout` or `stderr`.

#### Error Handling Patterns

* **External API Errors (`crt.sh`):**
  * **Retry Policy:** No automatic retries. The tool will fail fast, and the user can choose to re-run the command.
  * **Timeout Configuration:** All external HTTP requests will have a reasonable, non-infinite timeout (e.g., 15 seconds).
  * **Error Translation:** Raw network errors or non-200 HTTP status codes will be translated into clear, user-friendly messages (e.g., "Error: could not connect to crt.sh. Please check your internet connection.").
* **File I/O Errors:** Errors like "file not found" or "permission denied" will be caught and presented to the user with a clear, actionable message.
* **User Input Errors:** Invalid flag usage or incorrect arguments will be caught by the Cobra framework, which will automatically display the command's help text.
