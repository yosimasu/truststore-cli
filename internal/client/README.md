# HTTP Client Error Handling Patterns

This document describes the standardized error handling patterns for HTTP client operations in the truststore CLI.

## Error Classification

All HTTP client errors are classified into the following types:

### ErrorType Categories

1. **ErrorTypeNetwork**: Network connectivity issues
   - Connection refused, reset, or failed
   - DNS resolution failures
   - Generally retryable except DNS failures

2. **ErrorTypeTimeout**: Request timeout errors
   - Network timeouts
   - Request timeouts
   - Always retryable

3. **ErrorTypeServer**: HTTP server errors (5xx status codes)
   - Internal server errors (500)
   - Service unavailable (503)
   - Always retryable

4. **ErrorTypeValidation**: Client request errors (4xx status codes)
   - Bad request (400)
   - Not found (404)
   - Never retryable

5. **ErrorTypeParsing**: Response parsing errors
   - JSON decode errors
   - Invalid certificate data
   - Never retryable

6. **ErrorTypeUnknown**: Unclassified errors
   - Generally not retryable

## HTTPError Structure

```go
type HTTPError struct {
    Type       ErrorType // Error category
    StatusCode int       // HTTP status code, if applicable
    Message    string    // Human-readable error message
    Cause      error     // Underlying error
    URL        string    // URL that caused the error
    Retryable  bool      // Whether the error is retryable
}
```

## Usage Examples

### Basic Error Classification

```go
err := someHTTPOperation()
if err != nil {
    httpErr := ClassifyError(err, "https://api.example.com")
    
    switch httpErr.Type {
    case ErrorTypeTimeout:
        // Handle timeout
    case ErrorTypeNetwork:
        // Handle network error
    case ErrorTypeServer:
        // Handle server error
    }
}
```

### Retry Logic

```go
if IsRetryable(err) {
    // Retry the operation
} else {
    // Don't retry, handle the error
}
```

### Error Type Checking

```go
if IsTimeout(err) {
    log.Printf("Request timed out: %v", err)
}

if IsNetworkError(err) {
    log.Printf("Network error: %v", err)
}
```

### Creating Specific Errors

```go
// Create a validation error
err := NewValidationError("invalid certificate format")

// Create a parsing error
err := NewParsingError("failed to decode JSON", originalErr)

// Create an HTTP status error
err := NewHTTPStatusError(500, "https://api.example.com")
```

## Recovery Strategies

### Network Errors
- Retry with exponential backoff
- Check network connectivity
- Consider fallback mechanisms

### Timeout Errors
- Retry with potentially longer timeout
- Check if operation is idempotent
- Consider request complexity

### Server Errors (5xx)
- Retry with exponential backoff
- Respect rate limits
- Consider circuit breaker pattern

### Validation Errors (4xx)
- Do not retry
- Log for debugging
- Return error to user

### Parsing Errors
- Do not retry
- Log detailed error information
- Check API compatibility

## Integration with HTTP Client

The error handling patterns integrate seamlessly with the generic HTTP client:

```go
client := NewHTTPClient(DefaultConfig())
resp, err := client.Get("https://api.example.com")
if err != nil {
    httpErr := ClassifyError(err, "https://api.example.com")
    if httpErr.Retryable {
        // HTTP client will automatically retry
    }
}
```

The HTTP client automatically uses these patterns to determine whether to retry operations based on the error classification.