package client

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrorType represents the category of HTTP client error
type ErrorType int

const (
	// ErrorTypeUnknown represents an unclassified error
	ErrorTypeUnknown ErrorType = iota
	// ErrorTypeNetwork represents network connectivity errors
	ErrorTypeNetwork
	// ErrorTypeTimeout represents request timeout errors
	ErrorTypeTimeout
	// ErrorTypeServer represents HTTP server errors (5xx)
	ErrorTypeServer
	// ErrorTypeParsing represents response parsing errors
	ErrorTypeParsing
	// ErrorTypeValidation represents request validation errors
	ErrorTypeValidation
)

// String returns the string representation of ErrorType
func (e ErrorType) String() string {
	switch e {
	case ErrorTypeNetwork:
		return "network"
	case ErrorTypeTimeout:
		return "timeout"
	case ErrorTypeServer:
		return "server"
	case ErrorTypeParsing:
		return "parsing"
	case ErrorTypeValidation:
		return "validation"
	default:
		return "unknown"
	}
}

// HTTPError represents a classified HTTP client error
type HTTPError struct {
	Type       ErrorType
	StatusCode int    // HTTP status code, if applicable
	Message    string // Human-readable error message
	Cause      error  // Underlying error
	URL        string // URL that caused the error
	Retryable  bool   // Whether the error is retryable
}

// Error implements the error interface
func (e *HTTPError) Error() string {
	if e.URL != "" {
		return fmt.Sprintf("%s error for %s: %s", e.Type, e.URL, e.Message)
	}
	return fmt.Sprintf("%s error: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error
func (e *HTTPError) Unwrap() error {
	return e.Cause
}

// Is implements error comparison for errors.Is
func (e *HTTPError) Is(target error) bool {
	if t, ok := target.(*HTTPError); ok {
		return e.Type == t.Type && e.StatusCode == t.StatusCode
	}
	return false
}

// ClassifyError analyzes an error and returns a classified HTTPError
func ClassifyError(err error, requestURL string) *HTTPError {
	if err == nil {
		return nil
	}

	// Check for existing HTTPError
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr
	}

	httpError := &HTTPError{
		Type:    ErrorTypeUnknown,
		Message: err.Error(),
		Cause:   err,
		URL:     requestURL,
	}

	// Classify based on error type and message
	if netErr, ok := err.(net.Error); ok {
		return classifyNetError(netErr, requestURL)
	}

	// Check if it's a URL error by examining the error string
	errStr := err.Error()
	if strings.Contains(errStr, "timeout") {
		httpError.Type = ErrorTypeTimeout
		httpError.Retryable = true
	} else if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "network") {
		httpError.Type = ErrorTypeNetwork
		httpError.Retryable = true
	} else if strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "DNS") {
		httpError.Type = ErrorTypeNetwork
		httpError.Retryable = false
	} else {
		httpError = classifyGenericError(err, requestURL)
	}

	return httpError
}


// classifyNetError classifies net.Error types
func classifyNetError(netErr net.Error, url string) *HTTPError {
	httpError := &HTTPError{
		Type:      ErrorTypeNetwork,
		Message:   netErr.Error(),
		Cause:     netErr,
		URL:       url,
		Retryable: netErr.Temporary(),
	}

	if netErr.Timeout() {
		httpError.Type = ErrorTypeTimeout
		httpError.Message = "network timeout"
		httpError.Retryable = true
	}

	return httpError
}

// classifyGenericError classifies generic errors
func classifyGenericError(err error, url string) *HTTPError {
	errStr := strings.ToLower(err.Error())
	
	httpError := &HTTPError{
		Type:    ErrorTypeUnknown,
		Message: err.Error(),
		Cause:   err,
		URL:     url,
	}

	switch {
	case strings.Contains(errStr, "timeout"):
		httpError.Type = ErrorTypeTimeout
		httpError.Retryable = true
	case strings.Contains(errStr, "connection"):
		httpError.Type = ErrorTypeNetwork
		httpError.Retryable = true
	case strings.Contains(errStr, "json") || strings.Contains(errStr, "parse"):
		httpError.Type = ErrorTypeParsing
		httpError.Retryable = false
	case strings.Contains(errStr, "invalid") || strings.Contains(errStr, "validation"):
		httpError.Type = ErrorTypeValidation
		httpError.Retryable = false
	}

	return httpError
}

// NewHTTPStatusError creates an HTTPError from an HTTP status code
func NewHTTPStatusError(statusCode int, url string) *HTTPError {
	httpError := &HTTPError{
		StatusCode: statusCode,
		URL:        url,
	}

	if statusCode >= 500 {
		httpError.Type = ErrorTypeServer
		httpError.Message = fmt.Sprintf("server error (status %d)", statusCode)
		httpError.Retryable = true
	} else if statusCode >= 400 {
		httpError.Type = ErrorTypeValidation
		httpError.Message = fmt.Sprintf("client error (status %d)", statusCode)
		httpError.Retryable = false
	} else {
		httpError.Type = ErrorTypeUnknown
		httpError.Message = fmt.Sprintf("unexpected status %d", statusCode)
		httpError.Retryable = false
	}

	return httpError
}

// NewValidationError creates a validation error
func NewValidationError(message string) *HTTPError {
	return &HTTPError{
		Type:      ErrorTypeValidation,
		Message:   message,
		Retryable: false,
	}
}

// NewParsingError creates a parsing error
func NewParsingError(message string, cause error) *HTTPError {
	return &HTTPError{
		Type:      ErrorTypeParsing,
		Message:   message,
		Cause:     cause,
		Retryable: false,
	}
}

// IsRetryable checks if an error should trigger a retry
func IsRetryable(err error) bool {
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.Retryable
	}
	
	// For non-HTTPError types, check common patterns
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}
	
	return false
}

// IsTimeout checks if an error is a timeout error
func IsTimeout(err error) bool {
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.Type == ErrorTypeTimeout
	}
	
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

// IsNetworkError checks if an error is a network error
func IsNetworkError(err error) bool {
	if httpErr, ok := err.(*HTTPError); ok {
		return httpErr.Type == ErrorTypeNetwork
	}
	
	_, isNetErr := err.(net.Error)
	_, isURLErr := err.(*url.Error)
	
	return isNetErr || isURLErr
}