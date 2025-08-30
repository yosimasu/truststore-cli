package client

import (
	"errors"
	"net"
	"testing"
)

func TestErrorType_String(t *testing.T) {
	tests := []struct {
		errorType ErrorType
		expected  string
	}{
		{ErrorTypeNetwork, "network"},
		{ErrorTypeTimeout, "timeout"},
		{ErrorTypeServer, "server"},
		{ErrorTypeParsing, "parsing"},
		{ErrorTypeValidation, "validation"},
		{ErrorTypeUnknown, "unknown"},
	}

	for _, test := range tests {
		if test.errorType.String() != test.expected {
			t.Errorf("ErrorType(%d).String() = %q, expected %q", test.errorType, test.errorType.String(), test.expected)
		}
	}
}

func TestHTTPError_Error(t *testing.T) {
	tests := []struct {
		name     string
		httpErr  *HTTPError
		expected string
	}{
		{
			name: "error with URL",
			httpErr: &HTTPError{
				Type:    ErrorTypeNetwork,
				URL:     "https://example.com",
				Message: "connection refused",
			},
			expected: "network error for https://example.com: connection refused",
		},
		{
			name: "error without URL",
			httpErr: &HTTPError{
				Type:    ErrorTypeTimeout,
				Message: "request timeout",
			},
			expected: "timeout error: request timeout",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.httpErr.Error() != test.expected {
				t.Errorf("HTTPError.Error() = %q, expected %q", test.httpErr.Error(), test.expected)
			}
		})
	}
}

func TestHTTPError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	httpErr := &HTTPError{
		Type:  ErrorTypeNetwork,
		Cause: cause,
	}

	if httpErr.Unwrap() != cause {
		t.Errorf("HTTPError.Unwrap() should return the underlying error")
	}
}

func TestHTTPError_Is(t *testing.T) {
	err1 := &HTTPError{Type: ErrorTypeNetwork, StatusCode: 500}
	err2 := &HTTPError{Type: ErrorTypeNetwork, StatusCode: 500}
	err3 := &HTTPError{Type: ErrorTypeTimeout, StatusCode: 500}
	err4 := &HTTPError{Type: ErrorTypeNetwork, StatusCode: 404}
	genericErr := errors.New("generic error")

	// Same type and status code
	if !err1.Is(err2) {
		t.Errorf("err1.Is(err2) should be true")
	}

	// Different type
	if err1.Is(err3) {
		t.Errorf("err1.Is(err3) should be false (different type)")
	}

	// Different status code
	if err1.Is(err4) {
		t.Errorf("err1.Is(err4) should be false (different status code)")
	}

	// Different error type
	if err1.Is(genericErr) {
		t.Errorf("err1.Is(genericErr) should be false (different error type)")
	}
}

func TestClassifyError_ExistingHTTPError(t *testing.T) {
	original := &HTTPError{Type: ErrorTypeNetwork}
	result := ClassifyError(original, "http://example.com")

	if result != original {
		t.Errorf("ClassifyError should return existing HTTPError as-is")
	}
}


func TestClassifyError_NetError(t *testing.T) {
	tests := []struct {
		name      string
		netErr    net.Error
		wantType  ErrorType
		retryable bool
	}{
		{
			name:      "timeout error",
			netErr:    &timeoutError{},
			wantType:  ErrorTypeTimeout,
			retryable: true,
		},
		{
			name:      "temporary error",
			netErr:    &temporaryError{},
			wantType:  ErrorTypeNetwork,
			retryable: false, // Changed: temporary errors are no longer retryable, only timeout errors
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ClassifyError(test.netErr, "http://example.com")
			if result.Type != test.wantType {
				t.Errorf("Expected type %v, got %v", test.wantType, result.Type)
			}
			if result.Retryable != test.retryable {
				t.Errorf("Expected retryable %v, got %v", test.retryable, result.Retryable)
			}
		})
	}
}

func TestClassifyError_GenericError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantType  ErrorType
		retryable bool
	}{
		{
			name:      "timeout in message",
			err:       errors.New("operation timeout"),
			wantType:  ErrorTypeTimeout,
			retryable: true,
		},
		{
			name:      "connection in message",
			err:       errors.New("connection failed"),
			wantType:  ErrorTypeNetwork,
			retryable: true,
		},
		{
			name:      "json parsing error",
			err:       errors.New("invalid json"),
			wantType:  ErrorTypeParsing,
			retryable: false,
		},
		{
			name:      "validation error",
			err:       errors.New("invalid input"),
			wantType:  ErrorTypeValidation,
			retryable: false,
		},
		{
			name:      "unknown error",
			err:       errors.New("something went wrong"),
			wantType:  ErrorTypeUnknown,
			retryable: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ClassifyError(test.err, "http://example.com")
			if result.Type != test.wantType {
				t.Errorf("Expected type %v, got %v", test.wantType, result.Type)
			}
			if result.Retryable != test.retryable {
				t.Errorf("Expected retryable %v, got %v", test.retryable, result.Retryable)
			}
		})
	}
}

func TestNewHTTPStatusError(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantType   ErrorType
		retryable  bool
	}{
		{
			name:       "server error 500",
			statusCode: 500,
			wantType:   ErrorTypeServer,
			retryable:  true,
		},
		{
			name:       "server error 503",
			statusCode: 503,
			wantType:   ErrorTypeServer,
			retryable:  true,
		},
		{
			name:       "client error 400",
			statusCode: 400,
			wantType:   ErrorTypeValidation,
			retryable:  false,
		},
		{
			name:       "client error 404",
			statusCode: 404,
			wantType:   ErrorTypeValidation,
			retryable:  false,
		},
		{
			name:       "unexpected status 200",
			statusCode: 200,
			wantType:   ErrorTypeUnknown,
			retryable:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := NewHTTPStatusError(test.statusCode, "http://example.com")
			if result.Type != test.wantType {
				t.Errorf("Expected type %v, got %v", test.wantType, result.Type)
			}
			if result.StatusCode != test.statusCode {
				t.Errorf("Expected status code %d, got %d", test.statusCode, result.StatusCode)
			}
			if result.Retryable != test.retryable {
				t.Errorf("Expected retryable %v, got %v", test.retryable, result.Retryable)
			}
		})
	}
}

func TestNewValidationError(t *testing.T) {
	err := NewValidationError("invalid input")
	if err.Type != ErrorTypeValidation {
		t.Errorf("Expected type %v, got %v", ErrorTypeValidation, err.Type)
	}
	if err.Retryable {
		t.Errorf("Validation errors should not be retryable")
	}
	if err.Message != "invalid input" {
		t.Errorf("Expected message 'invalid input', got %q", err.Message)
	}
}

func TestNewParsingError(t *testing.T) {
	cause := errors.New("json decode error")
	err := NewParsingError("failed to parse response", cause)
	
	if err.Type != ErrorTypeParsing {
		t.Errorf("Expected type %v, got %v", ErrorTypeParsing, err.Type)
	}
	if err.Retryable {
		t.Errorf("Parsing errors should not be retryable")
	}
	if err.Message != "failed to parse response" {
		t.Errorf("Expected message 'failed to parse response', got %q", err.Message)
	}
	if err.Cause != cause {
		t.Errorf("Expected cause to be set")
	}
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "retryable HTTPError",
			err:      &HTTPError{Type: ErrorTypeTimeout, Retryable: true},
			expected: true,
		},
		{
			name:     "non-retryable HTTPError",
			err:      &HTTPError{Type: ErrorTypeValidation, Retryable: false},
			expected: false,
		},
		{
			name:     "temporary net error",
			err:      &temporaryError{},
			expected: false, // Changed: temporary errors are no longer retryable, only timeout errors
		},
		{
			name:     "timeout net error",
			err:      &timeoutError{},
			expected: true,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsRetryable(test.err)
			if result != test.expected {
				t.Errorf("IsRetryable(%v) = %v, expected %v", test.err, result, test.expected)
			}
		})
	}
}

func TestIsTimeout(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "timeout HTTPError",
			err:      &HTTPError{Type: ErrorTypeTimeout},
			expected: true,
		},
		{
			name:     "network HTTPError",
			err:      &HTTPError{Type: ErrorTypeNetwork},
			expected: false,
		},
		{
			name:     "timeout net error",
			err:      &timeoutError{},
			expected: true,
		},
		{
			name:     "timeout in message",
			err:      errors.New("operation timeout"),
			expected: true,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsTimeout(test.err)
			if result != test.expected {
				t.Errorf("IsTimeout(%v) = %v, expected %v", test.err, result, test.expected)
			}
		})
	}
}

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "network HTTPError",
			err:      &HTTPError{Type: ErrorTypeNetwork},
			expected: true,
		},
		{
			name:     "timeout HTTPError",
			err:      &HTTPError{Type: ErrorTypeTimeout},
			expected: false,
		},
		{
			name:     "net error",
			err:      &temporaryError{},
			expected: true,
		},
		{
			name:     "generic error",
			err:      errors.New("generic error"),
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsNetworkError(test.err)
			if result != test.expected {
				t.Errorf("IsNetworkError(%v) = %v, expected %v", test.err, result, test.expected)
			}
		})
	}
}

// Mock error types for testing
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return false }

type temporaryError struct{}

func (e *temporaryError) Error() string   { return "temporary" }
func (e *temporaryError) Timeout() bool   { return false }
func (e *temporaryError) Temporary() bool { return true }

func TestClassifyError_NilError(t *testing.T) {
	result := ClassifyError(nil, "http://example.com")
	if result != nil {
		t.Errorf("ClassifyError(nil) should return nil")
	}
}