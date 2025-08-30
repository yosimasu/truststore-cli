package client

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestNewResponseHandler(t *testing.T) {
	handler := NewResponseHandler()
	if handler == nil {
		t.Fatal("NewResponseHandler returned nil")
	}
	if !handler.validateJSON {
		t.Error("Expected validateJSON to be true by default")
	}
}

func TestResponseHandler_ReadJSONResponse(t *testing.T) {
	handler := NewResponseHandler()

	tests := []struct {
		name        string
		resp        *http.Response
		target      interface{}
		wantError   bool
		errorType   ErrorType
		expectValue interface{}
	}{
		{
			name:      "nil response",
			resp:      nil,
			target:    &map[string]interface{}{},
			wantError: true,
			errorType: ErrorTypeValidation,
		},
		{
			name: "valid JSON response",
			resp: &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"key": "value"}`)),
			},
			target:      &map[string]interface{}{},
			wantError:   false,
			expectValue: map[string]interface{}{"key": "value"},
		},
		{
			name: "empty response body",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("")),
			},
			target:    &map[string]interface{}{},
			wantError: true,
			errorType: ErrorTypeParsing,
		},
		{
			name: "invalid JSON",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"invalid": json}`)),
			},
			target:    &map[string]interface{}{},
			wantError: true,
			errorType: ErrorTypeParsing,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := handler.ReadJSONResponse(test.resp, test.target)
			
			if test.wantError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if httpErr, ok := err.(*HTTPError); ok {
					if httpErr.Type != test.errorType {
						t.Errorf("Expected error type %v, got %v", test.errorType, httpErr.Type)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				// Check the value was unmarshaled correctly
				if targetMap, ok := test.target.(*map[string]interface{}); ok {
					if expectedMap, ok := test.expectValue.(map[string]interface{}); ok {
						for k, v := range expectedMap {
							if (*targetMap)[k] != v {
								t.Errorf("Expected %s=%v, got %s=%v", k, v, k, (*targetMap)[k])
							}
						}
					}
				}
			}
		})
	}
}

func TestResponseHandler_ReadStringResponse(t *testing.T) {
	handler := NewResponseHandler()

	tests := []struct {
		name      string
		resp      *http.Response
		wantError bool
		errorType ErrorType
		expected  string
	}{
		{
			name:      "nil response",
			resp:      nil,
			wantError: true,
			errorType: ErrorTypeValidation,
		},
		{
			name: "valid string response",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("test content")),
			},
			wantError: false,
			expected:  "test content",
		},
		{
			name: "empty response",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("")),
			},
			wantError: false,
			expected:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := handler.ReadStringResponse(test.resp)
			
			if test.wantError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if httpErr, ok := err.(*HTTPError); ok {
					if httpErr.Type != test.errorType {
						t.Errorf("Expected error type %v, got %v", test.errorType, httpErr.Type)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if result != test.expected {
					t.Errorf("Expected %q, got %q", test.expected, result)
				}
			}
		})
	}
}

func TestResponseHandler_ValidateStatusCode(t *testing.T) {
	handler := NewResponseHandler()

	tests := []struct {
		name          string
		resp          *http.Response
		expectedCodes []int
		wantError     bool
		errorType     ErrorType
	}{
		{
			name:      "nil response",
			resp:      nil,
			wantError: true,
			errorType: ErrorTypeValidation,
		},
		{
			name: "default success (200)",
			resp: &http.Response{
				StatusCode: 200,
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			wantError: false,
		},
		{
			name: "custom success code",
			resp: &http.Response{
				StatusCode: 201,
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			expectedCodes: []int{201},
			wantError:     false,
		},
		{
			name: "client error (404)",
			resp: &http.Response{
				StatusCode: 404,
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			wantError: true,
			errorType: ErrorTypeValidation,
		},
		{
			name: "server error (500)",
			resp: &http.Response{
				StatusCode: 500,
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			wantError: true,
			errorType: ErrorTypeServer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := handler.ValidateStatusCode(test.resp, test.expectedCodes...)
			
			if test.wantError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if httpErr, ok := err.(*HTTPError); ok {
					if httpErr.Type != test.errorType {
						t.Errorf("Expected error type %v, got %v", test.errorType, httpErr.Type)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestResponseHandler_CheckCommonHeaders(t *testing.T) {
	handler := NewResponseHandler()

	tests := []struct {
		name     string
		resp     *http.Response
		expected map[string]string
	}{
		{
			name:     "nil response",
			resp:     nil,
			expected: nil,
		},
		{
			name: "response with headers",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type":   []string{"application/json"},
					"Content-Length": []string{"123"},
					"Server":         []string{"nginx/1.20"},
					"Cache-Control":  []string{"no-cache"},
					"Custom-Header":  []string{"ignored"},
				},
			},
			expected: map[string]string{
				"Content-Type":   "application/json",
				"Content-Length": "123",
				"Server":         "nginx/1.20",
				"Cache-Control":  "no-cache",
			},
		},
		{
			name: "response with partial headers",
			resp: &http.Response{
				Header: http.Header{
					"Content-Type": []string{"text/plain"},
				},
			},
			expected: map[string]string{
				"Content-Type": "text/plain",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := handler.CheckCommonHeaders(test.resp)
			
			if test.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
				return
			}
			
			for key, expectedValue := range test.expected {
				if actualValue, exists := result[key]; !exists || actualValue != expectedValue {
					t.Errorf("Expected %s=%q, got %s=%q", key, expectedValue, key, actualValue)
				}
			}
		})
	}
}

func TestResponseHandler_ProcessResponse(t *testing.T) {
	handler := NewResponseHandler()

	tests := []struct {
		name          string
		resp          *http.Response
		target        interface{}
		expectedCodes []int
		wantError     bool
		errorType     ErrorType
	}{
		{
			name: "successful JSON processing",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"result": "success"}`)),
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			target:    &map[string]interface{}{},
			wantError: false,
		},
		{
			name: "successful string processing",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("success")),
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			target:    new(string),
			wantError: false,
		},
		{
			name: "validation only (nil target)",
			resp: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader("ignored")),
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			target:    nil,
			wantError: false,
		},
		{
			name: "status code validation failure",
			resp: &http.Response{
				StatusCode: 404,
				Body:       io.NopCloser(strings.NewReader("not found")),
				Request:    &http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}},
			},
			target:    &map[string]interface{}{},
			wantError: true,
			errorType: ErrorTypeValidation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := handler.ProcessResponse(test.resp, test.target, test.expectedCodes...)
			
			if test.wantError {
				if err == nil {
					t.Fatal("Expected error but got none")
				}
				if httpErr, ok := err.(*HTTPError); ok {
					if httpErr.Type != test.errorType {
						t.Errorf("Expected error type %v, got %v", test.errorType, httpErr.Type)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

