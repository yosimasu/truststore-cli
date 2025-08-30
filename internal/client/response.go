package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// ResponseHandler provides utilities for handling HTTP responses
type ResponseHandler struct {
	validateJSON bool
}

// NewResponseHandler creates a new response handler
func NewResponseHandler() *ResponseHandler {
	return &ResponseHandler{
		validateJSON: true,
	}
}

// ReadJSONResponse reads and unmarshals a JSON response
func (r *ResponseHandler) ReadJSONResponse(resp *http.Response, v interface{}) error {
	if resp == nil {
		return NewValidationError("response is nil")
	}

	defer func() { _ = resp.Body.Close() }()

	// Check content type if validation is enabled
	if r.validateJSON {
		contentType := resp.Header.Get("Content-Type")
		if contentType != "" && contentType != "application/json" && contentType != "text/plain" {
			// Allow text/plain for some APIs that return JSON with wrong content-type
			_ = contentType
		}
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewParsingError("failed to read response body", err)
	}

	// Handle empty responses
	if len(body) == 0 {
		return NewParsingError("empty response body", nil)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(body, v); err != nil {
		return NewParsingError(fmt.Sprintf("failed to parse JSON response: %v", err), err)
	}

	return nil
}

// ReadStringResponse reads the response body as a string
func (r *ResponseHandler) ReadStringResponse(resp *http.Response) (string, error) {
	if resp == nil {
		return "", NewValidationError("response is nil")
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", NewParsingError("failed to read response body", err)
	}

	return string(body), nil
}

// ValidateStatusCode checks if the HTTP status code indicates success
func (r *ResponseHandler) ValidateStatusCode(resp *http.Response, expectedCodes ...int) error {
	if resp == nil {
		return NewValidationError("response is nil")
	}

	// If no expected codes provided, default to 200
	if len(expectedCodes) == 0 {
		expectedCodes = []int{http.StatusOK}
	}

	// Check if status code is in expected range
	for _, code := range expectedCodes {
		if resp.StatusCode == code {
			return nil
		}
	}

	// Return appropriate error based on status code
	return NewHTTPStatusError(resp.StatusCode, resp.Request.URL.String())
}

// CheckCommonHeaders validates common HTTP headers
func (r *ResponseHandler) CheckCommonHeaders(resp *http.Response) map[string]string {
	if resp == nil {
		return nil
	}

	headers := make(map[string]string)
	
	// Check common headers
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		headers["Content-Type"] = contentType
	}
	
	if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
		headers["Content-Length"] = contentLength
	}
	
	if server := resp.Header.Get("Server"); server != "" {
		headers["Server"] = server
	}
	
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "" {
		headers["Cache-Control"] = cacheControl
	}

	return headers
}

// ProcessResponse provides a complete response processing workflow
func (r *ResponseHandler) ProcessResponse(resp *http.Response, target interface{}, expectedCodes ...int) error {
	// Validate status code
	if err := r.ValidateStatusCode(resp, expectedCodes...); err != nil {
		return err
	}

	// If no target provided, just validate the response
	if target == nil {
		return nil
	}

	// Handle string target
	if strTarget, ok := target.(*string); ok {
		content, err := r.ReadStringResponse(resp)
		if err != nil {
			return err
		}
		*strTarget = content
		return nil
	}

	// Handle JSON target
	return r.ReadJSONResponse(resp, target)
}