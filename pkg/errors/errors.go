// Package errors provides custom error types and error handling utilities.
package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode represents a unique error code for API responses.
type ErrorCode string

// Standard error codes
const (
	CodeUnknown          ErrorCode = "UNKNOWN"
	CodeValidation       ErrorCode = "VALIDATION_ERROR"
	CodeNotFound         ErrorCode = "NOT_FOUND"
	CodeConflict         ErrorCode = "CONFLICT"
	CodeUnauthorized     ErrorCode = "UNAUTHORIZED"
	CodeForbidden        ErrorCode = "FORBIDDEN"
	CodeBadRequest       ErrorCode = "BAD_REQUEST"
	CodeInternalError    ErrorCode = "INTERNAL_ERROR"
	CodeServiceUnavail   ErrorCode = "SERVICE_UNAVAILABLE"
	CodeTimeout          ErrorCode = "TIMEOUT"
	CodeRateLimited      ErrorCode = "RATE_LIMITED"
	CodeResourceExhausted ErrorCode = "RESOURCE_EXHAUSTED"
)

// AppError represents a structured application error.
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	HTTPStatus int                    `json:"-"`
	Err        error                  `json:"-"`
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error.
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetail adds a detail key-value pair to the error.
func (e *AppError) WithDetail(key string, value interface{}) *AppError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// ToJSON returns the JSON representation of the error.
func (e *AppError) ToJSON() []byte {
	data, _ := json.Marshal(e)
	return data
}

// Constructor functions for common error types

// New creates a new AppError with the given code and message.
func New(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: codeToHTTPStatus(code),
	}
}

// Wrap wraps an existing error with an AppError.
func Wrap(err error, code ErrorCode, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: codeToHTTPStatus(code),
		Err:        err,
	}
}

// Validation creates a validation error.
func Validation(message string) *AppError {
	return New(CodeValidation, message)
}

// NotFound creates a not found error.
func NotFound(resource string) *AppError {
	return New(CodeNotFound, fmt.Sprintf("%s not found", resource))
}

// Conflict creates a conflict error.
func Conflict(message string) *AppError {
	return New(CodeConflict, message)
}

// Unauthorized creates an unauthorized error.
func Unauthorized(message string) *AppError {
	return New(CodeUnauthorized, message)
}

// Forbidden creates a forbidden error.
func Forbidden(message string) *AppError {
	return New(CodeForbidden, message)
}

// BadRequest creates a bad request error.
func BadRequest(message string) *AppError {
	return New(CodeBadRequest, message)
}

// Internal creates an internal server error.
func Internal(message string) *AppError {
	return New(CodeInternalError, message)
}

// ServiceUnavailable creates a service unavailable error.
func ServiceUnavailable(message string) *AppError {
	return New(CodeServiceUnavail, message)
}

// Timeout creates a timeout error.
func Timeout(message string) *AppError {
	return New(CodeTimeout, message)
}

// RateLimited creates a rate limited error.
func RateLimited(message string) *AppError {
	return New(CodeRateLimited, message)
}

// codeToHTTPStatus maps error codes to HTTP status codes.
func codeToHTTPStatus(code ErrorCode) int {
	switch code {
	case CodeValidation, CodeBadRequest:
		return http.StatusBadRequest
	case CodeNotFound:
		return http.StatusNotFound
	case CodeConflict:
		return http.StatusConflict
	case CodeUnauthorized:
		return http.StatusUnauthorized
	case CodeForbidden:
		return http.StatusForbidden
	case CodeTimeout:
		return http.StatusGatewayTimeout
	case CodeServiceUnavail:
		return http.StatusServiceUnavailable
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeResourceExhausted:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// Is checks if the target error is an AppError with the given code.
func Is(err error, code ErrorCode) bool {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code == code
	}
	return false
}

// GetHTTPStatus returns the HTTP status code for an error.
func GetHTTPStatus(err error) int {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.HTTPStatus
	}
	return http.StatusInternalServerError
}
