package zkp

import (
	"errors"
	"fmt"
	"testing"
)

func TestZKPError_Error(t *testing.T) {
	err := &ZKPError{Message: "something went wrong", Code: "TEST_CODE"}
	want := "[TEST_CODE] something went wrong"
	if got := err.Error(); got != want {
		t.Errorf("ZKPError.Error() = %q, want %q", got, want)
	}
}

func TestErrorsAs_NetworkError(t *testing.T) {
	cause := fmt.Errorf("connection refused")
	netErr := &NetworkError{
		ZKPError: ZKPError{Message: "request failed", Code: ErrCodeNetwork},
		Cause:    cause,
	}

	// errors.As must find *NetworkError
	var target *NetworkError
	if !errors.As(netErr, &target) {
		t.Fatal("errors.As did not find *NetworkError")
	}

	// Unwrap must surface the cause
	if !errors.Is(netErr, cause) {
		t.Error("errors.Is did not find cause via Unwrap")
	}
}

func TestErrorsAs_AllTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		fn   func(error) bool
	}{
		{
			name: "APIError",
			err:  &APIError{ZKPError: ZKPError{Code: ErrCodeAPI, Message: "msg"}, StatusCode: 400},
			fn:   func(e error) bool { var t *APIError; return errors.As(e, &t) },
		},
		{
			name: "AuthError",
			err:  &AuthError{ZKPError: ZKPError{Code: ErrCodeAuth, Message: "msg"}},
			fn:   func(e error) bool { var t *AuthError; return errors.As(e, &t) },
		},
		{
			name: "RateLimitError",
			err:  &RateLimitError{ZKPError: ZKPError{Code: ErrCodeRateLimit, Message: "msg"}, RetryAfterMs: 1000},
			fn:   func(e error) bool { var t *RateLimitError; return errors.As(e, &t) },
		},
		{
			name: "ValidationError",
			err:  &ValidationError{ZKPError: ZKPError{Code: ErrCodeValidation, Message: "msg"}},
			fn:   func(e error) bool { var t *ValidationError; return errors.As(e, &t) },
		},
		{
			name: "NetworkError",
			err:  &NetworkError{ZKPError: ZKPError{Code: ErrCodeNetwork, Message: "msg"}},
			fn:   func(e error) bool { var t *NetworkError; return errors.As(e, &t) },
		},
		{
			name: "NotFoundError",
			err:  &NotFoundError{ZKPError: ZKPError{Code: ErrCodeNotFound, Message: "msg"}},
			fn:   func(e error) bool { var t *NotFoundError; return errors.As(e, &t) },
		},
		{
			name: "ServerError",
			err:  &ServerError{ZKPError: ZKPError{Code: ErrCodeServer, Message: "msg"}, StatusCode: 500},
			fn:   func(e error) bool { var t *ServerError; return errors.As(e, &t) },
		},
		{
			name: "TreeFullError",
			err:  &TreeFullError{ZKPError: ZKPError{Code: ErrCodeTreeFull, Message: "msg"}},
			fn:   func(e error) bool { var t *TreeFullError; return errors.As(e, &t) },
		},
		{
			name: "CryptoError",
			err:  &CryptoError{ZKPError: ZKPError{Code: ErrCodeCrypto, Message: "msg"}},
			fn:   func(e error) bool { var t *CryptoError; return errors.As(e, &t) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.fn(tc.err) {
				t.Errorf("errors.As failed for %s", tc.name)
			}
		})
	}
}

func TestErrorCodes(t *testing.T) {
	codes := map[string]string{
		"ErrCodeAPI":        ErrCodeAPI,
		"ErrCodeAuth":       ErrCodeAuth,
		"ErrCodeRateLimit":  ErrCodeRateLimit,
		"ErrCodeValidation": ErrCodeValidation,
		"ErrCodeNetwork":    ErrCodeNetwork,
		"ErrCodeNotFound":   ErrCodeNotFound,
		"ErrCodeServer":     ErrCodeServer,
		"ErrCodeTreeFull":   ErrCodeTreeFull,
		"ErrCodeCrypto":     ErrCodeCrypto,
	}
	for name, code := range codes {
		if code == "" {
			t.Errorf("%s is empty", name)
		}
	}
}
