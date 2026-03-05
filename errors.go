package zkp

import "fmt"

// Error code constants returned in ZKPError.Code.
const (
	ErrCodeAPI        = "API_ERROR"
	ErrCodeAuth       = "AUTH_ERROR"
	ErrCodeRateLimit  = "RATE_LIMIT_ERROR"
	ErrCodeValidation = "VALIDATION_ERROR"
	ErrCodeNetwork    = "NETWORK_ERROR"
	ErrCodeNotFound   = "NOT_FOUND_ERROR"
	ErrCodeServer     = "SERVER_ERROR"
	ErrCodeTreeFull   = "TREE_FULL"
	ErrCodeCrypto     = "CRYPTO_ERROR"
)

// ZKPError is the base error type embedded by all SDK errors.
// Format: [CODE] message
type ZKPError struct {
	Message string
	Code    string
}

func (e *ZKPError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// APIError is returned when the server responds with an unexpected HTTP status
// code that does not map to a more specific error type.
type APIError struct {
	ZKPError
	StatusCode int
}

// AuthError is returned on HTTP 401. The API key is missing or invalid.
type AuthError struct {
	ZKPError
}

// RateLimitError is returned on HTTP 429. RetryAfterMs is populated from the
// Retry-After response header (in milliseconds) when present.
type RateLimitError struct {
	ZKPError
	RetryAfterMs int
}

// ValidationError is returned when client-side input validation fails before
// an HTTP request is made, or when the server returns HTTP 400.
type ValidationError struct {
	ZKPError
}

// NetworkError wraps a transport-level error (timeout, connection refused, etc.).
// Unwrap returns the underlying cause for use with errors.Is / errors.As.
type NetworkError struct {
	ZKPError
	Cause error
}

// Unwrap returns the underlying transport error so errors.Is / errors.As can
// traverse the chain.
func (e *NetworkError) Unwrap() error {
	return e.Cause
}

// NotFoundError is returned on HTTP 404.
type NotFoundError struct {
	ZKPError
}

// ServerError is returned on HTTP 5xx responses.
type ServerError struct {
	ZKPError
	StatusCode int
}

// TreeFullError is returned on HTTP 409 when the user's Merkle tree has no
// remaining leaf slots.
type TreeFullError struct {
	ZKPError
}

// CryptoError is returned when ECIES encryption or decryption fails (bad key
// format, wire-too-short, GCM authentication tag mismatch, etc.).
// Private key material is never included in the error message.
type CryptoError struct {
	ZKPError
}
