package zkpcrypto

import "fmt"

// ValidationError is returned when input validation fails (bad format, out-of-range, etc.).
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("[VALIDATION_ERROR] %s", e.Message)
}

// CryptoError is returned when a cryptographic operation fails (bad key format,
// wire-too-short, GCM authentication tag mismatch, etc.).
// Private key material is never included in the error message.
type CryptoError struct {
	Message string
}

func (e *CryptoError) Error() string {
	return fmt.Sprintf("[CRYPTO_ERROR] %s", e.Message)
}
