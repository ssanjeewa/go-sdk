package zkp

import (
	"fmt"
	"regexp"

	zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

// Package-level compiled regexps (BP-09: never compile inside function calls).
var (
	// reHexAddress matches a 0x-prefixed 20-byte Ethereum address (40 hex chars).
	reHexAddress = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

	// reBytes32 matches a 0x-prefixed 32-byte hex value (64 hex chars).
	reBytes32 = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

	// reUncompressedPubKey matches a 0x04-prefixed 65-byte uncompressed secp256k1 key (130 hex chars).
	reUncompressedPubKey = regexp.MustCompile(`^0x04[0-9a-fA-F]{128}$`)

	// reDecimalString matches a non-empty decimal integer string.
	reDecimalString = regexp.MustCompile(`^\d+$`)
)

// ── Single-field helpers (V-06) ───────────────────────────────────────────────

func isHexAddress(s string) bool      { return reHexAddress.MatchString(s) }
func isBytes32Hex(s string) bool      { return reBytes32.MatchString(s) }
func isUncompressedPubKey(s string) bool { return reUncompressedPubKey.MatchString(s) }

// ── Request validators ────────────────────────────────────────────────────────

// validateIssueRequest validates an IssueCredentialRequest before the HTTP call.
func validateIssueRequest(r *IssueCredentialRequest) error {
	if !isHexAddress(r.UserAddress) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("userAddress must be a 0x-prefixed 20-byte hex address, got %q", r.UserAddress),
		}}
	}
	if !isBytes32Hex(r.FileID) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("fileId must be a 0x-prefixed 32-byte hex value, got %q", r.FileID),
		}}
	}
	if !isUncompressedPubKey(r.UserPublicKey) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("userPublicKey must be a 0x04-prefixed 65-byte uncompressed secp256k1 key, got %q", r.UserPublicKey),
		}}
	}
	if r.Secret != "" && !reDecimalString.MatchString(r.Secret) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("secret must be a decimal integer string, got %q", r.Secret),
		}}
	}
	return nil
}

// validateBatchIssueRequest validates a BatchIssueCredentialRequest before the HTTP call.
func validateBatchIssueRequest(r *BatchIssueCredentialRequest) error {
	if !isHexAddress(r.UserAddress) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("userAddress must be a 0x-prefixed 20-byte hex address, got %q", r.UserAddress),
		}}
	}
	if !isUncompressedPubKey(r.UserPublicKey) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("userPublicKey must be a 0x04-prefixed 65-byte uncompressed secp256k1 key, got %q", r.UserPublicKey),
		}}
	}
	if len(r.Files) == 0 {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: "files must not be empty",
		}}
	}
	if len(r.Files) > MaxBatchSize {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("files length %d exceeds maximum of %d", len(r.Files), MaxBatchSize),
		}}
	}
	for i, f := range r.Files {
		if !isBytes32Hex(f.FileID) {
			return &ValidationError{ZKPError: ZKPError{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("files[%d].fileId must be a 0x-prefixed 32-byte hex value, got %q", i, f.FileID),
			}}
		}
		if f.Secret != "" && !reDecimalString.MatchString(f.Secret) {
			return &ValidationError{ZKPError: ZKPError{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("files[%d].secret must be a decimal integer string, got %q", i, f.Secret),
			}}
		}
	}
	return nil
}

// validateProofRequest validates a GenerateProofRequest before the HTTP call.
// n and s are validated against the BN254 scalar field (SEC-03).
func validateProofRequest(r *GenerateProofRequest) error {
	if !isHexAddress(r.UserAddress) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("userAddress must be a 0x-prefixed 20-byte hex address, got %q", r.UserAddress),
		}}
	}
	if !isBytes32Hex(r.FileID) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("fileId must be a 0x-prefixed 32-byte hex value, got %q", r.FileID),
		}}
	}
	if _, err := zkpcrypto.ParseFieldElement(r.N); err != nil {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("n: %v", err),
		}}
	}
	if _, err := zkpcrypto.ParseFieldElement(r.S); err != nil {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("s: %v", err),
		}}
	}
	return nil
}

// validateSharePrepareRequest validates a SharePrepareRequest before the HTTP call.
func validateSharePrepareRequest(r *SharePrepareRequest) error {
	if !isBytes32Hex(r.FileID) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("fileId must be a 0x-prefixed 32-byte hex value, got %q", r.FileID),
		}}
	}
	if !isHexAddress(r.GranteeAddress) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("granteeAddress must be a 0x-prefixed 20-byte hex address, got %q", r.GranteeAddress),
		}}
	}
	if !isUncompressedPubKey(r.GranteePublicKey) {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("granteePublicKey must be a 0x04-prefixed 65-byte uncompressed secp256k1 key, got %q", r.GranteePublicKey),
		}}
	}
	if r.EncryptedKeyForGrantee == "" {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: "encryptedKeyForGrantee must not be empty",
		}}
	}
	return nil
}
