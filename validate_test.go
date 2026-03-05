package zkp

import (
	"errors"
	"strings"
	"testing"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func validAddress() string  { return "0x" + strings.Repeat("ab", 20) }
func validFileID() string   { return "0x" + strings.Repeat("cd", 32) }
func validPubKey() string   { return "0x04" + strings.Repeat("ef", 64) }
func validDecimal() string  { return "12345678901234567890" }

func assertValidationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected *ValidationError, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// ── validateIssueRequest ──────────────────────────────────────────────────────

func TestValidateIssueRequest_Valid(t *testing.T) {
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	}
	if err := validateIssueRequest(req); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateIssueRequest_ValidWithSecret(t *testing.T) {
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
		Secret:        validDecimal(),
	}
	if err := validateIssueRequest(req); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateIssueRequest_BadAddress(t *testing.T) {
	req := &IssueCredentialRequest{
		UserAddress:   "0xdeadbeef", // too short
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	}
	assertValidationError(t, validateIssueRequest(req))
}

func TestValidateIssueRequest_MissingAddress(t *testing.T) {
	req := &IssueCredentialRequest{
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	}
	assertValidationError(t, validateIssueRequest(req))
}

func TestValidateIssueRequest_BadFileID(t *testing.T) {
	// 63 hex chars — one short of 64
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        "0x" + strings.Repeat("a", 63),
		UserPublicKey: validPubKey(),
	}
	assertValidationError(t, validateIssueRequest(req))
}

func TestValidateIssueRequest_BadPubKey(t *testing.T) {
	// Compressed key (0x02 prefix) — must be 0x04
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: "0x02" + strings.Repeat("ab", 32),
	}
	assertValidationError(t, validateIssueRequest(req))
}

func TestValidateIssueRequest_BadSecret(t *testing.T) {
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
		Secret:        "0xdeadbeef", // hex, not decimal
	}
	assertValidationError(t, validateIssueRequest(req))
}

// ── validateBatchIssueRequest ─────────────────────────────────────────────────

func TestValidateBatchIssueRequest_Valid(t *testing.T) {
	req := &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files: []BatchFileRequest{
			{FileID: validFileID()},
			{FileID: validFileID()},
		},
	}
	if err := validateBatchIssueRequest(req); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateBatchIssueRequest_EmptyFiles(t *testing.T) {
	req := &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files:         []BatchFileRequest{},
	}
	assertValidationError(t, validateBatchIssueRequest(req))
}

func TestValidateBatchIssueRequest_TooManyFiles(t *testing.T) {
	files := make([]BatchFileRequest, 21)
	for i := range files {
		files[i] = BatchFileRequest{FileID: validFileID()}
	}
	req := &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files:         files,
	}
	assertValidationError(t, validateBatchIssueRequest(req))
}

func TestValidateBatchIssueRequest_MaxFiles(t *testing.T) {
	// Exactly MaxBatchSize (20) files — must pass.
	files := make([]BatchFileRequest, MaxBatchSize)
	for i := range files {
		files[i] = BatchFileRequest{FileID: validFileID()}
	}
	req := &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files:         files,
	}
	if err := validateBatchIssueRequest(req); err != nil {
		t.Errorf("unexpected error for %d files: %v", MaxBatchSize, err)
	}
}

func TestValidateBatchIssueRequest_BadFileInBatch(t *testing.T) {
	req := &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files: []BatchFileRequest{
			{FileID: validFileID()},
			{FileID: "0xshort"}, // bad
		},
	}
	assertValidationError(t, validateBatchIssueRequest(req))
}

// ── validateProofRequest ──────────────────────────────────────────────────────

func TestValidateProofRequest_Valid(t *testing.T) {
	req := &GenerateProofRequest{
		UserAddress: validAddress(),
		FileID:      validFileID(),
		N:           "42",
		S:           "99",
	}
	if err := validateProofRequest(req); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateProofRequest_NOutOfRange(t *testing.T) {
	// n = BN254ScalarField — exactly at the upper bound (exclusive)
	import_bn254 := "21888242871839275222246405745257275088548364400416034343698204186575808495617"
	req := &GenerateProofRequest{
		UserAddress: validAddress(),
		FileID:      validFileID(),
		N:           import_bn254,
		S:           "1",
	}
	assertValidationError(t, validateProofRequest(req))
}

func TestValidateProofRequest_SNotDecimal(t *testing.T) {
	req := &GenerateProofRequest{
		UserAddress: validAddress(),
		FileID:      validFileID(),
		N:           "1",
		S:           "not-a-number",
	}
	assertValidationError(t, validateProofRequest(req))
}

func TestValidateProofRequest_NNotDecimal(t *testing.T) {
	req := &GenerateProofRequest{
		UserAddress: validAddress(),
		FileID:      validFileID(),
		N:           "0xff",
		S:           "1",
	}
	assertValidationError(t, validateProofRequest(req))
}

func TestValidateProofRequest_BadAddress(t *testing.T) {
	req := &GenerateProofRequest{
		UserAddress: "not-an-address",
		FileID:      validFileID(),
		N:           "1",
		S:           "1",
	}
	assertValidationError(t, validateProofRequest(req))
}

// ── validateSharePrepareRequest ───────────────────────────────────────────────

func TestValidateSharePrepareRequest_Valid(t *testing.T) {
	req := &SharePrepareRequest{
		FileID:                 validFileID(),
		GranteeAddress:         validAddress(),
		GranteePublicKey:       validPubKey(),
		EncryptedKeyForGrantee: "0x" + strings.Repeat("ab", 157),
	}
	if err := validateSharePrepareRequest(req); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateSharePrepareRequest_BadFileID(t *testing.T) {
	req := &SharePrepareRequest{
		FileID:                 "0xbad",
		GranteeAddress:         validAddress(),
		GranteePublicKey:       validPubKey(),
		EncryptedKeyForGrantee: "0xdata",
	}
	assertValidationError(t, validateSharePrepareRequest(req))
}

func TestValidateSharePrepareRequest_BadGranteeAddress(t *testing.T) {
	req := &SharePrepareRequest{
		FileID:                 validFileID(),
		GranteeAddress:         "0xshort",
		GranteePublicKey:       validPubKey(),
		EncryptedKeyForGrantee: "0xdata",
	}
	assertValidationError(t, validateSharePrepareRequest(req))
}

func TestValidateSharePrepareRequest_BadGranteePublicKey(t *testing.T) {
	req := &SharePrepareRequest{
		FileID:                 validFileID(),
		GranteeAddress:         validAddress(),
		GranteePublicKey:       "0x02" + strings.Repeat("ab", 32), // compressed
		EncryptedKeyForGrantee: "0xdata",
	}
	assertValidationError(t, validateSharePrepareRequest(req))
}

func TestValidateSharePrepareRequest_EmptyEncryptedKey(t *testing.T) {
	req := &SharePrepareRequest{
		FileID:                 validFileID(),
		GranteeAddress:         validAddress(),
		GranteePublicKey:       validPubKey(),
		EncryptedKeyForGrantee: "",
	}
	assertValidationError(t, validateSharePrepareRequest(req))
}

// ── single-field helpers ──────────────────────────────────────────────────────

func TestIsHexAddress(t *testing.T) {
	if !isHexAddress(validAddress()) {
		t.Error("valid address rejected")
	}
	if isHexAddress("0xshort") {
		t.Error("short address accepted")
	}
	if isHexAddress(strings.Repeat("a", 40)) { // no 0x prefix
		t.Error("address without 0x accepted")
	}
}

func TestIsBytes32Hex(t *testing.T) {
	if !isBytes32Hex(validFileID()) {
		t.Error("valid bytes32 rejected")
	}
	if isBytes32Hex("0x" + strings.Repeat("a", 63)) {
		t.Error("63-char hex accepted as bytes32")
	}
}

func TestIsUncompressedPubKey(t *testing.T) {
	if !isUncompressedPubKey(validPubKey()) {
		t.Error("valid pubkey rejected")
	}
	if isUncompressedPubKey("0x02" + strings.Repeat("ab", 64)) {
		t.Error("compressed pubkey (0x02) accepted")
	}
}
