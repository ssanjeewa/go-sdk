package zkpcrypto

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateKeyPair_Format(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error: %v", err)
	}

	// PrivateKey: 0x + 64 hex chars
	if !strings.HasPrefix(kp.PrivateKey, "0x") {
		t.Errorf("PrivateKey missing 0x prefix: %s", kp.PrivateKey)
	}
	if len(kp.PrivateKey) != 66 { // 0x + 64
		t.Errorf("PrivateKey length = %d, want 66", len(kp.PrivateKey))
	}

	// PublicKey: 0x04 + 128 hex chars
	if !strings.HasPrefix(kp.PublicKey, "0x04") {
		t.Errorf("PublicKey missing 0x04 prefix: %s", kp.PublicKey)
	}
	if len(kp.PublicKey) != 132 { // 0x + 130
		t.Errorf("PublicKey length = %d, want 132", len(kp.PublicKey))
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp1.PrivateKey == kp2.PrivateKey {
		t.Error("two generated private keys are identical — RNG failure")
	}
	if kp1.PublicKey == kp2.PublicKey {
		t.Error("two generated public keys are identical — RNG failure")
	}
}

func TestPrivateKeyToPublicKey_Roundtrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	derived, err := PrivateKeyToPublicKey(kp.PrivateKey)
	if err != nil {
		t.Fatalf("PrivateKeyToPublicKey() error: %v", err)
	}
	if derived != kp.PublicKey {
		t.Errorf("derived public key mismatch\ngot:  %s\nwant: %s", derived, kp.PublicKey)
	}
}

func TestPrivateKeyToPublicKey_TooShort(t *testing.T) {
	_, err := PrivateKeyToPublicKey("0x1234")
	if err == nil {
		t.Fatal("expected error for short private key")
	}
	var ce *CryptoError
	if !errors.As(err, &ce) {
		t.Errorf("expected *CryptoError, got %T: %v", err, err)
	}
}

func TestPrivateKeyToPublicKey_InvalidHex(t *testing.T) {
	_, err := PrivateKeyToPublicKey("0x" + strings.Repeat("ZZ", 32))
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	var ce *CryptoError
	if !errors.As(err, &ce) {
		t.Errorf("expected *CryptoError, got %T: %v", err, err)
	}
}

func TestIsValidPublicKey_Valid(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if !IsValidPublicKey(kp.PublicKey) {
		t.Errorf("IsValidPublicKey returned false for a freshly generated key: %s", kp.PublicKey)
	}
}

func TestIsValidPublicKey_WrongPrefix(t *testing.T) {
	// Compressed key starts with 0x02 or 0x03 — should be rejected.
	compressed := "0x02" + strings.Repeat("ab", 32)
	if IsValidPublicKey(compressed) {
		t.Error("compressed key (0x02 prefix) should be rejected")
	}
}

func TestIsValidPublicKey_WrongLength(t *testing.T) {
	if IsValidPublicKey("0x04" + strings.Repeat("ab", 31)) {
		t.Error("key with wrong length should be rejected")
	}
}

func TestIsValidPublicKey_Empty(t *testing.T) {
	if IsValidPublicKey("") {
		t.Error("empty string should be rejected")
	}
}
