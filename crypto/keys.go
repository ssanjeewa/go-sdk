package zkpcrypto

import (
	"encoding/hex"
	"fmt"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// KeyPair holds a secp256k1 key pair as hex-encoded strings.
// PrivateKey is 0x-prefixed 64-hex chars (32 bytes, zero-padded).
// PublicKey is 0x04-prefixed 130-hex chars (65 bytes, uncompressed).
type KeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateKeyPair generates a random secp256k1 key pair using crypto/rand.
// The private key is zero-padded to exactly 64 hex characters to handle the
// leading-zero edge case in rare private key scalars.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, &CryptoError{Message: fmt.Sprintf("generate key pair: %v", err)}
	}

	// Pad private key scalar to 32 bytes (64 hex chars) — handles leading-zero edge case.
	privBytes := priv.Serialize() // always 32 bytes from this library
	privHex := "0x" + hex.EncodeToString(privBytes)

	pubHex := "0x" + hex.EncodeToString(priv.PubKey().SerializeUncompressed()) // 65 bytes

	return &KeyPair{PrivateKey: privHex, PublicKey: pubHex}, nil
}

// PrivateKeyToPublicKey derives the uncompressed secp256k1 public key from a
// 0x-prefixed 64-hex private key string.
// Returns *CryptoError on invalid input.
func PrivateKeyToPublicKey(privateKeyHex string) (string, error) {
	privBytes, err := parsePrivateKeyHex(privateKeyHex)
	if err != nil {
		return "", err
	}

	var scalar secp.ModNScalar
	scalar.SetByteSlice(privBytes)
	priv := secp.NewPrivateKey(&scalar)

	return "0x" + hex.EncodeToString(priv.PubKey().SerializeUncompressed()), nil
}

// IsValidPublicKey reports whether pubKeyHex is a valid 0x04-prefixed
// uncompressed secp256k1 public key (65 bytes / 130 hex chars after the prefix).
func IsValidPublicKey(pubKeyHex string) bool {
	s := pubKeyHex
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != 130 {
		return false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return false
	}
	return b[0] == 0x04
}

// parsePrivateKeyHex decodes a 0x-prefixed or raw 64-hex private key into 32 bytes.
func parsePrivateKeyHex(privateKeyHex string) ([]byte, error) {
	s := privateKeyHex
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != 64 {
		return nil, &CryptoError{
			Message: fmt.Sprintf("private key must be 64 hex chars (32 bytes), got %d chars", len(s)),
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, &CryptoError{Message: "private key contains invalid hex characters"}
	}
	return b, nil
}
