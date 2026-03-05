package zkpcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// DecryptedSecret holds the plaintext (n, s) pair recovered after ECIES decryption.
// Callers should limit the lifetime of this struct and must never log or serialize it.
type DecryptedSecret struct {
	N *big.Int
	S *big.Int
}

// EncryptSecret encrypts the (n, s) credential secret pair using ECIES with the
// recipient's secp256k1 public key.
//
// Plaintext layout: n(32 bytes big-endian) || s(32 bytes big-endian) = 64 bytes.
//
// Wire format (157 bytes):
//
//	ephPubKey(65) | IV(12) | ciphertext(64) | GCMtag(16)
//
// The output is a 0x-prefixed hex string (316 chars total).
// Returns *CryptoError on invalid public key or encryption failure.
func EncryptSecret(recipientPubKeyHex string, n, s *big.Int) (string, error) {
	pubBytes, err := parsePublicKeyBytes(recipientPubKeyHex)
	if err != nil {
		return "", err
	}

	recipientPubKey, err := secp.ParsePubKey(pubBytes)
	if err != nil {
		return "", &CryptoError{Message: "invalid recipient public key: cannot parse secp256k1 point"}
	}

	// Generate ephemeral key pair using crypto/rand (SEC-05).
	ephPrivKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("generate ephemeral key: %v", err)}
	}
	ephPubKeyBytes := ephPrivKey.PubKey().SerializeUncompressed() // 65 bytes

	// ECDH: sharedX = (ephPrivKey * recipientPubKey).X
	sharedPoint := new(secp.JacobianPoint)
	recipientPubKey.AsJacobian(sharedPoint)
	secp.ScalarMultNonConst(&ephPrivKey.Key, sharedPoint, sharedPoint)
	sharedPoint.ToAffine()
	sharedX := sharedPoint.X.Bytes() // [32]byte

	// KDF: aesKey = SHA-256(sharedX)
	aesKeyHash := sha256.Sum256(sharedX[:])

	// Generate 12-byte IV.
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("generate IV: %v", err)}
	}

	// Pack plaintext: n || s, each zero-padded to 32 bytes.
	var plaintext [64]byte
	n.FillBytes(plaintext[:32])
	s.FillBytes(plaintext[32:])

	// AES-256-GCM encrypt.
	block, err := aes.NewCipher(aesKeyHash[:])
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("create AES cipher: %v", err)}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", &CryptoError{Message: fmt.Sprintf("create GCM: %v", err)}
	}

	// Seal appends ciphertext(64) + GCM tag(16).
	ciphertextAndTag := gcm.Seal(nil, iv, plaintext[:], nil)
	ciphertext := ciphertextAndTag[:len(ciphertextAndTag)-16]
	tag := ciphertextAndTag[len(ciphertextAndTag)-16:]

	// Wire: ephPubKey(65) | IV(12) | ciphertext(64) | tag(16) = 157 bytes.
	wire := make([]byte, 0, 157)
	wire = append(wire, ephPubKeyBytes...)
	wire = append(wire, iv...)
	wire = append(wire, ciphertext...)
	wire = append(wire, tag...)

	return "0x" + hex.EncodeToString(wire), nil
}

// DecryptSecret decrypts an ECIES-encrypted secret produced by EncryptSecret (or the
// equivalent in the Go middleware / Node.js SDK) using the recipient's private key.
//
// Returns *CryptoError on wire-too-short, bad public key prefix, ECDH failure,
// or GCM authentication tag mismatch. Private key material is never included in
// error messages (SEC-01).
func DecryptSecret(encryptedSecretHex, privateKeyHex string) (*DecryptedSecret, error) {
	privBytes, err := parsePrivateKeyHex(privateKeyHex)
	if err != nil {
		return nil, err // already *CryptoError
	}

	s := encryptedSecretHex
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	wire, err := hex.DecodeString(s)
	if err != nil {
		return nil, &CryptoError{Message: "encrypted secret contains invalid hex"}
	}
	// Minimum: ephPubKey(65) + IV(12) + GCM tag(16) = 93 bytes.
	if len(wire) < 93 {
		return nil, &CryptoError{Message: fmt.Sprintf("encrypted secret too short: %d bytes (minimum 93)", len(wire))}
	}

	ephPubBytes := wire[:65]
	if ephPubBytes[0] != 0x04 {
		return nil, &CryptoError{Message: "encrypted secret has invalid ephemeral public key prefix (expected 0x04)"}
	}

	iv := wire[65:77]
	ciphertextAndTag := wire[77:]

	// Parse ephemeral public key.
	ephPubKey, err := secp.ParsePubKey(ephPubBytes)
	if err != nil {
		return nil, &CryptoError{Message: "invalid ephemeral public key in wire"}
	}

	// ECDH: sharedX = (privKey * ephPubKey).X
	var scalar secp.ModNScalar
	scalar.SetByteSlice(privBytes)
	priv := secp.NewPrivateKey(&scalar)

	sharedPoint := new(secp.JacobianPoint)
	ephPubKey.AsJacobian(sharedPoint)
	secp.ScalarMultNonConst(&priv.Key, sharedPoint, sharedPoint)
	sharedPoint.ToAffine()
	sharedX := sharedPoint.X.Bytes()

	// KDF: aesKey = SHA-256(sharedX)
	aesKeyHash := sha256.Sum256(sharedX[:])

	block, err := aes.NewCipher(aesKeyHash[:])
	if err != nil {
		return nil, &CryptoError{Message: "failed to create AES cipher during decryption"}
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &CryptoError{Message: "failed to create GCM during decryption"}
	}

	plaintext, err := gcm.Open(nil, iv, ciphertextAndTag, nil)
	if err != nil {
		// Do NOT wrap err — GCM errors can leak partial key info (SEC-01).
		return nil, &CryptoError{Message: "decryption failed: authentication tag mismatch or corrupted ciphertext"}
	}
	if len(plaintext) != 64 {
		return nil, &CryptoError{Message: fmt.Sprintf("unexpected plaintext length: %d (expected 64)", len(plaintext))}
	}

	n := new(big.Int).SetBytes(plaintext[:32])
	sv := new(big.Int).SetBytes(plaintext[32:])

	return &DecryptedSecret{N: n, S: sv}, nil
}

// parsePublicKeyBytes decodes and validates a 0x04-prefixed uncompressed public key.
func parsePublicKeyBytes(pubKeyHex string) ([]byte, error) {
	s := pubKeyHex
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	if len(s) != 130 {
		return nil, &CryptoError{
			Message: fmt.Sprintf("public key must be 130 hex chars (65 bytes), got %d", len(s)),
		}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, &CryptoError{Message: "public key contains invalid hex characters"}
	}
	if b[0] != 0x04 {
		return nil, &CryptoError{Message: "public key must have 0x04 uncompressed prefix"}
	}
	return b, nil
}
