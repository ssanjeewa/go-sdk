// Package zkpcrypto provides ECIES encryption and secp256k1 key primitives
// for the ZKP middleware protocol.
//
// # Overview
//
// This package implements the cryptographic operations needed to interact with
// the ZKP middleware:
//
//   - secp256k1 key pair generation and derivation (keys.go)
//   - BN254 scalar field validation and parsing (field.go)
//   - ECIES encryption/decryption of credential secrets (ecies.go)
//
// The ECIES wire format is byte-for-byte compatible with the Go middleware
// (zkp-middleware/internal/crypto/ecies.go) and the Node.js SDK
// (@zkp-system/node-sdk).
//
// Wire format: ephPubKey(65) | IV(12) | ciphertext(64) | GCMtag(16) = 157 bytes
// AES key = SHA-256(ECDH shared secret x-coordinate)
//
// # Usage
//
//	kp, err := zkpcrypto.GenerateKeyPair()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	encrypted, err := zkpcrypto.EncryptSecret(kp.PublicKey, n, s)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	secret, err := zkpcrypto.DecryptSecret(encrypted, kp.PrivateKey)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(secret.N, secret.S)
//
// # Concurrency
//
// All functions in this package are stateless and safe for concurrent use.
package zkpcrypto
