// issue_credential demonstrates the full single-file credential issuance flow:
//
//  1. Check middleware health
//  2. Generate a secp256k1 key pair (or use an existing one)
//  3. Issue a credential → receive ClaimFile + InsertCalldata
//  4. Print the calldata to submit on-chain via batchInsertLeaves
//
// Usage:
//
//	ZKP_API_KEY=dev-key-1 go run ./examples/issue_credential/
//
// Environment variables:
//
//	ZKP_BASE_URL   Base URL of the ZKP middleware  (default: http://localhost:3002)
//	ZKP_API_KEY    Bearer token for authentication (required)
//	ZKP_FILE_ID    0x-prefixed bytes32 file ID     (required)
//	ZKP_ADDRESS    0x-prefixed 20-byte user address (required)
//	ZKP_PRIVKEY    0x-prefixed 64-hex private key  (optional; generates a new key if omitted)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	zkp "github.com/ssanjeewa/go-sdk"
	zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

func main() {
	baseURL := envOr("ZKP_BASE_URL", "http://localhost:3002")
	apiKey := mustEnv("ZKP_API_KEY")
	fileID := mustEnv("ZKP_FILE_ID")
	userAddress := mustEnv("ZKP_ADDRESS")

	// ── 1. Build client ──────────────────────────────────────────────────────
	client, err := zkp.NewClient(baseURL,
		zkp.WithAPIKey(apiKey),
		zkp.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	// ── 2. Health check ──────────────────────────────────────────────────────
	ctx := context.Background()
	health, err := client.Health(ctx)
	if err != nil {
		log.Fatalf("Health: %v", err)
	}
	fmt.Printf("Middleware status: %s  chainId: %d\n", health.Status, health.ChainID)

	// ── 3. Key pair ──────────────────────────────────────────────────────────
	var pubKey string
	if privKey := os.Getenv("ZKP_PRIVKEY"); privKey != "" {
		// Derive public key from existing private key.
		pubKey, err = zkpcrypto.PrivateKeyToPublicKey(privKey)
		if err != nil {
			log.Fatalf("PrivateKeyToPublicKey: %v", err)
		}
		fmt.Printf("Using existing key pair\n  publicKey:  %s\n", pubKey)
	} else {
		// Generate a fresh key pair.
		kp, err := zkpcrypto.GenerateKeyPair()
		if err != nil {
			log.Fatalf("GenerateKeyPair: %v", err)
		}
		pubKey = kp.PublicKey
		fmt.Printf("Generated new key pair\n  privateKey: %s\n  publicKey:  %s\n",
			kp.PrivateKey, kp.PublicKey)
		fmt.Println("  ⚠  Store the private key securely — you need it to generate proofs.")
	}

	// ── 4. Issue credential ──────────────────────────────────────────────────
	fmt.Printf("\nIssuing credential for\n  address: %s\n  fileId:  %s\n", userAddress, fileID)

	resp, err := client.IssueCredential(ctx, &zkp.IssueCredentialRequest{
		UserAddress:   userAddress,
		FileID:        fileID,
		UserPublicKey: pubKey,
	})
	if err != nil {
		log.Fatalf("IssueCredential: %v", err)
	}

	// ── 5. Print results ─────────────────────────────────────────────────────
	fmt.Println("\n── ClaimFile (store this safely) ──────────────────────────")
	prettyPrint(resp.ClaimFile)

	fmt.Println("\n── InsertCalldata (submit this on-chain) ──────────────────")
	prettyPrint(resp.InsertCalldata)

	fmt.Printf("\nDone. LeafIndex: %d\n", resp.ClaimFile.LeafIndex)
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("environment variable %s is required", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func prettyPrint(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}
