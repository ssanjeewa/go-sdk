// share_file demonstrates the full file-sharing flow:
//
//  1. Fetch the grantee's on-chain public key
//  2. Re-encrypt the file's AES key for the grantee using ECIES
//  3. Call PrepareShare → receive InsertCalldata + GrantShareCalldata
//  4. Print both calldatas to submit on-chain
//
// Usage:
//
//	ZKP_API_KEY=dev-key-1 \
//	ZKP_PRIVKEY=0x<64-hex> \
//	ZKP_ADDRESS=0x<owner-address> \
//	ZKP_FILE_ID=0x<bytes32> \
//	ZKP_ENCRYPTED_SECRET=0x<314-hex> \
//	ZKP_GRANTEE_ADDRESS=0x<grantee-address> \
//	go run ./examples/share_file/
//
// Environment variables:
//
//	ZKP_BASE_URL          Middleware base URL              (default: http://localhost:3002)
//	ZKP_API_KEY           Bearer token                     (required)
//	ZKP_PRIVKEY           0x-prefixed 64-hex private key   (required — to decrypt your own secrets)
//	ZKP_ADDRESS           0x-prefixed owner address        (required)
//	ZKP_FILE_ID           0x-prefixed bytes32 file ID      (required)
//	ZKP_ENCRYPTED_SECRET  EncryptedSecret from your ClaimFile (required)
//	ZKP_GRANTEE_ADDRESS   0x-prefixed grantee address      (required)
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
	privKey := mustEnv("ZKP_PRIVKEY")
	fileID := mustEnv("ZKP_FILE_ID")
	encryptedSecret := mustEnv("ZKP_ENCRYPTED_SECRET")
	granteeAddress := mustEnv("ZKP_GRANTEE_ADDRESS")

	// ── 1. Build client ──────────────────────────────────────────────────────
	client, err := zkp.NewClient(baseURL,
		zkp.WithAPIKey(apiKey),
		zkp.WithTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	ctx := context.Background()

	// ── 2. Fetch grantee's on-chain public key ───────────────────────────────
	fmt.Printf("Fetching public key for grantee %s…\n", granteeAddress)
	pubKeyResp, err := client.GetUserPubKey(ctx, granteeAddress)
	if err != nil {
		log.Fatalf("GetUserPubKey: %v", err)
	}
	if !pubKeyResp.Registered {
		log.Fatalf("Grantee %s has not registered a public key on-chain", granteeAddress)
	}
	fmt.Printf("  grantee pubKey: %s\n", pubKeyResp.PubKey)

	// ── 3. Decrypt your own secrets ──────────────────────────────────────────
	fmt.Println("\nDecrypting your credential secrets…")
	secret, err := zkpcrypto.DecryptSecret(encryptedSecret, privKey)
	if err != nil {
		log.Fatalf("DecryptSecret: %v", err)
	}

	// ── 4. Re-encrypt (n, s) for the grantee ────────────────────────────────
	// The grantee will use their private key to decrypt this and generate proofs.
	fmt.Println("Re-encrypting secrets for grantee…")
	encryptedForGrantee, err := zkpcrypto.EncryptSecret(pubKeyResp.PubKey, secret.N, secret.S)
	if err != nil {
		log.Fatalf("EncryptSecret: %v", err)
	}
	fmt.Printf("  encryptedKeyForGrantee: %s…(truncated)\n", encryptedForGrantee[:20])

	// ── 5. Prepare share ─────────────────────────────────────────────────────
	fmt.Printf("\nPreparing share for\n  fileId:  %s\n  grantee: %s\n", fileID, granteeAddress)

	shareResp, err := client.PrepareShare(ctx, &zkp.SharePrepareRequest{
		FileID:                 fileID,
		GranteeAddress:         granteeAddress,
		GranteePublicKey:       pubKeyResp.PubKey,
		EncryptedKeyForGrantee: encryptedForGrantee,
	})
	if err != nil {
		log.Fatalf("PrepareShare: %v", err)
	}

	// ── 6. Print results ─────────────────────────────────────────────────────
	fmt.Printf("\n  leafIndex:      %d\n", shareResp.LeafIndex)
	fmt.Printf("  commitment:     %s\n", shareResp.Commitment)
	fmt.Printf("  shareKeyCommit: %s\n", shareResp.ShareKeyCommit)

	fmt.Println("\n── InsertCalldata (insert grantee leaf on-chain) ──────────")
	prettyPrint(shareResp.InsertCalldata)

	fmt.Println("\n── GrantShareCalldata (record the share grant on-chain) ───")
	prettyPrint(shareResp.GrantShareCalldata)

	fmt.Println("\n── EncryptedCredential (pass to grantee out-of-band) ──────")
	fmt.Printf("  %s\n", shareResp.EncryptedCredential)

	fmt.Println("\nDone. Submit InsertCalldata first, then GrantShareCalldata.")
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
