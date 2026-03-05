// generate_proof demonstrates how to decrypt a ClaimFile's encrypted secret and
// generate a Groth16 ZK proof ready for on-chain submission:
//
//  1. Decrypt the EncryptedSecret from the ClaimFile using the private key
//  2. Call GenerateProof with the recovered (n, s) secrets
//  3. Print the Calldata to submit via executeRequest on ZKClaimServiceV3/V4
//
// Usage:
//
//	ZKP_API_KEY=dev-key-1 \
//	ZKP_PRIVKEY=0x<64-hex> \
//	ZKP_ADDRESS=0x<address> \
//	ZKP_FILE_ID=0x<bytes32> \
//	ZKP_LEAF_INDEX=0 \
//	ZKP_ENCRYPTED_SECRET=0x<314-hex> \
//	go run ./examples/generate_proof/
//
// Environment variables:
//
//	ZKP_BASE_URL         Middleware base URL          (default: http://localhost:3002)
//	ZKP_API_KEY          Bearer token                 (required)
//	ZKP_PRIVKEY          0x-prefixed 64-hex private key (required)
//	ZKP_ADDRESS          0x-prefixed user address     (required)
//	ZKP_FILE_ID          0x-prefixed bytes32 file ID  (required)
//	ZKP_LEAF_INDEX       Leaf index from ClaimFile    (required, decimal)
//	ZKP_ENCRYPTED_SECRET EncryptedSecret from ClaimFile (required)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	zkp "github.com/ssanjeewa/go-sdk"
	zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

func main() {
	baseURL := envOr("ZKP_BASE_URL", "http://localhost:3002")
	apiKey := mustEnv("ZKP_API_KEY")
	privKey := mustEnv("ZKP_PRIVKEY")
	userAddress := mustEnv("ZKP_ADDRESS")
	fileID := mustEnv("ZKP_FILE_ID")
	leafIndexStr := mustEnv("ZKP_LEAF_INDEX")
	encryptedSecret := mustEnv("ZKP_ENCRYPTED_SECRET")

	leafIndex, err := strconv.ParseUint(leafIndexStr, 10, 64)
	if err != nil {
		log.Fatalf("ZKP_LEAF_INDEX must be a non-negative integer: %v", err)
	}

	// ── 1. Build client ──────────────────────────────────────────────────────
	client, err := zkp.NewClient(baseURL,
		zkp.WithAPIKey(apiKey),
		zkp.WithTimeout(60*time.Second), // proof generation can take ~1s
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	// ── 2. Decrypt (n, s) from the ClaimFile encrypted secret ────────────────
	fmt.Println("Decrypting credential secrets…")
	secret, err := zkpcrypto.DecryptSecret(encryptedSecret, privKey)
	if err != nil {
		log.Fatalf("DecryptSecret: %v", err)
	}
	fmt.Printf("  n = %s\n  s = %s\n", secret.N.String(), secret.S.String())

	// ── 3. Generate proof ────────────────────────────────────────────────────
	fmt.Printf("\nGenerating proof for\n  address:   %s\n  fileId:    %s\n  leafIndex: %d\n",
		userAddress, fileID, leafIndex)

	ctx := context.Background()
	resp, err := client.GenerateProof(ctx, &zkp.GenerateProofRequest{
		UserAddress: userAddress,
		FileID:      fileID,
		N:           secret.N.String(),
		S:           secret.S.String(),
		LeafIndex:   leafIndex,
	})
	if err != nil {
		log.Fatalf("GenerateProof: %v", err)
	}

	// ── 4. Print results ─────────────────────────────────────────────────────
	fmt.Println("\n── Proof ──────────────────────────────────────────────────")
	prettyPrint(resp.Proof)

	fmt.Println("\n── Public signals ─────────────────────────────────────────")
	for i, s := range resp.PublicSignals {
		fmt.Printf("  [%d] %s\n", i, s)
	}

	fmt.Printf("\n── Request nullifier: %s\n", resp.RequestNullifier)
	fmt.Printf("── ReqID: %s\n", resp.ReqID)

	fmt.Println("\n── executeRequest Calldata (submit this on-chain) ─────────")
	prettyPrint(resp.Calldata)
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
