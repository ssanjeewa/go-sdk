// app_integration shows how to wire ZKPService into your application.
//
// Two operations are demonstrated:
//   - UploadFile:   issue credential + insert leaf on-chain  (called after file is registered)
//   - DownloadFile: generate proof + return executeRequest calldata
//
// Environment variables (Vault-rendered files used in production):
//
//	# Secrets — set *_FILE to path of Vault-rendered file, or set directly for local dev
//	ZKP_API_KEY          (or ZKP_API_KEY_FILE)    — middleware Bearer token
//	SIGNER_KEY           (or SIGNER_KEY_FILE)      — Light Account signer private key
//	ECIES_DEK            (or ECIES_DEK_FILE)       — 32-byte hex AES-256 key for ECIES key encryption
//	DATABASE_URL         (or DATABASE_URL_FILE)    — Postgres connection string
//
//	# Non-secret
//	ZKP_BASE_URL         — middleware base URL   (default: http://localhost:3002)
//	ALCHEMY_API_KEY      — Alchemy API key       (bundler + paymaster)
//	ALCHEMY_POLICY_ID    — gas sponsorship policy
//	LIGHT_ACCOUNT_ADDRESS — Light Account address (msg.sender in contracts)
//	ZKP_RPC_URL          — Arbitrum Sepolia RPC
//	ZKP_USER_ADDRESS     — user Light Account address (demo only)
//	ZKP_FILE_ID          — 0x-prefixed bytes32 file ID (demo only)
//
// First-run Vault setup (same Vault as zkp-middleware):
//
//	vault kv put secret/data/zkp-middleware/api_key    value=<bearer-token>
//	vault kv put secret/data/zkp-middleware/signer_key value=0x<privkey-hex>
//	vault kv put secret/data/zkp-middleware/ecies_dek  value=<32-byte-hex>
//	vault kv put secret/data/zkp-middleware/db_url     value=<postgres-dsn>
//
// Generate a secure ECIES DEK (one-time):
//
//	openssl rand -hex 32
package main

import (
	"context"
	"fmt"
	"log"
	"os"
)

func main() {
	// ── Load config (Vault-rendered files → secrets, env → non-secrets) ──────
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// ── Build service ─────────────────────────────────────────────────────────
	svc, err := NewZKPService(cfg)
	if err != nil {
		log.Fatalf("service: %v", err)
	}
	defer svc.Close()

	ctx := context.Background()

	// Demo values — in production these come from your HTTP request / job queue.
	userAddress := mustEnv("ZKP_USER_ADDRESS") // Light Account address
	fileID      := mustEnv("ZKP_FILE_ID")      // 0x-prefixed bytes32

	// ── Upload flow ───────────────────────────────────────────────────────────
	// Call this AFTER the file has been registered on-chain (createFile UserOp).
	// ZKPService handles: keypair generation, credential issuance, leaf insertion.
	fmt.Printf("Issuing credential for user=%s file=%s\n", userAddress, fileID)
	if err := svc.IssueAndInsert(ctx, userAddress, fileID); err != nil {
		log.Fatalf("IssueAndInsert: %v", err)
	}
	fmt.Println("✓ Credential issued and leaf inserted on-chain")

	// ── Download flow ─────────────────────────────────────────────────────────
	// Call this when the user requests access to the file.
	fmt.Printf("\nGenerating access proof for user=%s file=%s\n", userAddress, fileID)
	proofResp, err := svc.GenerateAccessProof(ctx, userAddress, fileID)
	if err != nil {
		log.Fatalf("GenerateAccessProof: %v", err)
	}
	fmt.Printf("✓ Proof ready  reqId=%s  nullifier=%s\n", proofResp.ReqID, proofResp.RequestNullifier)
	fmt.Printf("\n── executeRequest calldata ──\n")
	fmt.Printf("  to:   %s\n", proofResp.Calldata.To)
	fmt.Printf("  data: %s\n", proofResp.Calldata.Data)

	// Submit proofResp.Calldata on-chain as a UserOp (same sendUserOp pattern).
	// The executeRequest call verifies the proof and emits KeyReleased event.
	executeTxHash, err := svc.sendUserOp(ctx, proofResp.Calldata)
	if err != nil {
		log.Fatalf("sendUserOp (execute): %v", err)
	}
	fmt.Printf("\n✓ executeRequest tx: %s\n", executeTxHash)
	if err := svc.waitForTx(ctx, executeTxHash); err != nil {
		log.Fatalf("waitForTx (execute): %v", err)
	}
	fmt.Println("✓ Access granted — KeyReleased event emitted")
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("environment variable %s is required", key)
	}
	return v
}
