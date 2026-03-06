package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all secrets and settings for the ZKP integration service.
// All sensitive values use the _FILE pattern: if ${KEY}_FILE is set, the
// value is read from that file (Vault Agent renders it to RAM tmpfs at
// /vault/secrets/). Otherwise ${KEY} is used directly (local dev).
//
// Vault Agent path:  /vault/secrets/<name>
// Vault KV path:     secret/data/zkp-middleware/<name>
type Config struct {
	// ── Secrets (read from Vault-rendered files in production) ───────────────

	// ZKP middleware Bearer token (Vault: secret/data/zkp-middleware/api_key)
	ZKPAPIKey string

	// secp256k1 private key for the Light Account signer, 0x-prefixed hex
	// (Vault: secret/data/zkp-middleware/signer_key)
	SignerKey string

	// 32-byte AES-256 key used to encrypt per-user ECIES private keys in DB
	// (Vault: secret/data/zkp-middleware/ecies_dek)
	// Stored as 64-char hex string.
	ECIESDek string

	// PostgreSQL connection string
	// (Vault: secret/data/zkp-middleware/db_url)
	DatabaseURL string

	// ── Non-secret configuration ─────────────────────────────────────────────

	ZKPBaseURL    string
	AlchemyAPIKey string   // for bundler + paymaster (can be non-secret RPC key)
	AlchemyPolicy string   // Alchemy gas sponsorship policy ID
	LightAccount  string   // Light Account address (0x-prefixed)
	RPCURL        string   // Arbitrum Sepolia RPC URL
	Timeout       time.Duration
}

// LoadConfig reads config using the _FILE env-var pattern.
// In production, Vault Agent renders secrets to /vault/secrets/*.
// In development, set env vars directly (e.g., ZKP_API_KEY=dev-key-1).
func LoadConfig() (*Config, error) {
	cfg := &Config{
		ZKPAPIKey:     loadSecret("ZKP_API_KEY"),
		SignerKey:     loadSecret("SIGNER_KEY"),
		ECIESDek:      loadSecret("ECIES_DEK"),
		DatabaseURL:   loadSecret("DATABASE_URL"),
		ZKPBaseURL:    envOr("ZKP_BASE_URL", "http://localhost:3002"),
		AlchemyAPIKey: os.Getenv("ALCHEMY_API_KEY"),
		AlchemyPolicy: os.Getenv("ALCHEMY_POLICY_ID"),
		LightAccount:  os.Getenv("LIGHT_ACCOUNT_ADDRESS"),
		RPCURL:        os.Getenv("ZKP_RPC_URL"),
		Timeout:       60 * time.Second,
	}

	var errs []string
	if cfg.ZKPAPIKey == ""    { errs = append(errs, "ZKP_API_KEY or ZKP_API_KEY_FILE") }
	if cfg.SignerKey == ""    { errs = append(errs, "SIGNER_KEY or SIGNER_KEY_FILE") }
	if cfg.ECIESDek == ""    { errs = append(errs, "ECIES_DEK or ECIES_DEK_FILE") }
	if cfg.DatabaseURL == "" { errs = append(errs, "DATABASE_URL or DATABASE_URL_FILE") }
	if cfg.AlchemyAPIKey == "" { errs = append(errs, "ALCHEMY_API_KEY") }
	if cfg.AlchemyPolicy == "" { errs = append(errs, "ALCHEMY_POLICY_ID") }
	if cfg.LightAccount == "" { errs = append(errs, "LIGHT_ACCOUNT_ADDRESS") }
	if cfg.RPCURL == ""      { errs = append(errs, "ZKP_RPC_URL") }

	if len(errs) > 0 {
		return nil, fmt.Errorf("missing required config: %s", strings.Join(errs, ", "))
	}
	return cfg, nil
}

// loadSecret checks ${key}_FILE first (Vault sidecar / production),
// then falls back to ${key} env var (local dev). File bytes are zeroed after read.
func loadSecret(key string) string {
	if path := os.Getenv(key + "_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return ""
		}
		value := strings.TrimRight(string(data), "\r\n")
		// Zero the buffer — file may still be in OS page cache but
		// this prevents the plaintext from living in our heap longer than needed.
		for i := range data {
			data[i] = 0
		}
		return value
	}
	return os.Getenv(key)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
