# ZKP Go SDK — Application Integration Guide

Complete step-by-step guide to integrate `app_integration` into a Go application.
Covers local development, Vault secret management, on-chain setup, and production deployment.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Go | 1.22+ | `go version` |
| PostgreSQL | 14+ | Already in `zkp-middleware` Docker stack |
| HashiCorp Vault | 1.17+ | Already in `zkp-middleware` Docker stack |
| Alchemy account | — | API key + gas policy ID |
| Arbitrum Sepolia access | — | RPC URL (Alchemy or public) |

The `zkp-middleware` Docker stack (`make start` from `zkp-middleware/`) already runs
Vault + Postgres + Vault Agent. This guide reuses that same infrastructure.

---

## Architecture

```
Your Go App
    │
    ├─ IssueAndInsert(ctx, userAddr, fileID)
    │       ├── 1. getOrCreateECIESKey  → Postgres (encrypted_priv_key)
    │       ├── 2. SDK.IssueCredential  → ZKP Middleware  POST /v1/credentials/issue
    │       ├── 3. sendUserOp           → Alchemy Bundler → EntryPoint
    │       │                                  → Light Account → batchInsertLeaves
    │       └── 4. saveClaimFile        → Postgres (claim_data JSONB)
    │
    └─ GenerateAccessProof(ctx, userAddr, fileID)
            ├── 1. loadClaimFile              → Postgres
            ├── 2. loadDecryptedECIESKey      → Postgres → AES-GCM decrypt with DEK
            ├── 3. zkpcrypto.DecryptSecret    → recovers (n, s) in memory only
            ├── 4. SDK.GenerateProof          → ZKP Middleware  POST /v1/proof/generate
            └── 5. sendUserOp(executeRequest) → Alchemy Bundler → ZKClaimServiceV3/V4

Secrets flow (production):
  Vault KV  ──► Vault Agent ──► /vault/secrets/* (RAM tmpfs) ──► app reads _FILE env vars
```

---

## Step 1 — Add secrets to Vault

The existing Vault already has `secret/data/zkp-middleware/*` KV paths.
Add three new secrets for your application. Run these from inside `zkp-middleware/`:

```bash
# Requires the Vault ops token (created during make vault-configure)
export VAULT_TOKEN=$(cat vault-ops-token.txt)
export VAULT_ADDR=http://127.0.0.1:8200

# 1. ZKP middleware Bearer token  (get from admin dashboard → API Keys)
vault kv patch secret/zkp-middleware/app \
  api_key="<your-api-key>"

# 2. Signer private key — the EOA that controls the Light Account
#    NEVER use the owner key here. Create a dedicated signer.
vault kv patch secret/zkp-middleware/app \
  signer_key="0x<64-hex-private-key>"

# 3. ECIES DEK — 32-byte AES-256 key that encrypts per-user ECIES private keys
#    Generate once and store. If lost, all ECIES keys become unreadable.
vault kv patch secret/zkp-middleware/app \
  ecies_dek="$(openssl rand -hex 32)"
```

> **Never** put these values in `.env`, source control, or application logs.

---

## Step 2 — Add Vault Agent templates

Add three template files so Vault Agent renders the new secrets to the RAM tmpfs.

**`zkp-middleware/vault/agent/templates/app_api_key.tmpl`**
```
{{- with secret "secret/data/zkp-middleware/app" -}}{{ .Data.data.api_key }}{{- end -}}
```

**`zkp-middleware/vault/agent/templates/app_signer_key.tmpl`**
```
{{- with secret "secret/data/zkp-middleware/app" -}}{{ .Data.data.signer_key }}{{- end -}}
```

**`zkp-middleware/vault/agent/templates/app_ecies_dek.tmpl`**
```
{{- with secret "secret/data/zkp-middleware/app" -}}{{ .Data.data.ecies_dek }}{{- end -}}
```

Then add these blocks to **`zkp-middleware/vault/agent/vault-agent.hcl`**:

```hcl
# App integration secrets
template {
  source      = "/vault/agent/templates/app_api_key.tmpl"
  destination = "/vault/secrets/app_api_key"
  perms       = 0400
}

template {
  source      = "/vault/agent/templates/app_signer_key.tmpl"
  destination = "/vault/secrets/app_signer_key"
  perms       = 0400
}

template {
  source      = "/vault/agent/templates/app_ecies_dek.tmpl"
  destination = "/vault/secrets/app_ecies_dek"
  perms       = 0400
}
```

Restart Vault Agent to pick up the new templates:

```bash
docker restart zkp-vault-agent
docker logs zkp-vault-agent --tail 20   # confirm "rendered" for all templates
```

---

## Step 3 — Set your Light Account as sponsor

Your signer's Light Account address must have insertion rights on `ZKClaimRegistryV3`.
Run once with the **owner** key:

```bash
cast send 0x9019c0fbCaC853dA04d48CF6049a52b4812C7f28 \
  "setSponsor(address)" \
  <YOUR_LIGHT_ACCOUNT_ADDRESS> \
  --private-key $OWNER_PRIVATE_KEY \
  --rpc-url $ZKP_RPC_URL
```

Confirm:
```bash
cast call 0x9019c0fbCaC853dA04d48CF6049a52b4812C7f28 \
  "sponsor()" \
  --rpc-url $ZKP_RPC_URL
# should return your Light Account address
```

> If you don't have the owner key, ask the contract deployer (`0xb479D7...`) to run this.

---

## Step 4 — Derive your Light Account address

Your Light Account address is deterministic from your signer EOA via CREATE2.
Use the Alchemy Account Kit helper to derive it:

```bash
# Using cast (go-ethereum style) — approximation only; use Account Kit for exact address
npx @alchemy/aa-cli account address \
  --chain arbitrum-sepolia \
  --signer-private-key 0x<your-signer-key>
```

Or run the Go snippet:
```go
// The light account address is derived off-chain. Use Alchemy's SDK or
// call LightAccountFactory.getAddress(owner, salt=0) as a read call:
// Factory: 0x000000893A26168158fbeaDD9335Be5bC96592E2 (LightAccountFactory v2, all EVM chains)
cast call 0x000000893A26168158fbeaDD9335Be5bC96592E2 \
  "getAddress(address,uint256)(address)" \
  <YOUR_SIGNER_EOA_ADDRESS> 0 \
  --rpc-url $ZKP_RPC_URL
```

---

## Step 5 — Add the SDK to your Go module

```bash
go get github.com/ssanjeewa/go-sdk@latest
go get github.com/ethereum/go-ethereum@latest
go get github.com/lib/pq@latest
go mod tidy
```

---

## Step 6 — Copy ZKPService into your project

Copy the three files from `examples/app_integration/` into your own package.
Rename `package main` to your package name (e.g., `package zkpintegration`).

```
your-app/
├── internal/
│   └── zkpintegration/
│       ├── config.go    ← copy from examples/app_integration/config.go
│       ├── service.go   ← copy from examples/app_integration/service.go
│       └── ...
└── cmd/
    └── server/
        └── main.go
```

---

## Step 7 — Wire into your HTTP server

```go
package main

import (
    "context"
    "log"
    "net/http"

    "your-module/internal/zkpintegration"
)

func main() {
    cfg, err := zkpintegration.LoadConfig()
    if err != nil {
        log.Fatalf("config: %v", err)
    }

    svc, err := zkpintegration.NewZKPService(cfg)
    if err != nil {
        log.Fatalf("zkp service: %v", err)
    }
    defer svc.Close()

    http.HandleFunc("/upload/credential", func(w http.ResponseWriter, r *http.Request) {
        userAddr := r.Header.Get("X-User-Address") // Light Account address from auth middleware
        fileID   := r.URL.Query().Get("fileId")

        // Call AFTER the file has been registered on-chain (createFile UserOp).
        if err := svc.IssueAndInsert(r.Context(), userAddr, fileID); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    })

    http.HandleFunc("/download/proof", func(w http.ResponseWriter, r *http.Request) {
        userAddr := r.Header.Get("X-User-Address")
        fileID   := r.URL.Query().Get("fileId")

        proofResp, err := svc.GenerateAccessProof(r.Context(), userAddr, fileID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Return the executeRequest calldata to the client.
        // Client submits this as a UserOp to get the KeyReleased event.
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]any{
            "to":               proofResp.Calldata.To,
            "data":             proofResp.Calldata.Data,
            "requestNullifier": proofResp.RequestNullifier,
        })
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

---

## Step 8 — Environment variables

### Development (env vars directly)

```bash
# Secrets — set directly for local dev
export ZKP_API_KEY="dev-key-1"
export SIGNER_KEY="0x<your-signer-private-key>"
export ECIES_DEK="$(openssl rand -hex 32)"    # generate once, save it
export DATABASE_URL="postgres://zkp:zkp@localhost:5432/zkp?sslmode=disable"

# Non-secrets
export ZKP_BASE_URL="http://localhost:3002"
export ALCHEMY_API_KEY="<your-alchemy-api-key>"
export ALCHEMY_POLICY_ID="<your-gas-policy-id>"
export LIGHT_ACCOUNT_ADDRESS="0x<your-light-account>"
export ZKP_RPC_URL="https://arb-sepolia.g.alchemy.com/v2/$ALCHEMY_API_KEY"
```

### Production (Vault-rendered files via docker-compose)

```yaml
# In your docker-compose.yml app service:
environment:
  ZKP_API_KEY_FILE:     /vault/secrets/app_api_key
  SIGNER_KEY_FILE:      /vault/secrets/app_signer_key
  ECIES_DEK_FILE:       /vault/secrets/app_ecies_dek
  DATABASE_URL_FILE:    /vault/secrets/db_url
  ALCHEMY_API_KEY:      "<non-secret>"
  ALCHEMY_POLICY_ID:    "<non-secret>"
  LIGHT_ACCOUNT_ADDRESS: "0x<address>"
  ZKP_BASE_URL:         "http://zkp-app:3002"
  ZKP_RPC_URL:          "https://arb-sepolia.g.alchemy.com/v2/<key>"
volumes:
  - secrets_ram:/vault/secrets:ro   # same RAM tmpfs as zkp-middleware
```

---

## Step 9 — Run the example

```bash
# Start the full stack first
cd zkp-middleware && make start

# Then run the example (dev mode)
export ZKP_API_KEY="dev-key-1"
export SIGNER_KEY="0x<key>"
export ECIES_DEK="<32-byte-hex>"
export DATABASE_URL="postgres://zkp:zkp@localhost:5432/zkp?sslmode=disable"
export ALCHEMY_API_KEY="<key>"
export ALCHEMY_POLICY_ID="<policy>"
export LIGHT_ACCOUNT_ADDRESS="0x<address>"
export ZKP_RPC_URL="https://arb-sepolia.g.alchemy.com/v2/$ALCHEMY_API_KEY"
export ZKP_USER_ADDRESS="$LIGHT_ACCOUNT_ADDRESS"
export ZKP_FILE_ID="0x<bytes32-file-id>"

go run ./examples/app_integration/
```

---

## Error reference

| Error | Cause | Fix |
|---|---|---|
| `issue credential: file not found on chain` | `createFile` UserOp not yet mined | Wait for `createFile` tx before calling `IssueAndInsert` |
| `send insert userop: paymaster: policy limit` | Alchemy gas policy exhausted | Top up policy or whitelist contract addresses |
| `generate proof: proof: get merkle proof: leaf index N out of range` | `IssueAndInsert` not called, or `batchInsertLeaves` not confirmed | Run `IssueAndInsert` and wait for confirmation first |
| `generate proof: proof: root still diverged after resync` | Middleware restarted with stale tree, chain has more recent leaves | Wait ~5s and retry; middleware will re-sync |
| `decrypt secret: ecies decrypt failed` | Wrong ECIES DEK or rotated signer key | Ensure `ECIES_DEK` matches the one used during key creation |
| `bundler: AA21 didn't pay prefund` | Light Account not set as sponsor | Run `setSponsor` (Step 3) |

---

## Production checklist

- [ ] `SIGNER_KEY` and `ECIES_DEK` stored in Vault, never in `.env` or source control
- [ ] `ECIES_DEK` backed up securely (losing it makes all ECIES keys permanently unreadable)
- [ ] Light Account set as `sponsor` on `ZKClaimRegistryV3` via `setSponsor()`
- [ ] Alchemy gas policy has contract whitelist: `0x9019c0fbCaC853dA04d48CF6049a52b4812C7f28`
- [ ] Alchemy API key scoped to Arbitrum Sepolia only (Alchemy dashboard → API key settings)
- [ ] `zkp_ecies_keys` and `zkp_claim_files` tables on the same Postgres as `zkp-middleware`
- [ ] Signer EOA is NOT the owner (`0xb479D7...`) — use a dedicated key
- [ ] Rate limiting on `/upload/credential` and `/download/proof` endpoints
- [ ] `svc.Close()` called on shutdown to zero the DEK from memory
- [ ] DB backup includes `zkp_ecies_keys` — losing it means no proof generation for those users
