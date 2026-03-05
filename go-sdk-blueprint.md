# Go SDK Blueprint — `github.com/ssanjeewa/go-sdk`

> **Status**: Blueprint v1.0 — ready for implementation
> **Reference**: Node.js SDK `@zkp-system/node-sdk` v2.1.0 (parity target)
> **Scope**: Option 2 — HTTP client + crypto helpers. No admin client.

---

## 1. Overview

The Go SDK provides a standalone client library for Go applications integrating with the
ZKP middleware. It covers two independent layers:

| Layer | Package | Purpose |
|---|---|---|
| HTTP client | `zkp` (root) | REST API calls with auth, retries, typed errors |
| Crypto helpers | `zkp/crypto` | Key generation, ECIES encrypt/decrypt, field validation |

**What it is NOT:**
- Not a re-export of the middleware internals (no `internal/` imports)
- Not a Solidity ABI wrapper (no on-chain submissions — caller handles that)
- Not an admin client (no JWT, no key CRUD — separate concern)

**Relationship to the Node.js SDK:**
One-to-one type and method parity. Any Go service doing the same flow as a
TypeScript app should require zero documentation lookups to translate.

---

## 2. Module Identity

```
module: github.com/ssanjeewa/go-sdk
go:     1.22
path:   sdk/go/          (inside monorepo, standalone go.mod)
```

Published separately to pkg.go.dev. `go get github.com/ssanjeewa/go-sdk@latest`
works without importing anything else from this repository.

### go.mod skeleton

```go
module github.com/ssanjeewa/go-sdk

go 1.22

require (
    github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0   // ECIES, key generation
    github.com/ethereum/go-ethereum            v1.14.8   // keccak256 (scope only)
)
```

> `go-ethereum` is brought in only for `crypto.Keccak256` in the crypto sub-package.
> If the dependency is too heavy, the keccak256 call can be replaced with
> `golang.org/x/crypto/sha3` (pure Go), eliminating the go-ethereum dependency entirely.
> This is a decision to make at implementation time.

---

## 3. Directory Layout

```
sdk/go/
├── go.mod
├── go.sum
├── doc.go                      # package zkp — package-level godoc
├── client.go                   # ZKPClient struct, constructor, all API methods
├── options.go                  # ClientOption functional options (WithAPIKey, etc.)
├── types.go                    # All request/response structs
├── errors.go                   # Error types: ZKPError, APIError, ValidationError, ...
├── validate.go                 # Input validation helpers (internal use by client.go)
├── http.go                     # internal httpClient (not exported)
├── crypto/
│   ├── doc.go                  # package zkpcrypto — sub-package godoc
│   ├── keys.go                 # GenerateKeyPair, PrivateKeyToPublicKey
│   ├── ecies.go                # EncryptSecret, DecryptSecret
│   └── field.go                # BN254ScalarField, IsValidFieldElement
├── examples/
│   ├── issue_credential/
│   │   └── main.go
│   ├── generate_proof/
│   │   └── main.go
│   └── share_file/
│       └── main.go
└── README.md
```

---

## 4. Error Types (`errors.go`)

Mirrors the TypeScript error hierarchy exactly. All errors implement the standard
`error` interface. Callers can type-assert to get structured details.

```go
package zkp

import "fmt"

// ZKPError is the base error type for all SDK errors.
// Callers can inspect Code for programmatic handling.
type ZKPError struct {
    Message string
    Code    string
}

func (e *ZKPError) Error() string { return fmt.Sprintf("[%s] %s", e.Code, e.Message) }

// APIError is returned when the server responds with a non-2xx status code
// that is not covered by a more specific error type.
type APIError struct {
    ZKPError
    StatusCode int
}

// AuthError is returned on HTTP 401 (invalid or missing API key).
type AuthError struct{ ZKPError }

// RateLimitError is returned on HTTP 429. RetryAfter is the suggested wait duration.
type RateLimitError struct {
    ZKPError
    RetryAfterMs int
}

// ValidationError is returned when a request parameter fails client-side
// validation before the HTTP call is made.
type ValidationError struct{ ZKPError }

// NetworkError wraps transport-level failures (DNS, timeout, connection refused).
type NetworkError struct {
    ZKPError
    Cause error
}

func (e *NetworkError) Unwrap() error { return e.Cause }

// NotFoundError is returned on HTTP 404 (file not registered on-chain, etc.).
type NotFoundError struct{ ZKPError }

// ServerError is returned on HTTP 5xx.
type ServerError struct {
    ZKPError
    StatusCode int
}

// TreeFullError is returned on HTTP 409 — user's Merkle tree has no available leaves.
type TreeFullError struct{ ZKPError }

// CryptoError is returned by the crypto sub-package on invalid inputs or
// decryption failures.
type CryptoError struct{ ZKPError }
```

**Error code constants** (use these for programmatic `switch` on `ZKPError.Code`):

```go
const (
    ErrCodeAuth       = "AUTH_ERROR"
    ErrCodeRateLimit  = "RATE_LIMIT_ERROR"
    ErrCodeValidation = "VALIDATION_ERROR"
    ErrCodeNetwork    = "NETWORK_ERROR"
    ErrCodeNotFound   = "NOT_FOUND_ERROR"
    ErrCodeServer     = "SERVER_ERROR"
    ErrCodeTreeFull   = "TREE_FULL"
    ErrCodeCrypto     = "CRYPTO_ERROR"
    ErrCodeAPI        = "API_ERROR"
)
```

---

## 5. Types (`types.go`)

Direct Go translation of `sdk/node/src/types/api.ts`. All JSON field names are
**snake_case** to match the middleware wire format.

```go
package zkp

// ── Health ────────────────────────────────────────────────────────────────────

// HealthResponse is the response from GET /v1/health.
type HealthResponse struct {
    Status          string `json:"status"`           // always "ok"
    ChainID         int64  `json:"chainId"`
    LastSyncBlock   uint64 `json:"lastSyncBlock"`
    TrackedUsers    int    `json:"trackedUsers"`
    MiddlewarePubKey string `json:"middlewarePubKey"` // "0x04..." or "" if unconfigured
}

// ── Calldata ─────────────────────────────────────────────────────────────────

// Calldata is a ready-to-broadcast Ethereum transaction payload.
// The caller signs and submits this via their preferred wallet/RPC library.
type Calldata struct {
    To    string `json:"to"`
    Data  string `json:"data"`
    Value string `json:"value"`
}

// ── Credentials ───────────────────────────────────────────────────────────────

// ClaimFile is the credential record that the user stores locally.
// It contains the encrypted (n, s) secrets needed for proof generation.
type ClaimFile struct {
    UserAddress     string `json:"userAddress"`     // 0x-prefixed Ethereum address
    FileID          string `json:"fileId"`           // 0x-prefixed bytes32
    Commitment      string `json:"commitment"`       // 0x-prefixed bytes32
    LeafIndex       uint64 `json:"leafIndex"`
    EncryptedSecret string `json:"encryptedSecret"` // 0x + 314 hex chars (157-byte ECIES blob)
}

// IssueCredentialRequest is the payload for POST /v1/credentials/issue.
type IssueCredentialRequest struct {
    UserAddress   string `json:"userAddress"`   // 0x-prefixed Ethereum address
    FileID        string `json:"fileId"`         // 0x-prefixed bytes32 (66 chars)
    UserPublicKey string `json:"userPublicKey"` // 0x04-prefixed 65-byte uncompressed secp256k1 (132 hex chars)
    Secret        string `json:"secret,omitempty"` // optional decimal bigint string for n
}

// IssueCredentialResponse is the response from POST /v1/credentials/issue.
type IssueCredentialResponse struct {
    ClaimFile      ClaimFile `json:"claimFile"`
    InsertCalldata Calldata  `json:"insertCalldata"`
}

// ── Batch credential issuance ─────────────────────────────────────────────────

// BatchFileRequest is a single file entry in a batch issuance request.
type BatchFileRequest struct {
    FileID string `json:"fileId"`           // 0x-prefixed bytes32 (66 chars)
    Secret string `json:"secret,omitempty"` // optional decimal bigint string
}

// BatchIssueCredentialRequest is the payload for POST /v1/credentials/issue/batch.
// Files must contain 1–20 entries (MaxBatchSize = 20).
type BatchIssueCredentialRequest struct {
    UserAddress   string             `json:"userAddress"`
    UserPublicKey string             `json:"userPublicKey"`
    Files         []BatchFileRequest `json:"files"`
}

// BatchCredentialItem holds a single ClaimFile within a batch response.
type BatchCredentialItem struct {
    ClaimFile ClaimFile `json:"claimFile"`
}

// BatchIssueCredentialResponse is the response from POST /v1/credentials/issue/batch.
// Credentials is in the same order as the request Files slice.
// InsertCalldata is a single batchInsertLeaves calldata for all N leaves.
type BatchIssueCredentialResponse struct {
    Credentials    []BatchCredentialItem `json:"credentials"`
    InsertCalldata Calldata              `json:"insertCalldata"`
}

// ── Proof ─────────────────────────────────────────────────────────────────────

// SolidityProof is the Groth16 proof in Solidity ABI format.
// All coordinates are decimal bigint strings.
type SolidityProof struct {
    A [2]string    `json:"a"`
    B [2][2]string `json:"b"`
    C [2]string    `json:"c"`
}

// GenerateProofRequest is the payload for POST /v1/proof/generate.
type GenerateProofRequest struct {
    UserAddress   string `json:"userAddress"`
    FileID        string `json:"fileId"`
    N             string `json:"n"`         // decimal bigint string in [1, BN254ScalarField)
    S             string `json:"s"`         // decimal bigint string in [1, BN254ScalarField)
    LeafIndex     uint32 `json:"leafIndex"`
    UserPublicKey string `json:"userPublicKey,omitempty"` // optional — triggers encryptedFileKey in response
}

// GenerateProofResponse is the response from POST /v1/proof/generate.
type GenerateProofResponse struct {
    Proof            SolidityProof `json:"proof"`
    PublicSignals    [7]string     `json:"publicSignals"` // 7 field elements as decimal strings
    Calldata         Calldata      `json:"calldata"`
    RequestNullifier string        `json:"requestNullifier"` // 0x-prefixed bytes32
    ReqID            string        `json:"reqId"`            // decimal bigint string
    EncryptedFileKey string        `json:"encryptedFileKey,omitempty"` // ECIES hex, only when UserPublicKey provided
}

// ── Shares ────────────────────────────────────────────────────────────────────

// SharePrepareRequest is the payload for POST /v1/shares/prepare.
type SharePrepareRequest struct {
    FileID                 string `json:"fileId"`
    GranteeAddress         string `json:"granteeAddress"`
    GranteePublicKey       string `json:"granteePublicKey"`   // 0x04-prefixed 65-byte uncompressed secp256k1
    EncryptedKeyForGrantee string `json:"encryptedKeyForGrantee"` // ECIES blob — AES key re-encrypted for grantee
}

// SharePrepareResponse is the response from POST /v1/shares/prepare.
type SharePrepareResponse struct {
    InsertCalldata      Calldata `json:"insertCalldata"`      // batchInsertLeaves for grantee's tree
    GrantShareCalldata  Calldata `json:"grantShareCalldata"`  // grantShare on-chain call
    EncryptedCredential string   `json:"encryptedCredential"` // ECIES(granteePubKey, n_share‖s_share‖leafIndex)
}

// IncomingShare is a single share entry in IncomingSharesResponse.
type IncomingShare struct {
    FileID              string `json:"fileId"`
    Owner               string `json:"owner"`
    Active              bool   `json:"active"`
    GrantedAtBlock      uint64 `json:"grantedAtBlock"`
    EncryptedCredential string `json:"encryptedCredential"` // decrypt with grantee's private key → (n, s, leafIndex)
}

// IncomingSharesResponse is the response from GET /v1/shares/incoming/{address}.
type IncomingSharesResponse struct {
    Address string          `json:"address"`
    Shares  []IncomingShare `json:"shares"`
}

// ── User Registry ─────────────────────────────────────────────────────────────

// UserPubKeyResponse is the response from GET /v1/users/{address}/pubkey.
type UserPubKeyResponse struct {
    Registered bool   `json:"registered"`
    PubKey     string `json:"pubKey"` // "0x04..." 130-char hex, "" if not registered
}

// ResolveEmailResponse is the response from GET /v1/users/by-email/{emailHash}.
type ResolveEmailResponse struct {
    Registered bool   `json:"registered"`
    Address    string `json:"address"` // 0x-prefixed Ethereum address, zero address if not found
}
```

---

## 6. Client Options (`options.go`)

Functional options pattern — idiomatic Go, mirrors the TypeScript `ZKPClientOptions`
struct.

```go
package zkp

import "time"

// ClientOption is a functional option for configuring ZKPClient.
type ClientOption func(*clientConfig)

type clientConfig struct {
    apiKey       string
    timeout      time.Duration
    maxRetries   int
    retryDelay   time.Duration
}

func defaultConfig() *clientConfig {
    return &clientConfig{
        timeout:    30 * time.Second,
        maxRetries: 3,
        retryDelay: 200 * time.Millisecond,
    }
}

// WithAPIKey sets the Bearer token for authenticated requests.
// Required for all endpoints except Health() and Metrics().
func WithAPIKey(key string) ClientOption {
    return func(c *clientConfig) { c.apiKey = key }
}

// WithTimeout overrides the per-request HTTP timeout (default: 30s).
// Set higher for proof generation (~600ms proof + network round-trip).
func WithTimeout(d time.Duration) ClientOption {
    return func(c *clientConfig) { c.timeout = d }
}

// WithMaxRetries sets the number of retry attempts for retryable errors
// (429, 500, 502, 503, 504). Default: 3. Set 0 to disable retries.
func WithMaxRetries(n int) ClientOption {
    return func(c *clientConfig) { c.maxRetries = n }
}

// WithRetryDelay sets the base delay between retries (default: 200ms).
// Actual delay uses exponential backoff with ±10% jitter.
func WithRetryDelay(d time.Duration) ClientOption {
    return func(c *clientConfig) { c.retryDelay = d }
}
```

---

## 7. HTTP Client (`http.go`)

Not exported. Used internally by `ZKPClient`. Mirrors the TypeScript `HttpClient`
exactly — same retry logic, same status-code-to-error mapping.

```go
// internal httpClient design (not exported)

type httpClient struct {
    baseURL    string
    headers    map[string]string // Content-Type, Accept, Authorization
    timeout    time.Duration
    maxRetries int
    retryDelay time.Duration
    client     *http.Client
}

// Retryable status codes (same set as TypeScript SDK)
var retryableStatus = map[int]bool{
    429: true,
    500: true,
    502: true,
    503: true,
    504: true,
}

// Retry strategy: exponential backoff with 10% jitter, capped at 30s.
//   delay(attempt) = min(base * 2^attempt, 30s) + rand(0, delay*0.1)
//
// Retries apply to: network errors + retryableStatus codes.
// Non-retryable errors (400, 401, 404, 409) return immediately.

// Status → error type mapping:
//   401 → *AuthError
//   404 → *NotFoundError
//   409 → *TreeFullError
//   429 → *RateLimitError  (reads Retry-After header, converts to ms)
//   5xx → *ServerError{StatusCode}
//   other non-2xx → *APIError{StatusCode}
//   network/timeout → *NetworkError{Cause}
//
// 204 No Content → returns nil response body (no error).
// text/plain Content-Type → returns raw string (used by Metrics endpoint).
```

---

## 8. Client API (`client.go`)

### Constructor

```go
// NewClient creates a new ZKPClient.
//
//   client := zkp.NewClient("http://localhost:3002",
//       zkp.WithAPIKey("my-api-key"),
//       zkp.WithTimeout(60*time.Second),
//   )
func NewClient(baseURL string, opts ...ClientOption) (*ZKPClient, error)
```

Returns `*ValidationError` if `baseURL` is empty.

### Method signatures

All methods take `ctx context.Context` as first argument for timeout and
cancellation propagation.

```go
// ── Health & Observability (no API key required) ──────────────────────────────

// Health calls GET /v1/health.
func (c *ZKPClient) Health(ctx context.Context) (*HealthResponse, error)

// Metrics calls GET /metrics and returns the raw Prometheus text.
func (c *ZKPClient) Metrics(ctx context.Context) (string, error)

// ── Credentials (API key required) ───────────────────────────────────────────

// IssueCredential calls POST /v1/credentials/issue.
// Returns ClaimFile (store this) and InsertCalldata (submit on-chain).
func (c *ZKPClient) IssueCredential(ctx context.Context, req *IssueCredentialRequest) (*IssueCredentialResponse, error)

// IssueCredentialBatch calls POST /v1/credentials/issue/batch.
// Issues 1–20 credentials atomically. Returns one ClaimFile per file (same
// order as req.Files) and ONE combined batchInsertLeaves calldata.
func (c *ZKPClient) IssueCredentialBatch(ctx context.Context, req *BatchIssueCredentialRequest) (*BatchIssueCredentialResponse, error)

// ── Proof (API key required) ──────────────────────────────────────────────────

// GenerateProof calls POST /v1/proof/generate.
// n and s must be decimal bigint strings in [1, BN254ScalarField).
// Client validates the field bounds before making the HTTP call.
func (c *ZKPClient) GenerateProof(ctx context.Context, req *GenerateProofRequest) (*GenerateProofResponse, error)

// ── Shares (API key required) ─────────────────────────────────────────────────

// PrepareShare calls POST /v1/shares/prepare.
// Issues a fresh grantee credential and returns the calldatas needed to:
//   1. Insert the grantee's leaf into their Merkle tree (InsertCalldata)
//   2. Grant the share on-chain (GrantShareCalldata)
func (c *ZKPClient) PrepareShare(ctx context.Context, req *SharePrepareRequest) (*SharePrepareResponse, error)

// IncomingShares calls GET /v1/shares/incoming/{granteeAddress}.
// Returns all active and revoked shares granted to the given address.
// Each share contains EncryptedCredential — decrypt with the grantee's
// private key to recover (n, s, leafIndex) for proof generation.
func (c *ZKPClient) IncomingShares(ctx context.Context, granteeAddress string) (*IncomingSharesResponse, error)

// ── User Registry (API key required) ─────────────────────────────────────────

// GetUserPubKey calls GET /v1/users/{address}/pubkey.
// Returns the ECIES public key registered for a wallet address.
// Use this to encrypt credentials when preparing a share for another user.
func (c *ZKPClient) GetUserPubKey(ctx context.Context, address string) (*UserPubKeyResponse, error)

// ResolveEmail calls GET /v1/users/by-email/{emailHash}.
// emailHash must be keccak256(strings.ToLower(email)) as a 0x-prefixed bytes32.
// Returns the wallet address registered against that email hash.
func (c *ZKPClient) ResolveEmail(ctx context.Context, emailHash string) (*ResolveEmailResponse, error)

// ── Key management ────────────────────────────────────────────────────────────

// SetAPIKey replaces the API key used for authenticated requests.
// Safe to call concurrently — creates a new internal HTTP client.
func (c *ZKPClient) SetAPIKey(apiKey string)
```

### Client-side validation (before HTTP calls)

`IssueCredential`, `IssueCredentialBatch`, `GenerateProof`, `PrepareShare`,
`IncomingShares`, `GetUserPubKey`, `ResolveEmail` all perform local validation
and return `*ValidationError` immediately (no HTTP call) if:

| Field | Rule |
|---|---|
| `userAddress` | `/^0x[0-9a-fA-F]{40}$/` |
| `fileId` | `/^0x[0-9a-fA-F]{64}$/` |
| `userPublicKey` | `/^0x04[0-9a-fA-F]{128}$/` |
| `n`, `s` | valid decimal bigint, `0 < value < BN254ScalarField` |
| `leafIndex` | `>= 0` |
| `files` | length 1–20 (`MaxBatchSize`) |
| `emailHash` | `/^0x[0-9a-fA-F]{64}$/` |

---

## 9. Crypto Sub-package (`crypto/`)

### Package identity

```go
package zkpcrypto  // import "github.com/ssanjeewa/go-sdk/crypto"
```

> **Source of truth**: All logic is a clean port of `zkp-middleware/internal/crypto/`
> (ecies.go, secrets.go) and `sdk/node/src/crypto/keys.ts`.
> The wire format and all byte layouts are identical — Go middleware and this SDK
> can encrypt/decrypt each other's output interchangeably.

### `keys.go`

```go
// KeyPair holds a secp256k1 key pair.
type KeyPair struct {
    PrivateKey string // 0x-prefixed 32-byte hex (64 hex chars)
    PublicKey  string // 0x04-prefixed 65-byte uncompressed point (130 hex chars)
}

// GenerateKeyPair generates a fresh cryptographically random secp256k1 key pair.
// Uses crypto/rand via github.com/decred/dcrd/dcrec/secp256k1/v4.
// The private key is padded to 64 hex chars (handles leading-zero edge case).
func GenerateKeyPair() (*KeyPair, error)

// PrivateKeyToPublicKey derives the uncompressed secp256k1 public key from a private key.
// privateKeyHex must be a 0x-prefixed 32-byte hex string (64 hex chars).
func PrivateKeyToPublicKey(privateKeyHex string) (string, error)

// IsValidPublicKey returns true if pubKeyHex is a 0x04-prefixed 65-byte
// uncompressed secp256k1 public key (130 hex chars after the 0x04 prefix byte).
func IsValidPublicKey(pubKeyHex string) bool
```

### `ecies.go`

```go
// DecryptedSecret holds the (n, s) secrets recovered from a ClaimFile.EncryptedSecret.
type DecryptedSecret struct {
    N *big.Int // Nullifier secret
    S *big.Int // Trapdoor secret
}

// EncryptSecret ECIES-encrypts (n, s) for a recipient's secp256k1 public key.
//
// Wire format (157 bytes):
//   ephPubKey(65) | IV(12) | ciphertext(64) | GCMtag(16)
//
// AES key = SHA-256(ECDH_x_coordinate)
//
// recipientPubKeyHex must be 0x04-prefixed 65-byte uncompressed secp256k1 (130 hex chars).
// Returns "0x" + hex.EncodeToString(157-byte blob) = 316 chars total.
//
// Output is byte-for-byte compatible with:
//   - Go middleware ECIESEncrypt (zkp-middleware/internal/crypto/ecies.go)
//   - Node.js SDK encryptSecret (sdk/node/src/crypto/ecies.ts)
func EncryptSecret(recipientPubKeyHex string, n, s *big.Int) (string, error)

// DecryptSecret decrypts a ClaimFile.EncryptedSecret to recover (n, s).
//
// encryptedSecretHex: 0x-prefixed hex, 157 bytes (316 chars including 0x).
// privateKeyHex: 0x-prefixed 32-byte secp256k1 private key (64 hex chars).
//
// Returns *CryptoError if the wire format is invalid, the key is wrong,
// or the GCM authentication tag does not verify (tampered ciphertext).
func DecryptSecret(encryptedSecretHex, privateKeyHex string) (*DecryptedSecret, error)
```

### `field.go`

```go
// BN254ScalarField is the BN254 scalar field modulus.
// All ZKP circuit inputs (n, s, scope, publicSignals[*]) must be < this value.
var BN254ScalarField *big.Int // = 21888242871839275222246405745257275088548364400416034343698204186575808495617

// IsValidFieldElement returns true if v is in the range [0, BN254ScalarField).
// Use this to validate n and s before calling GenerateProof.
func IsValidFieldElement(v *big.Int) bool

// ParseFieldElement parses a decimal string into a *big.Int and validates it
// is a valid BN254 field element. Returns *ValidationError on failure.
func ParseFieldElement(s string) (*big.Int, error)
```

---

## 10. Validation Logic (`validate.go`)

Internal package-level helpers used by `client.go`. Not exported — callers see
only `*ValidationError` as the result.

```go
// Regexps
var (
    reHexAddress    = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
    reBytes32       = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
    reUncompressedPubKey = regexp.MustCompile(`^0x04[0-9a-fA-F]{128}$`)
    reDecimalString = regexp.MustCompile(`^\d+$`)
)

// validateIssueRequest — checks userAddress, fileId, userPublicKey, optional secret
// validateBatchIssueRequest — checks all of the above for 1–20 files
// validateProofRequest — checks address, fileId, n/s field bounds, leafIndex >= 0
// validateSharePrepareRequest — checks fileId, granteeAddress, granteePublicKey, encryptedKeyForGrantee
```

---

## 11. Concurrency Contract

- `ZKPClient` is **safe for concurrent use**. All state is immutable after construction.
- `SetAPIKey` creates a new internal HTTP client atomically via an `atomic.Pointer`.
- The `crypto` sub-package is **stateless** — all functions are safe for concurrent use.
- No goroutines are created inside the SDK — all calls are synchronous from the caller's
  perspective (context cancellation and timeout are handled via `http.Request.WithContext`).

---

## 12. Complete Usage Example

```go
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
    // ── 1. Create client ─────────────────────────────────────────────────────
    client, err := zkp.NewClient(
        "http://localhost:3002",
        zkp.WithAPIKey(os.Getenv("ZKP_API_KEY")),
        zkp.WithTimeout(60*time.Second), // proof gen takes ~600ms + network
    )
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // ── 2. Health check ──────────────────────────────────────────────────────
    health, err := client.Health(ctx)
    if err != nil {
        log.Fatal("health check failed:", err)
    }
    fmt.Printf("middleware OK — chain %d, synced to block %d\n",
        health.ChainID, health.LastSyncBlock)

    // ── 3. Generate user key pair (store private key securely) ───────────────
    keyPair, err := zkpcrypto.GenerateKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("public key:", keyPair.PublicKey)

    // ── 4. Issue credential (after file is registered on-chain) ──────────────
    issueResp, err := client.IssueCredential(ctx, &zkp.IssueCredentialRequest{
        UserAddress:   "0xabc...def",
        FileID:        "0x" + "a1b2..." /* 64 hex chars */,
        UserPublicKey: keyPair.PublicKey,
    })
    if err != nil {
        switch e := err.(type) {
        case *zkp.NotFoundError:
            log.Fatal("file not registered on-chain:", e)
        case *zkp.TreeFullError:
            log.Fatal("user's Merkle tree is full:", e)
        default:
            log.Fatal("unexpected error:", err)
        }
    }

    // Persist claimFile — required for proof generation
    claimFile := issueResp.ClaimFile
    fmt.Printf("credential issued — leafIndex=%d\n", claimFile.LeafIndex)
    // TODO: caller submits issueResp.InsertCalldata on-chain (batchInsertLeaves)

    // ── 5. Decrypt secrets from stored ClaimFile ─────────────────────────────
    secrets, err := zkpcrypto.DecryptSecret(claimFile.EncryptedSecret, keyPair.PrivateKey)
    if err != nil {
        log.Fatal("decrypt failed:", err)
    }

    // ── 6. Generate proof for download ───────────────────────────────────────
    proofResp, err := client.GenerateProof(ctx, &zkp.GenerateProofRequest{
        UserAddress: claimFile.UserAddress,
        FileID:      claimFile.FileID,
        N:           secrets.N.String(),
        S:           secrets.S.String(),
        LeafIndex:   uint32(claimFile.LeafIndex),
    })
    if err != nil {
        log.Fatal("proof generation failed:", err)
    }

    out, _ := json.MarshalIndent(proofResp.Calldata, "", "  ")
    fmt.Println("calldata ready to broadcast:", string(out))
    // TODO: caller submits proofResp.Calldata on-chain (executeRequest)
}
```

---

## 13. Error Handling Guide

```go
// Pattern 1: type-switch for fine-grained handling
resp, err := client.IssueCredential(ctx, req)
if err != nil {
    switch e := err.(type) {
    case *zkp.ValidationError:
        // bad input — fix the request
        fmt.Println("invalid request:", e.Message)
    case *zkp.NotFoundError:
        // file not on-chain yet — retry after createFile tx confirms
        fmt.Println("file not found:", e.Message)
    case *zkp.TreeFullError:
        // user's Merkle tree exhausted (depth 24 = 16M leaves)
        fmt.Println("tree full:", e.Message)
    case *zkp.RateLimitError:
        // back off and retry
        time.Sleep(time.Duration(e.RetryAfterMs) * time.Millisecond)
    case *zkp.NetworkError:
        // transport failure — check errors.Unwrap(e) for root cause
        fmt.Println("network error:", e.Cause)
    default:
        fmt.Println("unexpected error:", err)
    }
    return
}

// Pattern 2: errors.As for just one type
var valErr *zkp.ValidationError
if errors.As(err, &valErr) {
    fmt.Println("validation:", valErr.Message)
}
```

---

## 14. Testing Strategy

### Unit tests (no network, no crypto)

| File | What to test |
|---|---|
| `validate_test.go` | Each validation rule: valid/invalid address, bytes32, pubkey, field elements |
| `errors_test.go` | Error type assertions, `errors.As` / `errors.Is` compatibility |
| `http_test.go` | Status-to-error mapping, retry logic using `httptest.NewServer` |

### Integration tests

Use `httptest.NewServer` to mock the middleware. Each client method gets at least:
- Happy path — valid response, correct type returned
- 400 Bad Request → `ValidationError` (or `APIError`)
- 401 → `AuthError`
- 404 → `NotFoundError`
- 409 → `TreeFullError`
- 429 → `RateLimitError` with correct `RetryAfterMs`
- 500 → `ServerError`
- Timeout → `NetworkError`

### Crypto tests

| Test | What to verify |
|---|---|
| Round-trip encrypt/decrypt | `EncryptSecret` → `DecryptSecret` returns identical `(n, s)` |
| Cross-compatibility | Encrypt with Go SDK, decrypt with Node.js SDK reference vector (and vice versa) |
| Invalid private key | `DecryptSecret` returns `*CryptoError` |
| Tampered ciphertext | GCM auth tag failure → `*CryptoError` |
| Field bounds | `IsValidFieldElement(BN254ScalarField)` = false, `BN254ScalarField - 1` = true |
| Key generation | `GenerateKeyPair` returns properly formatted keys, `PrivateKeyToPublicKey` roundtrips |

### Cross-SDK compatibility vectors

Store test vectors as JSON files in `crypto/testdata/` — hardcoded `(n, s)` pairs
encrypted with the Go middleware's `ECIESEncrypt` and decrypted by this SDK.
This ensures wire-format compatibility across Go middleware ↔ Go SDK ↔ Node.js SDK.

### Coverage targets

- Statements: ≥ 90%
- Branches:   ≥ 85%
- Functions:  100% of exported symbols

---

## 15. Dependencies Summary

| Dependency | Version | Why |
|---|---|---|
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | v4.3.0 | secp256k1 ECDH for ECIES, key generation |
| `github.com/ethereum/go-ethereum` | v1.14.8 | `crypto.Keccak256` for scope calculation (optional) |

**Stdlib only** for everything else:
- `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256` — ECIES cipher
- `encoding/hex`, `encoding/json` — wire encoding
- `math/big` — BN254 field arithmetic
- `net/http` — HTTP client
- `regexp` — input validation
- `sync/atomic` — thread-safe `SetAPIKey`

> If `go-ethereum` is too large a dependency for the crypto-only import path,
> `crypto.Keccak256` can be replaced with `golang.org/x/crypto/sha3.NewLegacyKeccak256()`.
> Mark this as a decision to revisit at implementation time.

---

## 16. Publishing

```
go get github.com/ssanjeewa/go-sdk@latest
go get github.com/ssanjeewa/go-sdk/crypto@latest
```

- Module lives at `sdk/go/` inside the monorepo with its own `go.mod`
- Tagged independently: `sdk/go/v0.1.0` (monorepo sub-module tag convention)
- `go.sum` committed alongside `go.mod`
- CI runs `go test -race ./...` and `go vet ./...` on every push to `sdk/go/**`
- License: MIT (same as Node.js SDK)

---

## 17. Out of Scope (v1)

The following are **explicitly out of scope** for the initial Go SDK release:

| Feature | Reason |
|---|---|
| Admin client (login, key CRUD) | Separate concern; admin is operator tooling, not app integration |
| On-chain submission | Caller provides their own go-ethereum client and wallet |
| Proof generation (circuit/snarkjs) | Handled by the middleware server — never in the client |
| Merkle tree operations | Middleware manages the tree — client just stores `leafIndex` |
| File encryption/decryption (AES) | App-level concern, out of protocol scope |
| Streaming / WebSocket | Not in the middleware API |
| React / gRPC bindings | Not applicable to Go |

---

## 18. Implementation Sequence

When building from this blueprint, implement in this order to unlock testing at each step:

1. **`errors.go`** — error types first (no dependencies)
2. **`crypto/field.go`** — `BN254ScalarField`, `IsValidFieldElement`, `ParseFieldElement`
3. **`crypto/keys.go`** — `GenerateKeyPair`, `PrivateKeyToPublicKey`
4. **`crypto/ecies.go`** — `EncryptSecret`, `DecryptSecret` (+ cross-compat tests)
5. **`types.go`** — all request/response structs
6. **`validate.go`** — validation helpers
7. **`http.go`** — internal HTTP client with retry + error mapping
8. **`options.go`** — `ClientOption` and `defaultConfig`
9. **`client.go`** — `NewClient` + all 10 API methods
10. **`examples/`** — runnable examples
11. **`README.md`** — installation + quickstart

Each step is independently testable. Steps 1–4 (crypto) have zero network dependency.

---

*Blueprint written 2026-03-05. Reference: Node.js SDK v2.1.0, Go middleware v1.0 (implementation-plan.md).*
