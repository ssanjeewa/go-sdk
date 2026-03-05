# go-sdk

Go client library for the [ZKP middleware](https://github.com/ssanjeewa/zkp-auth) — HTTP client + ECIES crypto helpers for the ZKClaimUpload zero-knowledge credential protocol on Arbitrum Sepolia.

---

## Installation

```bash
go get github.com/ssanjeewa/go-sdk@latest
```

Crypto sub-package only (no HTTP dependency, no `net/http`):

```bash
go get github.com/ssanjeewa/go-sdk/crypto@latest
```

**Requires**: Go 1.22+

---

## Quickstart

The example below shows the full credential issuance + proof generation flow.

```go
package main

import (
    "context"
    "fmt"
    "log"

    zkp       "github.com/ssanjeewa/go-sdk"
    zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

func main() {
    ctx := context.Background()

    // 1. Create client
    client, err := zkp.NewClient("https://middleware.example.com",
        zkp.WithAPIKey("your-api-key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // 2. Generate a secp256k1 key pair (store the private key securely)
    kp, err := zkpcrypto.GenerateKeyPair()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("privateKey:", kp.PrivateKey) // 0x-prefixed 64-hex
    fmt.Println("publicKey: ", kp.PublicKey)  // 0x04-prefixed 130-hex

    // 3. Issue a credential
    issueResp, err := client.IssueCredential(ctx, &zkp.IssueCredentialRequest{
        UserAddress:   "0xYourWalletAddress",
        FileID:        "0xYourFileID000000000000000000000000000000000000000000000000000000",
        UserPublicKey: kp.PublicKey,
    })
    if err != nil {
        log.Fatal(err)
    }
    claimFile := issueResp.ClaimFile
    fmt.Println("leafIndex:       ", claimFile.LeafIndex)
    fmt.Println("encryptedSecret: ", claimFile.EncryptedSecret)
    // Submit issueResp.InsertCalldata on-chain via batchInsertLeaves

    // 4. Later: decrypt secrets and generate a proof
    secret, err := zkpcrypto.DecryptSecret(claimFile.EncryptedSecret, kp.PrivateKey)
    if err != nil {
        log.Fatal(err)
    }

    proofResp, err := client.GenerateProof(ctx, &zkp.GenerateProofRequest{
        UserAddress: "0xYourWalletAddress",
        FileID:      claimFile.FileID,
        N:           secret.N.String(),
        S:           secret.S.String(),
        LeafIndex:   claimFile.LeafIndex,
    })
    if err != nil {
        log.Fatal(err)
    }
    // Submit proofResp.Calldata on-chain via executeRequest
    fmt.Println("requestNullifier:", proofResp.RequestNullifier)
}
```

---

## API Reference

### `zkp` package — HTTP client

| Method | Auth | Description |
|---|---|---|
| `NewClient(baseURL, ...opts)` | — | Create a client. Returns `*ValidationError` if baseURL is empty. |
| `Health(ctx)` | No | GET `/v1/health` — service status and chain ID. |
| `Metrics(ctx)` | No | GET `/metrics` — raw Prometheus text. |
| `IssueCredential(ctx, req)` | Yes | POST `/v1/credentials/issue` — issue one credential. |
| `IssueCredentialBatch(ctx, req)` | Yes | POST `/v1/credentials/issue/batch` — issue 1–20 credentials. |
| `GenerateProof(ctx, req)` | Yes | POST `/v1/proof/generate` — generate a Groth16 proof. |
| `PrepareShare(ctx, req)` | Yes | POST `/v1/shares/prepare` — prepare a delegated share. |
| `IncomingShares(ctx, address)` | Yes | GET `/v1/shares/incoming/{address}` — list shares granted to an address. |
| `GetUserPubKey(ctx, address)` | Yes | GET `/v1/users/{address}/pubkey` — get on-chain public key. |
| `ResolveEmail(ctx, emailHash)` | Yes | GET `/v1/users/by-email/{emailHash}` — resolve email hash to address. |
| `SetAPIKey(key)` | — | Update the API key. Safe for concurrent use. |

---

## Crypto sub-package

`github.com/ssanjeewa/go-sdk/crypto` is fully standalone — it has no dependency on the HTTP client and can be imported separately.

```go
import zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
```

### Key management

```go
// Generate a fresh secp256k1 key pair
kp, err := zkpcrypto.GenerateKeyPair()
// kp.PrivateKey → "0x" + 64 hex chars (32 bytes, zero-padded)
// kp.PublicKey  → "0x04" + 128 hex chars (65 bytes, uncompressed)

// Derive public key from an existing private key
pubKey, err := zkpcrypto.PrivateKeyToPublicKey(privKeyHex)

// Validate a public key format
ok := zkpcrypto.IsValidPublicKey(pubKeyHex)
```

### ECIES encryption

The wire format is byte-for-byte identical to the Go middleware and Node.js SDK:
`ephPubKey(65) | IV(12) | ciphertext(64) | GCMtag(16)` = **157 bytes** = `0x` + 314 hex chars.

```go
// Encrypt (n, s) credential secrets for a recipient
encrypted, err := zkpcrypto.EncryptSecret(recipientPubKeyHex, n, s)

// Decrypt — returns the (n, s) pair
secret, err := zkpcrypto.DecryptSecret(encryptedSecretHex, privateKeyHex)
fmt.Println(secret.N, secret.S) // *big.Int values
```

### BN254 field validation

```go
// Validate a field element
ok := zkpcrypto.IsValidFieldElement(v) // v must be non-nil, ≥ 0, < BN254ScalarField

// Parse a decimal string into a field element
v, err := zkpcrypto.ParseFieldElement("42") // returns *ValidationError on bad input
```

---

## Error handling

All methods return typed errors. Use `errors.As` to inspect the specific type:

```go
resp, err := client.IssueCredential(ctx, req)
if err != nil {
    var authErr       *zkp.AuthError
    var rateLimitErr  *zkp.RateLimitError
    var notFoundErr   *zkp.NotFoundError
    var treeFullErr   *zkp.TreeFullError
    var networkErr    *zkp.NetworkError
    var validationErr *zkp.ValidationError
    var serverErr     *zkp.ServerError

    switch {
    case errors.As(err, &authErr):
        fmt.Println("invalid or missing API key")

    case errors.As(err, &rateLimitErr):
        fmt.Printf("rate limited — retry after %dms\n", rateLimitErr.RetryAfterMs)

    case errors.As(err, &notFoundErr):
        fmt.Println("file not registered on-chain")

    case errors.As(err, &treeFullErr):
        fmt.Println("user Merkle tree is full — wallet rotation required")

    case errors.As(err, &networkErr):
        fmt.Printf("transport error: %v\n", errors.Unwrap(networkErr))

    case errors.As(err, &validationErr):
        fmt.Printf("bad input: %v\n", validationErr)

    case errors.As(err, &serverErr):
        fmt.Printf("server error %d\n", serverErr.StatusCode)

    default:
        fmt.Printf("unexpected error: %v\n", err)
    }
}
```

All error types implement the `error` interface and format as `[ERROR_CODE] message`.

| Type | Code | HTTP status |
|---|---|---|
| `ValidationError` | `VALIDATION_ERROR` | — (client-side) |
| `AuthError` | `AUTH_ERROR` | 401 |
| `NotFoundError` | `NOT_FOUND_ERROR` | 404 |
| `TreeFullError` | `TREE_FULL` | 409 |
| `RateLimitError` | `RATE_LIMIT_ERROR` | 429 |
| `ServerError` | `SERVER_ERROR` | 5xx |
| `NetworkError` | `NETWORK_ERROR` | — (transport) |
| `APIError` | `API_ERROR` | other 4xx |

---

## Configuration

Pass `ClientOption` functions to `NewClient`:

| Option | Default | Description |
|---|---|---|
| `WithAPIKey(key string)` | `""` | Bearer token for authentication. Required for all endpoints except `Health` and `Metrics`. |
| `WithTimeout(d time.Duration)` | `30s` | Per-attempt HTTP request timeout. |
| `WithMaxRetries(n int)` | `3` | Maximum retry attempts on `5xx`, `429`, or transport errors. Set to `0` to disable retries. |
| `WithRetryDelay(d time.Duration)` | `200ms` | Base delay for exponential backoff between retries. |

```go
client, err := zkp.NewClient("https://middleware.example.com",
    zkp.WithAPIKey(os.Getenv("ZKP_API_KEY")),
    zkp.WithTimeout(45*time.Second),
    zkp.WithMaxRetries(5),
    zkp.WithRetryDelay(500*time.Millisecond),
)
```

**Retry behaviour**: backoff = `min(retryDelay × 2^attempt, 30s) ± 10% jitter`.
For `429 Too Many Requests`, the `Retry-After` header is honoured when longer than the computed backoff.

---

## Examples

Runnable examples are in the [`examples/`](examples/) directory.

| Example | Description |
|---|---|
| [`examples/issue_credential/`](examples/issue_credential/) | Health check → key pair → issue credential → print InsertCalldata |
| [`examples/generate_proof/`](examples/generate_proof/) | Decrypt ClaimFile secrets → generate proof → print executeRequest Calldata |
| [`examples/share_file/`](examples/share_file/) | Fetch grantee pubkey → re-encrypt secrets → prepare share → print calldatas |

Run with:

```bash
# Start the middleware first (from zkp-middleware/)
make run

# Issue a credential
ZKP_API_KEY=dev-key-1 \
ZKP_ADDRESS=0xYourAddress \
ZKP_FILE_ID=0xYourFileID \
go run ./examples/issue_credential/

# Generate a proof (using the ClaimFile from above)
ZKP_API_KEY=dev-key-1 \
ZKP_PRIVKEY=0xYourPrivateKey \
ZKP_ADDRESS=0xYourAddress \
ZKP_FILE_ID=0xYourFileID \
ZKP_LEAF_INDEX=0 \
ZKP_ENCRYPTED_SECRET=0x... \
go run ./examples/generate_proof/
```

---

## Compatibility

| Component | Version |
|---|---|
| Go | 1.22+ |
| ZKP middleware | v1.x (Arbitrum Sepolia, depth-24 circuit) |
| Node.js SDK (`@zkp-system/node-sdk`) | v2.1.0 |
| ECIES wire format | `ephPubKey(65) \| IV(12) \| ciphertext(64) \| GCMtag(16)` = 157 bytes |
| BN254 scalar field | `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| Chain | Arbitrum Sepolia (chainId 421614) |

The ECIES implementation is byte-for-byte wire-compatible with the Go middleware and the Node.js SDK — credentials encrypted by any SDK can be decrypted by any other.

---

## Security notes

- **Private keys**: never logged or included in error messages. Limit the lifetime of `*DecryptedSecret` values and never serialize or log them.
- **API keys**: never included in error messages or logs (the `Authorization` header is stripped before any error is constructed).
- **Concurrency**: `ZKPClient` is safe for concurrent use. `SetAPIKey` uses atomic operations; in-flight requests are unaffected.
- **Field validation**: `n` and `s` are validated against the BN254 scalar field before any HTTP call to avoid wasted round-trips.

---

## License

MIT
