# Go SDK — Custom Backend Integration Guide

How to add ZKP file access control to an existing Go HTTP backend.
The ZKP middleware is already running — you only need to call it via the SDK.

---

## What the SDK does for you

```
Your Backend                   Go SDK                      ZKP Middleware (running)
─────────────────────────────────────────────────────────────────────────────────
POST /files/:id/grant   ──►  IssueCredential()     ──►  POST /v1/credentials/issue
                              returns: ClaimFile          returns: (n, s, commitment,
                                       InsertCalldata               leafIndex, insertCalldata)
                         ──►  submit InsertCalldata ──►  ZKClaimRegistryV3.batchInsertLeaves()
                              (you sign + send this)       (on Arbitrum Sepolia)

POST /files/:id/access  ──►  GenerateProof()        ──►  POST /v1/proof/generate
                              returns: ProofCalldata       returns: Groth16 proof
                         ──►  submit ProofCalldata   ──►  ZKClaimServiceV3.executeRequest()
                              (you sign + send this)       (verifies proof, emits KeyReleased)
```

Your backend is responsible for two things the SDK cannot do:
1. Storing the `ClaimFile` per user per file (you need it to generate proofs later)
2. Signing and submitting the two calldatas on-chain

---

## 1. Module setup

```bash
# In your Go module root
go get github.com/ssanjeewa/go-sdk@latest
go get github.com/ethereum/go-ethereum@latest
go mod tidy
```

---

## 2. Client initialization

Create a single `zkp.ZKPClient` at startup and reuse it — it is safe for concurrent use.

```go
package main

import (
    "log"
    "time"

    zkp "github.com/ssanjeewa/go-sdk"
)

var zkpClient *zkp.ZKPClient

func initZKP() {
    var err error
    zkpClient, err = zkp.NewClient(
        "https://mdw.bethel.network",   // your middleware URL
        zkp.WithAPIKey("your-api-key"), // from admin dashboard → API Keys
        zkp.WithTimeout(60*time.Second),
    )
    if err != nil {
        log.Fatalf("zkp client: %v", err)
    }
}
```

---

## 3. What you need to store

Before integrating, decide where you store two things per (user, file) pair:

| Data | What it is | Where to store |
|---|---|---|
| `ClaimFile` | leafIndex + encryptedSecret + commitment | Your DB (safe to store — already encrypted) |
| ECIES keypair | secp256k1 keypair for encrypting/decrypting secrets | Private key in Vault/KMS; public key in DB |

The simplest approach: **one keypair per user**, generated once.

```go
import zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"

// Generate once per user, store privately
kp, err := zkpcrypto.GenerateKeyPair()
// kp.PrivateKey → store encrypted in your secret manager
// kp.PublicKey  → store in your users table
```

---

## 4. Operation 1 — Grant access (issue + insert)

Call this **after** the file is already registered on-chain via `createFile`.

```go
import (
    "context"
    "encoding/json"

    zkp "github.com/ssanjeewa/go-sdk"
)

// GrantFileAccess issues a ZKP credential for userAddress on fileID,
// inserts the Merkle leaf on-chain, and stores the ClaimFile.
func GrantFileAccess(ctx context.Context, userAddress, fileID, userPublicKey string) error {

    // ── Step 1: Issue credential via SDK ────────────────────────────────────
    resp, err := zkpClient.IssueCredential(ctx, &zkp.IssueCredentialRequest{
        UserAddress:   userAddress,   // user's wallet / Light Account address
        FileID:        fileID,        // 0x-prefixed bytes32
        UserPublicKey: userPublicKey, // user's ECIES public key (0x04-prefixed, 65 bytes)
    })
    if err != nil {
        return fmt.Errorf("issue credential: %w", err)
    }

    // resp.ClaimFile      → store this — needed later to generate proofs
    // resp.InsertCalldata → submit this on-chain (next step)

    // ── Step 2: Submit InsertCalldata on-chain ───────────────────────────────
    // resp.InsertCalldata is the encoded batchInsertLeaves() call for ZKClaimRegistryV3.
    // Your signer must be set as sponsor via setSponsor() — see Prerequisites.
    txHash, err := submitOnChain(ctx, resp.InsertCalldata)
    if err != nil {
        return fmt.Errorf("insert on-chain: %w", err)
    }

    // ── Step 3: Wait for confirmation ────────────────────────────────────────
    if err := waitForTx(ctx, txHash); err != nil {
        return fmt.Errorf("tx failed: %w", err)
    }

    // ── Step 4: Store ClaimFile in your DB ───────────────────────────────────
    // The ClaimFile contains leafIndex + encryptedSecret + commitment.
    // encryptedSecret is already ECIES-encrypted — safe to store as-is.
    claimJSON, _ := json.Marshal(resp.ClaimFile)
    return saveClaimFile(ctx, userAddress, fileID, claimJSON)
}
```

---

## 5. Operation 2 — Access file (generate proof + execute)

Call this when a user requests access to a file they were previously granted.

```go
import (
    "context"
    "encoding/json"

    zkp     "github.com/ssanjeewa/go-sdk"
    zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

// AccessFile generates a ZKP proof for userAddress on fileID and submits
// the executeRequest call on-chain. Returns the tx hash.
func AccessFile(ctx context.Context, userAddress, fileID, userPrivateKey string) (string, error) {

    // ── Step 1: Load ClaimFile from your DB ──────────────────────────────────
    claimJSON, err := loadClaimFile(ctx, userAddress, fileID)
    if err != nil {
        return "", fmt.Errorf("no credential found: %w", err)
    }
    var claimFile zkp.ClaimFile
    json.Unmarshal(claimJSON, &claimFile)

    // ── Step 2: Decrypt (n, s) from ClaimFile ───────────────────────────────
    // userPrivateKey is the ECIES private key — load from your secret manager.
    // It NEVER leaves your backend.
    secret, err := zkpcrypto.DecryptSecret(claimFile.EncryptedSecret, userPrivateKey)
    if err != nil {
        return "", fmt.Errorf("decrypt secret: %w", err)
    }

    // ── Step 3: Generate proof via SDK ──────────────────────────────────────
    proofResp, err := zkpClient.GenerateProof(ctx, &zkp.GenerateProofRequest{
        UserAddress: userAddress,
        FileID:      fileID,
        N:           secret.N.String(), // never log these values
        S:           secret.S.String(),
        LeafIndex:   claimFile.LeafIndex,
    })
    if err != nil {
        return "", fmt.Errorf("generate proof: %w", err)
    }

    // proofResp.Calldata → encoded executeRequest() call for ZKClaimServiceV3
    // proofResp.RequestNullifier → store/log this for audit trail (safe — public)
    // proofResp.ReqID → the request counter used in this proof

    // ── Step 4: Submit executeRequest on-chain ──────────────────────────────
    txHash, err := submitOnChain(ctx, proofResp.Calldata)
    if err != nil {
        return "", fmt.Errorf("execute on-chain: %w", err)
    }

    // ── Step 5: Wait for confirmation ───────────────────────────────────────
    // The contract emits KeyReleased event — your system listens for this
    // to deliver the decrypted file to the user.
    if err := waitForTx(ctx, txHash); err != nil {
        return "", fmt.Errorf("tx failed: %w", err)
    }

    return txHash, nil
}
```

---

## 6. On-chain submission helpers

Add these to your project. They use `go-ethereum` to sign and send transactions.

```go
import (
    "context"
    "encoding/hex"
    "fmt"
    "math/big"
    "strings"
    "time"

    "github.com/ethereum/go-ethereum"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"

    zkp "github.com/ssanjeewa/go-sdk"
)

var (
    ethClient  *ethclient.Client
    signerKey  *ecdsa.PrivateKey
    chainID    *big.Int
)

func initChain(rpcURL, privateKeyHex string) error {
    var err error

    ethClient, err = ethclient.Dial(rpcURL)
    if err != nil {
        return fmt.Errorf("dial: %w", err)
    }

    chainID, err = ethClient.ChainID(context.Background())
    if err != nil {
        return fmt.Errorf("chainID: %w", err)
    }

    signerKey, err = crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
    if err != nil {
        return fmt.Errorf("parse key: %w", err)
    }

    return nil
}

// submitOnChain signs and sends a raw EVM transaction from SDK calldata.
// Returns the tx hash. The signer must have insertion rights (sponsor role).
func submitOnChain(ctx context.Context, calldata *zkp.Calldata) (string, error) {
    sender := crypto.PubkeyToAddress(signerKey.PublicKey)
    to     := common.HexToAddress(calldata.To)
    data, err := hex.DecodeString(strings.TrimPrefix(calldata.Data, "0x"))
    if err != nil {
        return "", fmt.Errorf("decode calldata: %w", err)
    }

    nonce, err := ethClient.PendingNonceAt(ctx, sender)
    if err != nil {
        return "", fmt.Errorf("nonce: %w", err)
    }

    gas, err := ethClient.EstimateGas(ctx, ethereum.CallMsg{From: sender, To: &to, Data: data})
    if err != nil {
        return "", fmt.Errorf("estimate gas: %w", err)
    }

    gasPrice, err := ethClient.SuggestGasPrice(ctx)
    if err != nil {
        return "", fmt.Errorf("gas price: %w", err)
    }

    tx := types.NewTx(&types.LegacyTx{
        Nonce:    nonce,
        To:       &to,
        Value:    big.NewInt(0),
        Gas:      gas * 12 / 10, // +20% buffer
        GasPrice: gasPrice,
        Data:     data,
    })

    signed, err := types.SignTx(tx, types.NewLondonSigner(chainID), signerKey)
    if err != nil {
        return "", fmt.Errorf("sign: %w", err)
    }

    if err := ethClient.SendTransaction(ctx, signed); err != nil {
        return "", fmt.Errorf("send: %w", err)
    }

    return signed.Hash().Hex(), nil
}

// waitForTx polls until the transaction is confirmed or ctx expires.
func waitForTx(ctx context.Context, txHashHex string) error {
    hash := common.HexToHash(txHashHex)
    for {
        receipt, err := ethClient.TransactionReceipt(ctx, hash)
        if err == nil {
            if receipt.Status == 0 {
                return fmt.Errorf("tx %s reverted", txHashHex)
            }
            return nil
        }
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(500 * time.Millisecond):
        }
    }
}
```

---

## 7. Wire into your HTTP handlers

```go
package main

import (
    "encoding/json"
    "net/http"
    "os"

    "github.com/go-chi/chi/v5"
)

func main() {
    // Init SDK client
    initZKP()

    // Init chain connection (signer must be set as sponsor on ZKClaimRegistryV3)
    if err := initChain(
        os.Getenv("RPC_URL"),         // https://arb-sepolia.g.alchemy.com/v2/<key>
        os.Getenv("SIGNER_PRIVKEY"),  // 0x-prefixed hex — use secret manager in production
    ); err != nil {
        log.Fatal(err)
    }

    r := chi.NewRouter()

    // Grant a user access to a file (called after file is registered on-chain)
    r.Post("/files/{fileId}/grant", func(w http.ResponseWriter, r *http.Request) {
        fileID := chi.URLParam(r, "fileId")

        var body struct {
            UserAddress   string `json:"userAddress"`
            UserPublicKey string `json:"userPublicKey"`
        }
        json.NewDecoder(r.Body).Decode(&body)

        if err := GrantFileAccess(r.Context(), body.UserAddress, fileID, body.UserPublicKey); err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        w.WriteHeader(http.StatusOK)
    })

    // User requests access to a file — returns tx hash of executeRequest
    r.Post("/files/{fileId}/access", func(w http.ResponseWriter, r *http.Request) {
        fileID := chi.URLParam(r, "fileId")

        var body struct {
            UserAddress string `json:"userAddress"`
        }
        json.NewDecoder(r.Body).Decode(&body)

        // Load user's ECIES private key from YOUR secret manager
        privKey := loadUserPrivKey(body.UserAddress) // your implementation

        txHash, err := AccessFile(r.Context(), body.UserAddress, fileID, privKey)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        json.NewEncoder(w).Encode(map[string]string{"txHash": txHash})
    })

    http.ListenAndServe(":8080", r)
}
```

---

## 8. Prerequisites on-chain (one-time setup)

Before your system can submit `batchInsertLeaves`, your signer address must be
set as `sponsor` on `ZKClaimRegistryV3`. Ask the contract owner to run:

```bash
cast send 0x9019c0fbCaC853dA04d48CF6049a52b4812C7f28 \
  "setSponsor(address)" <YOUR_SIGNER_ADDRESS> \
  --private-key $OWNER_PRIVKEY \
  --rpc-url $RPC_URL
```

Your signer address is:
```bash
cast wallet address --private-key $SIGNER_PRIVKEY
```

---

## 9. Environment variables

```bash
# Middleware
ZKP_BASE_URL=https://mdw.bethel.network
ZKP_API_KEY=<from-admin-dashboard>

# Chain
RPC_URL=https://arb-sepolia.g.alchemy.com/v2/<alchemy-key>
SIGNER_PRIVKEY=0x<your-signer-key>   # must be set as sponsor on registry
```

---

## 10. Call sequence — what order matters

```
File upload in your system:
  1. Your app registers file on-chain → createFile() tx ✓
  2. Your app calls GrantFileAccess() → IssueCredential + batchInsertLeaves tx ✓
  3. Store ClaimFile in your DB ✓

File access in your system:
  1. Your app calls AccessFile() → GenerateProof + executeRequest tx ✓
  2. Contract emits KeyReleased event ✓
  3. Your app delivers file to user ✓

CRITICAL: step 2 (batchInsertLeaves) MUST be confirmed on-chain
before calling GenerateProof. This was the root cause of the original
500 error — the leaf was never inserted so the Merkle proof failed.
```

---

## 11. Error handling cheat sheet

| Error from SDK | Meaning | Fix |
|---|---|---|
| `*zkp.NotFoundError` | File not registered on-chain yet | Call `createFile` first |
| `*zkp.TreeFullError` | User's Merkle tree is full (16M leaves) | Rotate to new wallet |
| `*zkp.AuthError` | Wrong or missing API key | Check `ZKP_API_KEY` |
| `*zkp.ValidationError` | Bad input (address format, key format) | Check request fields |
| `generate proof: leaf index N out of range` | `batchInsertLeaves` not confirmed yet | Wait for tx + 2s |
| `generate proof: root still diverged` | Middleware restarting / resyncing | Retry after 5s |

```go
// Type-switch on SDK errors for precise handling
import "errors"
import zkp "github.com/ssanjeewa/go-sdk"

if err := zkpClient.IssueCredential(...); err != nil {
    var notFound *zkp.NotFoundError
    var treeFull *zkp.TreeFullError
    var authErr  *zkp.AuthError

    switch {
    case errors.As(err, &notFound):
        // file not registered on-chain — return 404 to your client
    case errors.As(err, &treeFull):
        // extremely rare — 16M leaves exhausted
    case errors.As(err, &authErr):
        // misconfigured API key
    default:
        // unexpected — log and return 500
    }
}
```
