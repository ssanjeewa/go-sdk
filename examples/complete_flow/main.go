// complete_flow demonstrates the full ZKP credential lifecycle:
//
//  1. Issue credential    → ClaimFile + InsertCalldata (off-chain, SDK)
//  2. Submit InsertCalldata on-chain via batchInsertLeaves (ZKClaimRegistryV3)
//  3. Wait for transaction confirmation (~0.25s block time on Arbitrum Sepolia)
//  4. Decrypt (n, s) from ClaimFile.EncryptedSecret
//  5. Generate Groth16 proof  (off-chain, SDK)
//  6. Print executeRequest calldata ready for on-chain submission
//
// This example uses go-ethereum directly for on-chain steps.
// Add it to your module: go get github.com/ethereum/go-ethereum
//
// Usage:
//
//	ZKP_API_KEY=dev-key-1 \
//	ZKP_PRIVKEY=0x<64-hex> \
//	ZKP_ADDRESS=0x<address> \
//	ZKP_FILE_ID=0x<bytes32> \
//	ZKP_RPC_URL=https://sepolia-rollup.arbitrum.io/rpc \
//	go run ./examples/complete_flow/
//
// Environment variables:
//
//	ZKP_BASE_URL  Middleware base URL                     (default: http://localhost:3002)
//	ZKP_API_KEY   Bearer token                            (required)
//	ZKP_PRIVKEY   secp256k1 private key, 0x-prefixed hex  (required — used for ECIES decrypt AND tx signing)
//	ZKP_ADDRESS   Light Account / wallet address           (required)
//	ZKP_FILE_ID   0x-prefixed bytes32 file ID             (required)
//	ZKP_RPC_URL   Arbitrum Sepolia JSON-RPC endpoint       (required)
package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	zkp "github.com/ssanjeewa/go-sdk"
	zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

func main() {
	baseURL := envOr("ZKP_BASE_URL", "http://localhost:3002")
	apiKey := mustEnv("ZKP_API_KEY")
	privKeyHex := mustEnv("ZKP_PRIVKEY")
	userAddress := mustEnv("ZKP_ADDRESS")
	fileID := mustEnv("ZKP_FILE_ID")
	rpcURL := mustEnv("ZKP_RPC_URL")

	ctx := context.Background()

	// ── 1. Build SDK client ──────────────────────────────────────────────────
	client, err := zkp.NewClient(baseURL,
		zkp.WithAPIKey(apiKey),
		zkp.WithTimeout(60*time.Second),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	// ── 2. Derive key pair from private key ──────────────────────────────────
	pubKey, err := zkpcrypto.PrivateKeyToPublicKey(privKeyHex)
	if err != nil {
		log.Fatalf("PrivateKeyToPublicKey: %v", err)
	}
	fmt.Printf("Address:    %s\n", userAddress)
	fmt.Printf("Public key: %s\n\n", pubKey)

	// ── 3. Issue credential ──────────────────────────────────────────────────
	fmt.Println("Step 1/5 — Issuing credential…")
	issueResp, err := client.IssueCredential(ctx, &zkp.IssueCredentialRequest{
		UserAddress:   userAddress,
		FileID:        fileID,
		UserPublicKey: pubKey,
	})
	if err != nil {
		log.Fatalf("IssueCredential: %v", err)
	}
	claimFile := issueResp.ClaimFile
	fmt.Printf("  ✓ Credential issued  leafIndex=%d  commitment=%s\n",
		claimFile.LeafIndex, claimFile.Commitment)

	// ── 4. Connect to chain ──────────────────────────────────────────────────
	ethClient, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		log.Fatalf("ethclient.Dial: %v", err)
	}
	defer ethClient.Close()

	chainID, err := ethClient.ChainID(ctx)
	if err != nil {
		log.Fatalf("ChainID: %v", err)
	}
	fmt.Printf("  Chain ID: %d\n\n", chainID)

	// ── 5. Submit InsertCalldata on-chain ────────────────────────────────────
	// insertCalldata encodes batchInsertLeaves(userAddress, [commitment])
	// on ZKClaimRegistryV3 (0x9019c0fbCaC853dA04d48CF6049a52b4812C7f28).
	// The signer must be the owner or sponsor — see CLAUDE.md access control.
	fmt.Println("Step 2/5 — Submitting batchInsertLeaves on-chain…")
	txHash, err := submitCalldata(ctx, ethClient, chainID, privKeyHex, issueResp.InsertCalldata)
	if err != nil {
		log.Fatalf("submitCalldata (insertLeaves): %v", err)
	}
	fmt.Printf("  ✓ Tx submitted: %s\n", txHash)

	// ── 6. Wait for confirmation ─────────────────────────────────────────────
	fmt.Println("Step 3/5 — Waiting for tx confirmation…")
	receipt, err := waitMined(ctx, ethClient, txHash)
	if err != nil {
		log.Fatalf("waitMined: %v", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		log.Fatalf("tx %s reverted (status=%d)", txHash, receipt.Status)
	}
	fmt.Printf("  ✓ Confirmed at block %d\n\n", receipt.BlockNumber)

	// Brief pause so the middleware's TreeIndexer can process the LeafInserted
	// event. On Arbitrum Sepolia (~0.25s blocks) one poll cycle is enough.
	// Remove this if you poll the middleware health endpoint instead.
	time.Sleep(2 * time.Second)

	// ── 7. Decrypt (n, s) from ClaimFile ────────────────────────────────────
	fmt.Println("Step 4/5 — Decrypting credential secrets…")
	secret, err := zkpcrypto.DecryptSecret(claimFile.EncryptedSecret, privKeyHex)
	if err != nil {
		log.Fatalf("DecryptSecret: %v", err)
	}
	fmt.Printf("  ✓ n = %s\n  ✓ s = %s\n\n", secret.N.String(), secret.S.String())

	// ── 8. Generate Groth16 proof ────────────────────────────────────────────
	fmt.Printf("Step 5/5 — Generating proof for leafIndex=%d…\n", claimFile.LeafIndex)
	proofResp, err := client.GenerateProof(ctx, &zkp.GenerateProofRequest{
		UserAddress: userAddress,
		FileID:      fileID,
		N:           secret.N.String(),
		S:           secret.S.String(),
		LeafIndex:   claimFile.LeafIndex,
	})
	if err != nil {
		log.Fatalf("GenerateProof: %v", err)
	}
	fmt.Printf("  ✓ Proof generated  reqId=%s  nullifier=%s\n\n",
		proofResp.ReqID, proofResp.RequestNullifier)

	// ── 9. Print executeRequest calldata ─────────────────────────────────────
	fmt.Println("── executeRequest calldata (submit to ZKClaimServiceV3/V4) ──")
	fmt.Printf("  to:   %s\n", proofResp.Calldata.To)
	fmt.Printf("  data: %s\n", proofResp.Calldata.Data)
}

// submitCalldata signs and sends a raw EVM transaction from calldata.
// privKeyHex is a 0x-prefixed 32-byte hex secp256k1 private key.
func submitCalldata(
	ctx context.Context,
	client *ethclient.Client,
	chainID *big.Int,
	privKeyHex string,
	calldata *zkp.Calldata,
) (string, error) {
	privKey, err := crypto.HexToECDSA(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}

	sender := crypto.PubkeyToAddress(privKey.PublicKey.(ecdsa.PublicKey))

	toAddr := common.HexToAddress(calldata.To)
	data, err := hex.DecodeString(strings.TrimPrefix(calldata.Data, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode calldata hex: %w", err)
	}

	nonce, err := client.PendingNonceAt(ctx, sender)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	// Estimate gas — batchInsertLeaves costs <100k gas on Arbitrum Sepolia.
	gasLimit, err := client.EstimateGas(ctx, ethereum.CallMsg{
		From: sender,
		To:   &toAddr,
		Data: data,
	})
	if err != nil {
		return "", fmt.Errorf("estimate gas: %w", err)
	}
	gasLimit = gasLimit * 12 / 10 // +20% buffer

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("suggest gas price: %w", err)
	}

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		To:       &toAddr,
		Value:    big.NewInt(0),
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})

	signer := types.NewLondonSigner(chainID)
	signed, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		return "", fmt.Errorf("sign tx: %w", err)
	}

	if err := client.SendTransaction(ctx, signed); err != nil {
		return "", fmt.Errorf("send tx: %w", err)
	}

	return signed.Hash().Hex(), nil
}

// waitMined polls for a transaction receipt until it is confirmed or ctx expires.
func waitMined(ctx context.Context, client *ethclient.Client, txHashHex string) (*types.Receipt, error) {
	hash := common.HexToHash(txHashHex)
	for {
		receipt, err := client.TransactionReceipt(ctx, hash)
		if err == nil {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
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
