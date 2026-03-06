// complete_flow_4337 demonstrates the full ZKP credential lifecycle using
// ERC-4337 (Alchemy LightAccount + paymaster) for gas-sponsored on-chain submission.
//
// Flow:
//
//  1. Issue credential (SDK)          → ClaimFile + InsertCalldata
//  2. Build + submit UserOperation    → batchInsertLeaves via Light Account
//  3. Wait for UserOp transaction     → confirmed on-chain
//  4. Decrypt (n, s) from ClaimFile   (SDK crypto)
//  5. Generate Groth16 proof          (SDK)
//  6. Submit executeRequest UserOp    → ZKClaimServiceV3/V4 via Light Account
//
// Prerequisites:
//   - go get github.com/ethereum/go-ethereum
//   - Light Account address must be set as sponsor on ZKClaimRegistryV3:
//       cast send <REGISTRY> "setSponsor(address)" <LIGHT_ACCOUNT_ADDR> \
//         --private-key $OWNER_KEY --rpc-url $ZKP_RPC_URL
//
// Usage:
//
//	ZKP_API_KEY=dev-key-1 \
//	ZKP_PRIVKEY=0x<64-hex-signer-key> \
//	ZKP_ADDRESS=0x<light-account-address> \
//	ZKP_FILE_ID=0x<bytes32> \
//	ZKP_RPC_URL=https://arb-sepolia.g.alchemy.com/v2/<alchemy-api-key> \
//	ALCHEMY_API_KEY=<alchemy-api-key> \
//	ALCHEMY_POLICY_ID=<gas-policy-id> \
//	go run ./examples/complete_flow_4337/
//
// Environment variables:
//
//	ZKP_BASE_URL       Middleware base URL                    (default: http://localhost:3002)
//	ZKP_API_KEY        Bearer token                           (required)
//	ZKP_PRIVKEY        Signer EOA private key, 0x-prefixed    (required)
//	ZKP_ADDRESS        Light Account address, 0x-prefixed     (required)
//	ZKP_FILE_ID        0x-prefixed bytes32 file ID            (required)
//	ZKP_RPC_URL        Arbitrum Sepolia JSON-RPC              (required)
//	ALCHEMY_API_KEY    Alchemy API key for bundler + paymaster (required)
//	ALCHEMY_POLICY_ID  Alchemy gas sponsorship policy ID      (required)
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	zkp "github.com/ssanjeewa/go-sdk"
	zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"
)

// EntryPoint v0.6 — same address on all EVM chains.
const entryPointAddr = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

func main() {
	baseURL      := envOr("ZKP_BASE_URL", "http://localhost:3002")
	apiKey       := mustEnv("ZKP_API_KEY")
	privKeyHex   := mustEnv("ZKP_PRIVKEY")
	lightAccount := mustEnv("ZKP_ADDRESS") // Light Account address — msg.sender in contracts
	fileID       := mustEnv("ZKP_FILE_ID")
	rpcURL       := mustEnv("ZKP_RPC_URL")
	alchemyKey   := mustEnv("ALCHEMY_API_KEY")
	policyID     := mustEnv("ALCHEMY_POLICY_ID")

	bundlerURL := "https://arb-sepolia.g.alchemy.com/v2/" + alchemyKey

	ctx := context.Background()

	// ── 1. Build SDK client ──────────────────────────────────────────────────
	zkpClient, err := zkp.NewClient(baseURL,
		zkp.WithAPIKey(apiKey),
		zkp.WithTimeout(60*time.Second),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	ethClient, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		log.Fatalf("ethclient.Dial: %v", err)
	}
	defer ethClient.Close()

	// ── 2. Derive signer from private key ────────────────────────────────────
	privKey, err := crypto.HexToECDSA(strings.TrimPrefix(privKeyHex, "0x"))
	if err != nil {
		log.Fatalf("parse private key: %v", err)
	}
	pubKey, err := zkpcrypto.PrivateKeyToPublicKey(privKeyHex)
	if err != nil {
		log.Fatalf("PrivateKeyToPublicKey: %v", err)
	}
	fmt.Printf("Light Account: %s\n\n", lightAccount)

	// ── 3. Issue credential ──────────────────────────────────────────────────
	fmt.Println("Step 1/5 — Issuing credential…")
	issueResp, err := zkpClient.IssueCredential(ctx, &zkp.IssueCredentialRequest{
		UserAddress:   lightAccount,
		FileID:        fileID,
		UserPublicKey: pubKey,
	})
	if err != nil {
		log.Fatalf("IssueCredential: %v", err)
	}
	claimFile := issueResp.ClaimFile
	fmt.Printf("  ✓ leafIndex=%d  commitment=%s\n", claimFile.LeafIndex, claimFile.Commitment)

	// ── 4. Submit InsertCalldata via ERC-4337 UserOp ─────────────────────────
	// insertCalldata.to   = ZKClaimRegistryV3
	// insertCalldata.data = batchInsertLeaves(lightAccount, [commitment])
	fmt.Println("\nStep 2/5 — Submitting batchInsertLeaves UserOp…")
	insertTxHash, err := sendUserOp(ctx, ethClient, bundlerURL, policyID,
		privKey, lightAccount, issueResp.InsertCalldata)
	if err != nil {
		log.Fatalf("sendUserOp (insert): %v", err)
	}
	fmt.Printf("  ✓ UserOp tx: %s\n", insertTxHash)

	// ── 5. Wait for confirmation ─────────────────────────────────────────────
	fmt.Println("\nStep 3/5 — Waiting for confirmation…")
	if err := waitForTx(ctx, ethClient, insertTxHash); err != nil {
		log.Fatalf("waitForTx: %v", err)
	}
	fmt.Println("  ✓ Confirmed")

	// Allow middleware TreeIndexer to process the LeafInserted event.
	time.Sleep(2 * time.Second)

	// ── 6. Decrypt (n, s) from ClaimFile ────────────────────────────────────
	fmt.Println("\nStep 4/5 — Decrypting credential secrets…")
	secret, err := zkpcrypto.DecryptSecret(claimFile.EncryptedSecret, privKeyHex)
	if err != nil {
		log.Fatalf("DecryptSecret: %v", err)
	}
	fmt.Printf("  ✓ n = %s\n  ✓ s = %s\n", secret.N.String(), secret.S.String())

	// ── 7. Generate Groth16 proof ────────────────────────────────────────────
	fmt.Printf("\nStep 5/5 — Generating proof (leafIndex=%d)…\n", claimFile.LeafIndex)
	proofResp, err := zkpClient.GenerateProof(ctx, &zkp.GenerateProofRequest{
		UserAddress: lightAccount,
		FileID:      fileID,
		N:           secret.N.String(),
		S:           secret.S.String(),
		LeafIndex:   claimFile.LeafIndex,
	})
	if err != nil {
		log.Fatalf("GenerateProof: %v", err)
	}
	fmt.Printf("  ✓ reqId=%s  nullifier=%s\n", proofResp.ReqID, proofResp.RequestNullifier)

	// ── 8. Print executeRequest calldata ─────────────────────────────────────
	// Submit this as another UserOp via sendUserOp(proofResp.Calldata).
	fmt.Println("\n── executeRequest calldata (submit as UserOp to ZKClaimServiceV3/V4) ──")
	fmt.Printf("  to:   %s\n", proofResp.Calldata.To)
	fmt.Printf("  data: %s\n", proofResp.Calldata.Data)
}

// ── ERC-4337 helpers ─────────────────────────────────────────────────────────

// UserOperation represents an ERC-4337 v0.6 UserOperation.
type UserOperation struct {
	Sender               string `json:"sender"`
	Nonce                string `json:"nonce"`                // hex
	InitCode             string `json:"initCode"`             // "0x" when account is deployed
	CallData             string `json:"callData"`
	CallGasLimit         string `json:"callGasLimit"`         // hex
	VerificationGasLimit string `json:"verificationGasLimit"` // hex
	PreVerificationGas   string `json:"preVerificationGas"`   // hex
	MaxFeePerGas         string `json:"maxFeePerGas"`         // hex
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"` // hex
	PaymasterAndData     string `json:"paymasterAndData"`     // filled by paymaster step
	Signature            string `json:"signature"`
}

// sendUserOp builds, sponsors, signs, and submits one UserOp.
// calldata.to / calldata.data become the LightAccount.execute() call.
func sendUserOp(
	ctx context.Context,
	ethClient *ethclient.Client,
	bundlerURL, policyID string,
	signerKey *ecdsa.PrivateKey,
	lightAccountAddr string,
	calldata *zkp.Calldata,
) (string, error) {
	// 1. Get current nonce from EntryPoint.getNonce(sender, key=0)
	nonce, err := getEntryPointNonce(ctx, ethClient, lightAccountAddr)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	// 2. Encode LightAccount.execute(target, value, data)
	// ABI: execute(address,uint256,bytes) = 0xb61d27f6
	target := common.HexToAddress(calldata.To)
	callDataBytes, err := hex.DecodeString(strings.TrimPrefix(calldata.Data, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode calldata: %w", err)
	}
	executeCallData, err := encodeLightAccountExecute(target, big.NewInt(0), callDataBytes)
	if err != nil {
		return "", fmt.Errorf("encode execute: %w", err)
	}

	// 3. Get gas fees from node
	tip, baseFee, err := getGasFees(ctx, ethClient)
	if err != nil {
		return "", fmt.Errorf("get gas fees: %w", err)
	}
	maxFee := new(big.Int).Add(baseFee, tip)

	uo := &UserOperation{
		Sender:               lightAccountAddr,
		Nonce:                toHex(nonce),
		InitCode:             "0x", // account is already deployed
		CallData:             "0x" + hex.EncodeToString(executeCallData),
		CallGasLimit:         toHex(big.NewInt(150_000)), // batchInsertLeaves <100k gas
		VerificationGasLimit: toHex(big.NewInt(150_000)),
		PreVerificationGas:   toHex(big.NewInt(50_000)),
		MaxFeePerGas:         toHex(maxFee),
		MaxPriorityFeePerGas: toHex(tip),
		PaymasterAndData:     "0x",
		Signature:            "0x",
	}

	// 4. Request paymaster sponsorship from Alchemy
	uo.PaymasterAndData, err = requestPaymaster(bundlerURL, policyID, uo)
	if err != nil {
		return "", fmt.Errorf("request paymaster: %w", err)
	}

	// 5. Compute UserOpHash and sign
	uoHash, err := computeUserOpHash(uo)
	if err != nil {
		return "", fmt.Errorf("compute userop hash: %w", err)
	}
	// ERC-4337 expects a personal_sign style signature (EIP-191 prefix)
	sig, err := crypto.Sign(accounts.TextHash(uoHash[:]), signerKey)
	if err != nil {
		return "", fmt.Errorf("sign userop: %w", err)
	}
	sig[64] += 27 // adjust v for Ethereum convention
	uo.Signature = "0x" + hex.EncodeToString(sig)

	// 6. Submit to bundler
	return submitUserOp(bundlerURL, uo)
}

// getEntryPointNonce calls EntryPoint.getNonce(sender, key) via eth_call.
func getEntryPointNonce(ctx context.Context, client *ethclient.Client, sender string) (*big.Int, error) {
	// ABI: getNonce(address sender, uint192 key) returns (uint256 nonce)
	// selector = keccak256("getNonce(address,uint192)") = 0x35567e1a
	addr := common.HexToAddress(sender)
	var padded [32]byte
	copy(padded[12:], addr.Bytes())

	data := make([]byte, 4+64)
	copy(data[:4], []byte{0x35, 0x56, 0x7e, 0x1a})
	copy(data[4:36], padded[:])
	// key = 0 (already zero)

	ep := common.HexToAddress(entryPointAddr)
	result, err := client.CallContract(ctx, ethereum.CallMsg{To: &ep, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	if len(result) < 32 {
		return big.NewInt(0), nil
	}
	return new(big.Int).SetBytes(result[:32]), nil
}

// encodeLightAccountExecute ABI-encodes execute(address,uint256,bytes).
// selector: 0xb61d27f6
func encodeLightAccountExecute(target common.Address, value *big.Int, data []byte) ([]byte, error) {
	// Manual ABI encoding: selector + address + uint256 + bytes (offset + length + data)
	buf := make([]byte, 0, 4+32+32+32+32+len(data))
	buf = append(buf, 0xb6, 0x1d, 0x27, 0xf6) // selector

	// address (padded left to 32 bytes)
	var addrPad [32]byte
	copy(addrPad[12:], target.Bytes())
	buf = append(buf, addrPad[:]...)

	// uint256 value
	buf = append(buf, math.PaddedBigBytes(value, 32)...)

	// bytes offset = 96 (3 * 32)
	buf = append(buf, math.PaddedBigBytes(big.NewInt(96), 32)...)

	// bytes length
	buf = append(buf, math.PaddedBigBytes(big.NewInt(int64(len(data))), 32)...)

	// bytes data (padded to 32-byte boundary)
	buf = append(buf, data...)
	if pad := (32 - len(data)%32) % 32; pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}
	return buf, nil
}

// getGasFees returns (maxPriorityFeePerGas, baseFee) from the latest block.
func getGasFees(ctx context.Context, client *ethclient.Client) (*big.Int, *big.Int, error) {
	tip, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("tip cap: %w", err)
	}
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	baseFee := header.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(1e9) // 1 gwei fallback
	}
	return tip, baseFee, nil
}

// requestPaymaster calls alchemy_requestPaymasterAndData to get paymasterAndData.
func requestPaymaster(bundlerURL, policyID string, uo *UserOperation) (string, error) {
	type pmRequest struct {
		PolicyID   string         `json:"policyId"`
		EntryPoint string         `json:"entryPoint"`
		UserOp     *UserOperation `json:"userOperation"`
	}
	type pmResponse struct {
		Result struct {
			PaymasterAndData string `json:"paymasterAndData"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	req := rpcRequest("alchemy_requestPaymasterAndData", []any{
		pmRequest{PolicyID: policyID, EntryPoint: entryPointAddr, UserOp: uo},
	})
	var resp pmResponse
	if err := postJSON(bundlerURL, req, &resp); err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("paymaster error: %s", resp.Error.Message)
	}
	return resp.Result.PaymasterAndData, nil
}

// computeUserOpHash computes the ERC-4337 v0.6 userOpHash (chainId=421614).
// userOpHash = keccak256(abi.encode(keccak256(pack(uo)), entryPoint, chainId))
func computeUserOpHash(uo *UserOperation) ([32]byte, error) {
	// Pack the UserOperation fields and hash them.
	packed, err := packUserOp(uo)
	if err != nil {
		return [32]byte{}, err
	}
	innerHash := crypto.Keccak256Hash(packed)

	// Outer hash: keccak256(innerHash ‖ entryPoint ‖ chainId)
	ep := common.HexToAddress(entryPointAddr)
	chainID := big.NewInt(421614) // Arbitrum Sepolia

	var outer []byte
	outer = append(outer, innerHash.Bytes()...)
	var epPad [32]byte
	copy(epPad[12:], ep.Bytes())
	outer = append(outer, epPad[:]...)
	outer = append(outer, math.PaddedBigBytes(chainID, 32)...)

	return crypto.Keccak256Hash(outer), nil
}

// packUserOp ABI-encodes the hashable fields of a UserOperation for v0.6.
func packUserOp(uo *UserOperation) ([]byte, error) {
	decode := func(s string) ([]byte, error) {
		return hex.DecodeString(strings.TrimPrefix(s, "0x"))
	}
	hexToBig := func(s string) *big.Int {
		b, _ := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
		return b
	}

	callData, _ := decode(uo.CallData)
	initCode, _ := decode(uo.InitCode)
	pmData, _ := decode(uo.PaymasterAndData)

	var buf []byte
	addr := common.HexToAddress(uo.Sender)
	var addrPad [32]byte
	copy(addrPad[12:], addr.Bytes())
	buf = append(buf, addrPad[:]...)
	buf = append(buf, math.PaddedBigBytes(hexToBig(uo.Nonce), 32)...)
	buf = append(buf, crypto.Keccak256(initCode)...)
	buf = append(buf, crypto.Keccak256(callData)...)
	buf = append(buf, math.PaddedBigBytes(hexToBig(uo.CallGasLimit), 32)...)
	buf = append(buf, math.PaddedBigBytes(hexToBig(uo.VerificationGasLimit), 32)...)
	buf = append(buf, math.PaddedBigBytes(hexToBig(uo.PreVerificationGas), 32)...)
	buf = append(buf, math.PaddedBigBytes(hexToBig(uo.MaxFeePerGas), 32)...)
	buf = append(buf, math.PaddedBigBytes(hexToBig(uo.MaxPriorityFeePerGas), 32)...)
	buf = append(buf, crypto.Keccak256(pmData)...)
	return buf, nil
}

// submitUserOp submits via eth_sendUserOperation and returns the tx hash.
func submitUserOp(bundlerURL string, uo *UserOperation) (string, error) {
	type sendResult struct {
		Result string `json:"result"` // userOpHash
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	req := rpcRequest("eth_sendUserOperation", []any{uo, entryPointAddr})
	var resp sendResult
	if err := postJSON(bundlerURL, req, &resp); err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("bundler error: %s", resp.Error.Message)
	}

	// Poll eth_getUserOperationReceipt to get the actual tx hash.
	return waitForUserOpReceipt(bundlerURL, resp.Result)
}

// waitForUserOpReceipt polls eth_getUserOperationReceipt until a tx hash is returned.
func waitForUserOpReceipt(bundlerURL, userOpHash string) (string, error) {
	type receiptResult struct {
		Result *struct {
			Receipt struct {
				TransactionHash string `json:"transactionHash"`
			} `json:"receipt"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}

	for i := 0; i < 60; i++ { // ~30s timeout
		req := rpcRequest("eth_getUserOperationReceipt", []any{userOpHash})
		var resp receiptResult
		if err := postJSON(bundlerURL, req, &resp); err != nil {
			return "", err
		}
		if resp.Error != nil {
			return "", fmt.Errorf("receipt error: %s", resp.Error.Message)
		}
		if resp.Result != nil {
			return resp.Result.Receipt.TransactionHash, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("UserOp not mined within 30s: %s", userOpHash)
}

// waitForTx polls TransactionReceipt until confirmed.
func waitForTx(ctx context.Context, client *ethclient.Client, txHashHex string) error {
	hash := common.HexToHash(txHashHex)
	for {
		receipt, err := client.TransactionReceipt(ctx, hash)
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

// ── JSON-RPC helpers ─────────────────────────────────────────────────────────

func rpcRequest(method string, params []any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
}

func postJSON(url string, body, dst any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(dst)
}

func toHex(n *big.Int) string {
	return "0x" + fmt.Sprintf("%x", n)
}

// ── Env helpers ──────────────────────────────────────────────────────────────

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
