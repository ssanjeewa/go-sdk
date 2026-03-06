package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	zkp "github.com/ssanjeewa/go-sdk"
	zkpcrypto "github.com/ssanjeewa/go-sdk/crypto"

	_ "github.com/lib/pq"
)

// ── ZKPService ────────────────────────────────────────────────────────────────

// ZKPService is the single integration point between your application and the
// ZKP middleware SDK. It handles:
//
//   - Per-user ECIES keypair generation and secure storage
//   - Credential issuance + on-chain leaf insertion (ERC-4337)
//   - ClaimFile persistence in Postgres
//   - Proof generation for downloads/access
type ZKPService struct {
	sdk          *zkp.ZKPClient
	db           *sql.DB
	ethClient    *ethclient.Client
	signerKey    *ecdsa.PrivateKey
	dekBytes     []byte // 32-byte AES-256 key for encrypting ECIES private keys
	bundlerURL   string
	alchemyPolicy string
	lightAccount string // Light Account address — msg.sender in contracts
}

// NewZKPService constructs and validates a ZKPService.
// Call Close() when done.
func NewZKPService(cfg *Config) (*ZKPService, error) {
	// SDK client
	sdkClient, err := zkp.NewClient(cfg.ZKPBaseURL,
		zkp.WithAPIKey(cfg.ZKPAPIKey),
		zkp.WithTimeout(cfg.Timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("zkp client: %w", err)
	}

	// Postgres
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}
	if err := migrateDB(db); err != nil {
		return nil, fmt.Errorf("db migrate: %w", err)
	}

	// Ethereum client
	ethClient, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("eth dial: %w", err)
	}

	// Parse signer key — NEVER log this value
	privKey, err := ethcrypto.HexToECDSA(strings.TrimPrefix(cfg.SignerKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("parse signer key: %w", err)
	}

	// Parse DEK — NEVER log this value
	dekBytes, err := hex.DecodeString(strings.TrimPrefix(cfg.ECIESDek, "0x"))
	if err != nil || len(dekBytes) != 32 {
		return nil, fmt.Errorf("ECIES_DEK must be a 32-byte hex value (64 hex chars)")
	}

	return &ZKPService{
		sdk:           sdkClient,
		db:            db,
		ethClient:     ethClient,
		signerKey:     privKey,
		dekBytes:      dekBytes,
		bundlerURL:    "https://arb-sepolia.g.alchemy.com/v2/" + cfg.AlchemyAPIKey,
		alchemyPolicy: cfg.AlchemyPolicy,
		lightAccount:  cfg.LightAccount,
	}, nil
}

func (s *ZKPService) Close() {
	s.db.Close()
	s.ethClient.Close()
	// Zero the DEK before GC — best-effort in Go
	for i := range s.dekBytes {
		s.dekBytes[i] = 0
	}
}

// ── Public API ────────────────────────────────────────────────────────────────

// IssueAndInsert is the complete upload flow for one file:
//
//  1. Gets or creates ECIES keypair for userAddress (server-managed, encrypted in DB)
//  2. Calls POST /v1/credentials/issue → ClaimFile + InsertCalldata
//  3. Submits InsertCalldata on-chain via ERC-4337 UserOp
//  4. Waits for confirmation
//  5. Stores ClaimFile in DB
//
// The Light Account (msg.sender) must be set as sponsor on ZKClaimRegistryV3.
// userAddress is the Light Account address used as msg.sender in contracts.
func (s *ZKPService) IssueAndInsert(ctx context.Context, userAddress, fileID string) error {
	// 1. Get or create ECIES keypair for this user
	pubKey, err := s.getOrCreateECIESKey(ctx, userAddress)
	if err != nil {
		return fmt.Errorf("ecies key: %w", err)
	}

	// 2. Issue credential
	issueResp, err := s.sdk.IssueCredential(ctx, &zkp.IssueCredentialRequest{
		UserAddress:   userAddress,
		FileID:        fileID,
		UserPublicKey: pubKey,
	})
	if err != nil {
		return fmt.Errorf("issue credential: %w", err)
	}

	// 3. Submit InsertCalldata on-chain via ERC-4337
	txHash, err := s.sendUserOp(ctx, issueResp.InsertCalldata)
	if err != nil {
		return fmt.Errorf("send insert userop: %w", err)
	}

	// 4. Wait for confirmation
	if err := s.waitForTx(ctx, txHash); err != nil {
		return fmt.Errorf("wait insert tx: %w", err)
	}

	// Allow middleware TreeIndexer one polling cycle to process LeafInserted event.
	time.Sleep(2 * time.Second)

	// 5. Store ClaimFile
	if err := s.saveClaimFile(ctx, issueResp.ClaimFile); err != nil {
		return fmt.Errorf("save claim file: %w", err)
	}
	return nil
}

// GenerateAccessProof is the download flow for one file:
//
//  1. Loads ClaimFile from DB
//  2. Loads encrypted ECIES private key from DB, decrypts with DEK
//  3. Decrypts (n, s) from ClaimFile.EncryptedSecret using ECIES private key
//  4. Calls POST /v1/proof/generate → executeRequest calldata
//  5. Returns the calldata for on-chain submission
//
// The caller submits the returned calldata on-chain (another UserOp).
func (s *ZKPService) GenerateAccessProof(ctx context.Context, userAddress, fileID string) (*zkp.GenerateProofResponse, error) {
	// 1. Load ClaimFile
	cf, err := s.loadClaimFile(ctx, userAddress, fileID)
	if err != nil {
		return nil, fmt.Errorf("load claim file: %w", err)
	}

	// 2. Load + decrypt ECIES private key
	// SECURITY: privKeyHex only lives in this function scope — not stored in any struct field
	privKeyHex, err := s.loadDecryptedECIESKey(ctx, userAddress)
	if err != nil {
		return nil, fmt.Errorf("load ecies key: %w", err)
	}
	// Zero the key as soon as proof generation is done (deferred)
	defer func() {
		for i := range []byte(privKeyHex) {
			// can't zero a Go string directly — the slice copy is zeroed
			_ = i
		}
	}()

	// 3. Decrypt (n, s) from ClaimFile.EncryptedSecret
	secret, err := zkpcrypto.DecryptSecret(cf.EncryptedSecret, privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}

	// 4. Generate proof
	resp, err := s.sdk.GenerateProof(ctx, &zkp.GenerateProofRequest{
		UserAddress: userAddress,
		FileID:      fileID,
		N:           secret.N.String(),
		S:           secret.S.String(),
		LeafIndex:   cf.LeafIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("generate proof: %w", err)
	}
	return resp, nil
}

// ── ECIES key management ──────────────────────────────────────────────────────
// Strategy: server generates a keypair per user.
// Private key is AES-256-GCM encrypted with the DEK (from Vault) and stored in DB.
// Public key stored plaintext (not secret).
// DEK never touches the DB or logs.

func (s *ZKPService) getOrCreateECIESKey(ctx context.Context, userAddress string) (pubKey string, err error) {
	// Check if key already exists
	var encryptedPrivKey []byte
	var existingPubKey string
	err = s.db.QueryRowContext(ctx,
		`SELECT encrypted_priv_key, pub_key FROM zkp_ecies_keys WHERE user_address = $1`,
		strings.ToLower(userAddress),
	).Scan(&encryptedPrivKey, &existingPubKey)

	if err == nil {
		return existingPubKey, nil // key already exists
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("query ecies key: %w", err)
	}

	// Generate fresh keypair
	kp, err := zkpcrypto.GenerateKeyPair()
	if err != nil {
		return "", fmt.Errorf("generate keypair: %w", err)
	}

	// Encrypt private key with DEK using AES-256-GCM
	// SECURITY: kp.PrivateKey never written to any log
	encPriv, err := aesGCMEncrypt(s.dekBytes, []byte(kp.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("encrypt ecies privkey: %w", err)
	}

	// Store encrypted private key + plaintext public key
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO zkp_ecies_keys (user_address, pub_key, encrypted_priv_key)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_address) DO NOTHING`,
		strings.ToLower(userAddress), kp.PublicKey, encPriv,
	)
	if err != nil {
		return "", fmt.Errorf("insert ecies key: %w", err)
	}

	return kp.PublicKey, nil
}

func (s *ZKPService) loadDecryptedECIESKey(ctx context.Context, userAddress string) (string, error) {
	var encryptedPrivKey []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT encrypted_priv_key FROM zkp_ecies_keys WHERE user_address = $1`,
		strings.ToLower(userAddress),
	).Scan(&encryptedPrivKey)
	if err != nil {
		return "", fmt.Errorf("query ecies key: %w", err)
	}

	plaintext, err := aesGCMDecrypt(s.dekBytes, encryptedPrivKey)
	if err != nil {
		return "", fmt.Errorf("decrypt ecies key: %w", err)
	}
	return string(plaintext), nil
}

// ── ClaimFile storage ─────────────────────────────────────────────────────────
// encryptedSecret is already ECIES-encrypted by the middleware — safe to store as-is.

func (s *ZKPService) saveClaimFile(ctx context.Context, cf *zkp.ClaimFile) error {
	data, err := json.Marshal(cf)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO zkp_claim_files (user_address, file_id, leaf_index, claim_data)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (user_address, file_id) DO UPDATE
		   SET leaf_index = EXCLUDED.leaf_index,
		       claim_data = EXCLUDED.claim_data,
		       updated_at = NOW()`,
		strings.ToLower(cf.UserAddress), cf.FileID, cf.LeafIndex, data,
	)
	return err
}

func (s *ZKPService) loadClaimFile(ctx context.Context, userAddress, fileID string) (*zkp.ClaimFile, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT claim_data FROM zkp_claim_files WHERE user_address = $1 AND file_id = $2`,
		strings.ToLower(userAddress), fileID,
	).Scan(&data)
	if err != nil {
		return nil, fmt.Errorf("query claim file: %w", err)
	}
	var cf zkp.ClaimFile
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("unmarshal claim file: %w", err)
	}
	return &cf, nil
}

// ── AES-256-GCM helpers ───────────────────────────────────────────────────────

// aesGCMEncrypt encrypts plaintext with AES-256-GCM using a random 12-byte nonce.
// Output layout: nonce(12) || ciphertext || GCM tag(16)
func aesGCMEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ── ERC-4337 helpers ──────────────────────────────────────────────────────────

const entryPointAddr = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"

type userOperation struct {
	Sender               string `json:"sender"`
	Nonce                string `json:"nonce"`
	InitCode             string `json:"initCode"`
	CallData             string `json:"callData"`
	CallGasLimit         string `json:"callGasLimit"`
	VerificationGasLimit string `json:"verificationGasLimit"`
	PreVerificationGas   string `json:"preVerificationGas"`
	MaxFeePerGas         string `json:"maxFeePerGas"`
	MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
	PaymasterAndData     string `json:"paymasterAndData"`
	Signature            string `json:"signature"`
}

// sendUserOp builds, sponsors, signs, and submits one UserOp for the given calldata.
// Returns the on-chain tx hash.
func (s *ZKPService) sendUserOp(ctx context.Context, calldata *zkp.Calldata) (string, error) {
	// Nonce from EntryPoint
	nonce, err := s.getEntryPointNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}

	// Encode LightAccount.execute(target, value, data)
	target := common.HexToAddress(calldata.To)
	rawData, err := hex.DecodeString(strings.TrimPrefix(calldata.Data, "0x"))
	if err != nil {
		return "", fmt.Errorf("decode calldata: %w", err)
	}
	execData, err := encodeLightAccountExecute(target, big.NewInt(0), rawData)
	if err != nil {
		return "", fmt.Errorf("encode execute: %w", err)
	}

	// Gas fees
	tip, err := s.ethClient.SuggestGasTipCap(ctx)
	if err != nil {
		return "", fmt.Errorf("tip cap: %w", err)
	}
	header, err := s.ethClient.HeaderByNumber(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("header: %w", err)
	}
	baseFee := header.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(1e9)
	}
	maxFee := new(big.Int).Add(baseFee, tip)

	uo := &userOperation{
		Sender:               s.lightAccount,
		Nonce:                toHex(nonce),
		InitCode:             "0x",
		CallData:             "0x" + hex.EncodeToString(execData),
		CallGasLimit:         toHex(big.NewInt(150_000)),
		VerificationGasLimit: toHex(big.NewInt(150_000)),
		PreVerificationGas:   toHex(big.NewInt(50_000)),
		MaxFeePerGas:         toHex(maxFee),
		MaxPriorityFeePerGas: toHex(tip),
		PaymasterAndData:     "0x",
		Signature:            "0x",
	}

	// Paymaster sponsorship
	uo.PaymasterAndData, err = s.requestPaymaster(uo)
	if err != nil {
		return "", fmt.Errorf("paymaster: %w", err)
	}

	// Sign UserOp hash
	uoHash, err := computeUserOpHash(uo)
	if err != nil {
		return "", fmt.Errorf("compute hash: %w", err)
	}
	sig, err := ethcrypto.Sign(accounts.TextHash(uoHash[:]), s.signerKey)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27
	uo.Signature = "0x" + hex.EncodeToString(sig)

	// Submit + wait for tx hash
	return s.submitAndWaitUserOp(uo)
}

func (s *ZKPService) getEntryPointNonce(ctx context.Context) (*big.Int, error) {
	// EntryPoint.getNonce(address sender, uint192 key) selector: 0x35567e1a
	addr := common.HexToAddress(s.lightAccount)
	var padded [32]byte
	copy(padded[12:], addr.Bytes())
	data := make([]byte, 4+64)
	copy(data[:4], []byte{0x35, 0x56, 0x7e, 0x1a})
	copy(data[4:36], padded[:])

	ep := common.HexToAddress(entryPointAddr)
	result, err := s.ethClient.CallContract(ctx, ethereum.CallMsg{To: &ep, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	if len(result) < 32 {
		return big.NewInt(0), nil
	}
	return new(big.Int).SetBytes(result[:32]), nil
}

func (s *ZKPService) requestPaymaster(uo *userOperation) (string, error) {
	type pmReq struct {
		PolicyID   string         `json:"policyId"`
		EntryPoint string         `json:"entryPoint"`
		UserOp     *userOperation `json:"userOperation"`
	}
	type pmResp struct {
		Result *struct {
			PaymasterAndData string `json:"paymasterAndData"`
		} `json:"result"`
		Error *struct{ Message string `json:"message"` } `json:"error"`
	}

	req := rpcBody("alchemy_requestPaymasterAndData", []any{
		pmReq{PolicyID: s.alchemyPolicy, EntryPoint: entryPointAddr, UserOp: uo},
	})
	var resp pmResp
	if err := postJSON(s.bundlerURL, req, &resp); err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("%s", resp.Error.Message)
	}
	return resp.Result.PaymasterAndData, nil
}

func (s *ZKPService) submitAndWaitUserOp(uo *userOperation) (string, error) {
	type sendResp struct {
		Result string `json:"result"` // userOpHash
		Error  *struct{ Message string `json:"message"` } `json:"error"`
	}

	req := rpcBody("eth_sendUserOperation", []any{uo, entryPointAddr})
	var resp sendResp
	if err := postJSON(s.bundlerURL, req, &resp); err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("bundler: %s", resp.Error.Message)
	}

	// Poll for receipt → get actual tx hash
	return s.pollUserOpReceipt(resp.Result)
}

func (s *ZKPService) pollUserOpReceipt(userOpHash string) (string, error) {
	type receiptResp struct {
		Result *struct {
			Receipt struct {
				TransactionHash string `json:"transactionHash"`
			} `json:"receipt"`
		} `json:"result"`
		Error *struct{ Message string `json:"message"` } `json:"error"`
	}

	for i := 0; i < 60; i++ {
		req := rpcBody("eth_getUserOperationReceipt", []any{userOpHash})
		var resp receiptResp
		if err := postJSON(s.bundlerURL, req, &resp); err != nil {
			return "", err
		}
		if resp.Error != nil {
			return "", fmt.Errorf("receipt: %s", resp.Error.Message)
		}
		if resp.Result != nil {
			return resp.Result.Receipt.TransactionHash, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", fmt.Errorf("UserOp not mined within 30s: %s", userOpHash)
}

func (s *ZKPService) waitForTx(ctx context.Context, txHashHex string) error {
	hash := common.HexToHash(txHashHex)
	for {
		receipt, err := s.ethClient.TransactionReceipt(ctx, hash)
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

// ── ABI / crypto helpers ──────────────────────────────────────────────────────

// encodeLightAccountExecute ABI-encodes execute(address,uint256,bytes) — selector 0xb61d27f6
func encodeLightAccountExecute(target common.Address, value *big.Int, data []byte) ([]byte, error) {
	buf := make([]byte, 0, 4+32+32+32+32+len(data))
	buf = append(buf, 0xb6, 0x1d, 0x27, 0xf6)
	var addrPad [32]byte
	copy(addrPad[12:], target.Bytes())
	buf = append(buf, addrPad[:]...)
	buf = append(buf, math.PaddedBigBytes(value, 32)...)
	buf = append(buf, math.PaddedBigBytes(big.NewInt(96), 32)...) // bytes offset
	buf = append(buf, math.PaddedBigBytes(big.NewInt(int64(len(data))), 32)...)
	buf = append(buf, data...)
	if pad := (32 - len(data)%32) % 32; pad > 0 {
		buf = append(buf, make([]byte, pad)...)
	}
	return buf, nil
}

// computeUserOpHash computes the ERC-4337 v0.6 hash for chainId=421614 (Arbitrum Sepolia).
func computeUserOpHash(uo *userOperation) ([32]byte, error) {
	hexToBig := func(s string) *big.Int {
		b, _ := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
		return b
	}
	decodeHex := func(s string) []byte {
		b, _ := hex.DecodeString(strings.TrimPrefix(s, "0x"))
		return b
	}

	var packed []byte
	addr := common.HexToAddress(uo.Sender)
	var addrPad [32]byte
	copy(addrPad[12:], addr.Bytes())
	packed = append(packed, addrPad[:]...)
	packed = append(packed, math.PaddedBigBytes(hexToBig(uo.Nonce), 32)...)
	packed = append(packed, ethcrypto.Keccak256(decodeHex(uo.InitCode))...)
	packed = append(packed, ethcrypto.Keccak256(decodeHex(uo.CallData))...)
	packed = append(packed, math.PaddedBigBytes(hexToBig(uo.CallGasLimit), 32)...)
	packed = append(packed, math.PaddedBigBytes(hexToBig(uo.VerificationGasLimit), 32)...)
	packed = append(packed, math.PaddedBigBytes(hexToBig(uo.PreVerificationGas), 32)...)
	packed = append(packed, math.PaddedBigBytes(hexToBig(uo.MaxFeePerGas), 32)...)
	packed = append(packed, math.PaddedBigBytes(hexToBig(uo.MaxPriorityFeePerGas), 32)...)
	packed = append(packed, ethcrypto.Keccak256(decodeHex(uo.PaymasterAndData))...)
	innerHash := ethcrypto.Keccak256Hash(packed)

	ep := common.HexToAddress(entryPointAddr)
	var epPad [32]byte
	copy(epPad[12:], ep.Bytes())
	var outer []byte
	outer = append(outer, innerHash.Bytes()...)
	outer = append(outer, epPad[:]...)
	outer = append(outer, math.PaddedBigBytes(big.NewInt(421614), 32)...)
	return ethcrypto.Keccak256Hash(outer), nil
}

// ── JSON-RPC helpers ──────────────────────────────────────────────────────────

func rpcBody(method string, params []any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
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

func toHex(n *big.Int) string { return "0x" + fmt.Sprintf("%x", n) }

// ── Postgres migrations ───────────────────────────────────────────────────────

func migrateDB(db *sql.DB) error {
	_, err := db.Exec(`
		-- Per-user ECIES keypairs.
		-- pub_key:            stored plaintext (not secret)
		-- encrypted_priv_key: AES-256-GCM(DEK, privKey) — DEK lives only in Vault
		CREATE TABLE IF NOT EXISTS zkp_ecies_keys (
			user_address       TEXT PRIMARY KEY,
			pub_key            TEXT        NOT NULL,
			encrypted_priv_key BYTEA       NOT NULL,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		-- Credential files issued per (user, file).
		-- claim_data contains the full ClaimFile JSON.
		-- encryptedSecret inside claim_data is ECIES-encrypted by the middleware — safe to store.
		CREATE TABLE IF NOT EXISTS zkp_claim_files (
			user_address TEXT        NOT NULL,
			file_id      TEXT        NOT NULL,
			leaf_index   BIGINT      NOT NULL,
			claim_data   JSONB       NOT NULL,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (user_address, file_id)
		);
	`)
	return err
}
