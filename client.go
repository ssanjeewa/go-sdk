package zkp

import (
	"context"
	"fmt"
	"sync/atomic"
)

// ZKPClient is the main entry point for the ZKP middleware SDK.
//
// Create a client once and reuse it across goroutines — ZKPClient is safe
// for concurrent use by multiple goroutines (BP-10).
//
//	client, err := zkp.NewClient("https://middleware.example.com",
//	    zkp.WithAPIKey("your-api-key"),
//	)
type ZKPClient struct {
	http   *httpClient
	apiKey atomic.Pointer[string] // SEC-04: atomic for concurrent SetAPIKey safety
}

// NewClient creates a new ZKPClient targeting the given base URL.
// Returns *ValidationError if baseURL is empty.
//
// Options:
//
//	WithAPIKey    — set the Bearer token (required for most endpoints)
//	WithTimeout   — per-attempt timeout (default 30s)
//	WithMaxRetries — max retry attempts on 5xx/429/transport errors (default 3)
//	WithRetryDelay — base retry backoff delay (default 200ms)
func NewClient(baseURL string, opts ...ClientOption) (*ZKPClient, error) {
	if baseURL == "" {
		return nil, &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: "baseURL must not be empty",
		}}
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	c := &ZKPClient{
		http: newHTTPClient(baseURL, cfg),
	}
	if cfg.apiKey != "" {
		key := cfg.apiKey
		c.apiKey.Store(&key)
	}
	return c, nil
}

// SetAPIKey atomically updates the API key used for authenticated requests.
// Safe to call concurrently with in-flight requests (SEC-04).
// In-flight requests that already started continue with the previous key;
// new requests after this call use the new key.
func (c *ZKPClient) SetAPIKey(apiKey string) {
	key := apiKey
	c.apiKey.Store(&key)
}

// assertAPIKey returns *ValidationError if no API key has been configured.
func (c *ZKPClient) assertAPIKey() error {
	if p := c.apiKey.Load(); p == nil || *p == "" {
		return &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: "API key not set — provide it via WithAPIKey option or SetAPIKey method",
		}}
	}
	return nil
}

// authedHTTP returns a one-shot httpClient clone with the current API key
// attached as an Authorization: Bearer header (SEC-04: reads key atomically).
func (c *ZKPClient) authedHTTP() *httpClient {
	p := c.apiKey.Load()
	if p == nil || *p == "" {
		return c.http
	}
	return c.http.withHeader("Authorization", "Bearer "+*p)
}

// ── Unauthenticated endpoints ─────────────────────────────────────────────────

// Health returns the current service status from GET /v1/health.
// No API key required.
func (c *ZKPClient) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.http.do(ctx, "GET", "/v1/health", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Metrics returns the raw Prometheus metrics text from GET /metrics.
// No API key required.
func (c *ZKPClient) Metrics(ctx context.Context) (string, error) {
	var raw string
	if err := c.http.do(ctx, "GET", "/metrics", nil, &raw); err != nil {
		return "", err
	}
	return raw, nil
}

// ── Authenticated endpoints ───────────────────────────────────────────────────

// IssueCredential issues a new ZK credential for a (userAddress, fileId) pair.
// Validates inputs client-side before making the HTTP call.
// Returns *ValidationError on bad input, *NotFoundError if the file is not
// registered on-chain, *TreeFullError if the user's Merkle tree is full.
func (c *ZKPClient) IssueCredential(ctx context.Context, req *IssueCredentialRequest) (*IssueCredentialResponse, error) {
	if err := validateIssueRequest(req); err != nil {
		return nil, err
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp IssueCredentialResponse
	if err := c.authedHTTP().do(ctx, "POST", "/v1/credentials/issue", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// IssueCredentialBatch issues credentials for 1–20 files in a single request.
// Returns *ValidationError if the files slice is empty or exceeds MaxBatchSize.
func (c *ZKPClient) IssueCredentialBatch(ctx context.Context, req *BatchIssueCredentialRequest) (*BatchIssueCredentialResponse, error) {
	if err := validateBatchIssueRequest(req); err != nil {
		return nil, err
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp BatchIssueCredentialResponse
	if err := c.authedHTTP().do(ctx, "POST", "/v1/credentials/issue/batch", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateProof generates a Groth16 ZK proof for a given credential.
// n and s are validated against the BN254 scalar field before the HTTP call
// to avoid a wasted round-trip (SEC-03).
func (c *ZKPClient) GenerateProof(ctx context.Context, req *GenerateProofRequest) (*GenerateProofResponse, error) {
	if err := validateProofRequest(req); err != nil {
		return nil, err
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp GenerateProofResponse
	if err := c.authedHTTP().do(ctx, "POST", "/v1/proof/generate", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PrepareShare prepares a delegated credential share for a grantee.
// Returns *ValidationError on bad input, *NotFoundError if the file is not
// registered, *TreeFullError if the grantee's tree is full.
func (c *ZKPClient) PrepareShare(ctx context.Context, req *SharePrepareRequest) (*SharePrepareResponse, error) {
	if err := validateSharePrepareRequest(req); err != nil {
		return nil, err
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp SharePrepareResponse
	if err := c.authedHTTP().do(ctx, "POST", "/v1/shares/prepare", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// IncomingShares returns all credential shares granted to granteeAddress.
// Returns *ValidationError if granteeAddress is not a valid Ethereum address.
func (c *ZKPClient) IncomingShares(ctx context.Context, granteeAddress string) (*IncomingSharesResponse, error) {
	if !isHexAddress(granteeAddress) {
		return nil, &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("granteeAddress must be a 0x-prefixed 20-byte hex address, got %q", granteeAddress),
		}}
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp IncomingSharesResponse
	path := "/v1/shares/incoming/" + granteeAddress
	if err := c.authedHTTP().do(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetUserPubKey returns the on-chain public key registered for an address.
// If the user has not registered a key, Registered will be false and PubKey
// will be an empty string.
func (c *ZKPClient) GetUserPubKey(ctx context.Context, address string) (*UserPubKeyResponse, error) {
	if !isHexAddress(address) {
		return nil, &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("address must be a 0x-prefixed 20-byte hex address, got %q", address),
		}}
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp UserPubKeyResponse
	path := "/v1/users/" + address + "/pubkey"
	if err := c.authedHTTP().do(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ResolveEmail resolves a keccak256 email hash to an address and public key.
// emailHash must be a 0x-prefixed bytes32 hex string.
func (c *ZKPClient) ResolveEmail(ctx context.Context, emailHash string) (*ResolveEmailResponse, error) {
	if !isBytes32Hex(emailHash) {
		return nil, &ValidationError{ZKPError: ZKPError{
			Code:    ErrCodeValidation,
			Message: fmt.Sprintf("emailHash must be a 0x-prefixed 32-byte hex value, got %q", emailHash),
		}}
	}
	if err := c.assertAPIKey(); err != nil {
		return nil, err
	}
	var resp ResolveEmailResponse
	path := "/v1/users/by-email/" + emailHash
	if err := c.authedHTTP().do(ctx, "GET", path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
