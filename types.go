package zkp

// MaxBatchSize is the maximum number of files allowed in a single batch
// credential issuance request.
const MaxBatchSize = 20

// ── Health ────────────────────────────────────────────────────────────────────

// HealthResponse is returned by GET /v1/health.
// LastSyncBlock and TrackedUsers are only populated when called via an
// authenticated admin endpoint.
type HealthResponse struct {
	Status           string `json:"status"`
	ChainID          int64  `json:"chainId"`
	LastSyncBlock    uint64 `json:"lastSyncBlock,omitempty"`
	TrackedUsers     int    `json:"trackedUsers,omitempty"`
	MiddlewarePubKey string `json:"middlewarePubKey,omitempty"`
}

// ── Calldata ──────────────────────────────────────────────────────────────────

// Calldata is a ready-to-submit EVM transaction payload.
// Submit directly to the chain — no signing is required by the SDK.
type Calldata struct {
	To    string `json:"to"`
	Data  string `json:"data"`
	Value string `json:"value"`
}

// ── Credential ────────────────────────────────────────────────────────────────

// ClaimFile is the credential file returned after issuance.
// The holder must store this safely — it is required for proof generation.
type ClaimFile struct {
	UserAddress     string `json:"userAddress"`
	FileID          string `json:"fileId"`
	Commitment      string `json:"commitment"`      // 0x-prefixed bytes32 hex
	LeafIndex       uint64 `json:"leafIndex"`
	EncryptedSecret string `json:"encryptedSecret"` // ECIES(userPubKey, n‖s) — 0x-prefixed hex
}

// IssueCredentialRequest is the request body for POST /v1/credentials/issue.
type IssueCredentialRequest struct {
	UserAddress   string `json:"userAddress"`
	FileID        string `json:"fileId"`        // 0x-prefixed bytes32
	UserPublicKey string `json:"userPublicKey"` // 0x04-prefixed 65-byte uncompressed secp256k1
	Secret        string `json:"secret,omitempty"` // optional decimal bigint (dev/test only)
}

// IssueCredentialResponse is the response body for POST /v1/credentials/issue.
type IssueCredentialResponse struct {
	ClaimFile      *ClaimFile `json:"claimFile"`
	InsertCalldata *Calldata  `json:"insertCalldata"`
}

// ── Batch credential ──────────────────────────────────────────────────────────

// BatchFileRequest is a single file entry in a batch issuance request.
type BatchFileRequest struct {
	FileID string `json:"fileId"`           // 0x-prefixed bytes32
	Secret string `json:"secret,omitempty"` // optional decimal bigint (dev/test only)
}

// BatchIssueCredentialRequest is the request body for POST /v1/credentials/issue/batch.
// Files must contain 1–MaxBatchSize entries.
type BatchIssueCredentialRequest struct {
	UserAddress   string             `json:"userAddress"`
	UserPublicKey string             `json:"userPublicKey"` // 0x04-prefixed uncompressed secp256k1
	Files         []BatchFileRequest `json:"files"`
}

// BatchCredentialItem wraps a single ClaimFile in a batch response.
type BatchCredentialItem struct {
	ClaimFile *ClaimFile `json:"claimFile"`
}

// BatchIssueCredentialResponse is the response body for POST /v1/credentials/issue/batch.
type BatchIssueCredentialResponse struct {
	Credentials    []BatchCredentialItem `json:"credentials"`
	InsertCalldata *Calldata             `json:"insertCalldata"` // single tx covering all N leaves
}

// ── Proof ─────────────────────────────────────────────────────────────────────

// SolidityProof holds the Groth16 proof coordinates formatted for the
// on-chain Solidity verifier. All values are decimal strings.
type SolidityProof struct {
	A [2]string    `json:"a"`
	B [2][2]string `json:"b"`
	C [2]string    `json:"c"`
}

// GenerateProofRequest is the request body for POST /v1/proof/generate.
// N and S must be valid BN254 scalar field elements in decimal string form.
type GenerateProofRequest struct {
	UserAddress   string `json:"userAddress"`
	FileID        string `json:"fileId"`                 // 0x-prefixed bytes32
	N             string `json:"n"`                      // BN254 field element, decimal string
	S             string `json:"s"`                      // BN254 field element, decimal string
	LeafIndex     uint64 `json:"leafIndex"`
	UserPublicKey string `json:"userPublicKey,omitempty"` // 0x04-prefixed (optional)
	EncryptedBlob string `json:"encryptedBlob,omitempty"` // 0x-prefixed hex (grantee download)
}

// GenerateProofResponse is the response body for POST /v1/proof/generate.
type GenerateProofResponse struct {
	Proof            *SolidityProof `json:"proof"`
	PublicSignals    [7]string      `json:"publicSignals"`
	Calldata         *Calldata      `json:"calldata"`
	RequestNullifier string         `json:"requestNullifier"`
	ReqID            string         `json:"reqId"`
	EncryptedFileKey string         `json:"encryptedFileKey,omitempty"` // present on grantee downloads
}

// ── Shares ────────────────────────────────────────────────────────────────────

// SharePrepareRequest is the request body for POST /v1/shares/prepare.
type SharePrepareRequest struct {
	FileID                 string `json:"fileId"`                 // 0x-prefixed bytes32
	GranteeAddress         string `json:"granteeAddress"`         // 0x-prefixed Ethereum address
	GranteePublicKey       string `json:"granteePublicKey"`       // 0x04-prefixed uncompressed secp256k1
	EncryptedKeyForGrantee string `json:"encryptedKeyForGrantee"` // ECIES blob, 0x-prefixed hex
}

// SharePrepareResponse is the response body for POST /v1/shares/prepare.
type SharePrepareResponse struct {
	EncryptedCredential string    `json:"encryptedCredential"` // 0x-prefixed hex
	ShareKeyCommit      string    `json:"shareKeyCommit"`      // 0x-prefixed bytes32
	InsertCalldata      *Calldata `json:"insertCalldata"`
	GrantShareCalldata  *Calldata `json:"grantShareCalldata"`
	LeafIndex           uint64    `json:"leafIndex"`
	Commitment          string    `json:"commitment"` // 0x-prefixed bytes32
}

// IncomingShare is one entry in an IncomingSharesResponse.
type IncomingShare struct {
	FileID              string `json:"fileId"`
	Owner               string `json:"owner"`
	Active              bool   `json:"active"`
	GrantedAtBlock      uint64 `json:"grantedAtBlock"`
	EncryptedCredential string `json:"encryptedCredential,omitempty"` // 0x-prefixed hex
}

// IncomingSharesResponse is the response body for GET /v1/shares/incoming/{address}.
type IncomingSharesResponse struct {
	Address string          `json:"address"`
	Shares  []IncomingShare `json:"shares"`
}

// ── Users ─────────────────────────────────────────────────────────────────────

// UserPubKeyResponse is the response body for GET /v1/users/{address}/pubkey.
type UserPubKeyResponse struct {
	Address    string `json:"address"`
	PubKey     string `json:"pubKey"`     // 0x04-prefixed hex; empty if not registered
	Registered bool   `json:"registered"` // true when a 65-byte key is stored on-chain
}

// ResolveEmailResponse is the response body for GET /v1/users/by-email/{emailHash}.
type ResolveEmailResponse struct {
	EmailHash  string `json:"emailHash"`  // 0x-prefixed bytes32
	Address    string `json:"address"`    // resolved wallet address, or zero address
	PubKey     string `json:"pubKey"`     // 0x04-prefixed hex; empty if not registered
	Registered bool   `json:"registered"` // true when address resolved and has a pubKey
}
