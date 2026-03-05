package zkp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── fixtures ──────────────────────────────────────────────────────────────────

var (
	fixtureHealth = HealthResponse{Status: "ok", ChainID: 421614, MiddlewarePubKey: "0x04ab"}

	fixtureClaimFile = ClaimFile{
		UserAddress:     validAddress(),
		FileID:          validFileID(),
		Commitment:      "0x" + strings.Repeat("cc", 32),
		LeafIndex:       0,
		EncryptedSecret: "0x" + strings.Repeat("dd", 157),
	}

	fixtureCalldata = Calldata{To: "0x" + strings.Repeat("ee", 20), Data: "0xabcd", Value: "0"}

	fixtureIssueResp = IssueCredentialResponse{
		ClaimFile:      &fixtureClaimFile,
		InsertCalldata: &fixtureCalldata,
	}

	fixtureBatchResp = BatchIssueCredentialResponse{
		Credentials:    []BatchCredentialItem{{ClaimFile: &fixtureClaimFile}},
		InsertCalldata: &fixtureCalldata,
	}

	fixtureProofResp = GenerateProofResponse{
		Proof: &SolidityProof{
			A: [2]string{"1", "2"},
			B: [2][2]string{{"3", "4"}, {"5", "6"}},
			C: [2]string{"7", "8"},
		},
		PublicSignals:    [7]string{"1", "2", "3", "4", "5", "6", "7"},
		Calldata:         &fixtureCalldata,
		RequestNullifier: "0xdeadbeef",
		ReqID:            "0",
	}

	fixtureShareResp = SharePrepareResponse{
		EncryptedCredential: "0x" + strings.Repeat("ff", 10),
		ShareKeyCommit:      "0x" + strings.Repeat("aa", 32),
		InsertCalldata:      &fixtureCalldata,
		GrantShareCalldata:  &fixtureCalldata,
		LeafIndex:           1,
		Commitment:          "0x" + strings.Repeat("bb", 32),
	}

	fixtureIncomingResp = IncomingSharesResponse{
		Address: validAddress(),
		Shares: []IncomingShare{
			{FileID: validFileID(), Owner: validAddress(), Active: true, GrantedAtBlock: 100},
		},
	}

	fixtureUserPubKey = UserPubKeyResponse{
		Address:    validAddress(),
		PubKey:     validPubKey(),
		Registered: true,
	}

	fixtureEmailResp = ResolveEmailResponse{
		EmailHash:  validFileID(),
		Address:    validAddress(),
		PubKey:     validPubKey(),
		Registered: true,
	}
)

// apiServer starts a test server serving a single fixed JSON response.
func apiServer(t *testing.T, statusCode int, body any) (*httptest.Server, *ZKPClient) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	t.Cleanup(srv.Close)

	c, err := NewClient(srv.URL, WithAPIKey("test-key"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, c
}

// ── Health ────────────────────────────────────────────────────────────────────

func TestClient_Health_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureHealth)
	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if resp.Status != "ok" || resp.ChainID != 421614 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestClient_Health_NetworkError(t *testing.T) {
	c, _ := NewClient("http://localhost:1") // nothing listening
	_, err := c.Health(context.Background())
	var ne *NetworkError
	if !errors.As(err, &ne) {
		t.Errorf("expected *NetworkError, got %T: %v", err, err)
	}
}

// ── IssueCredential ───────────────────────────────────────────────────────────

func TestClient_IssueCredential_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureIssueResp)
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	}
	resp, err := c.IssueCredential(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}
	if resp.ClaimFile == nil || resp.InsertCalldata == nil {
		t.Error("response missing required fields")
	}
}

func TestClient_IssueCredential_NoAPIKey(t *testing.T) {
	// Client without API key — must return *ValidationError without HTTP call.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP call made despite missing API key")
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL) // no WithAPIKey
	_, err := c.IssueCredential(context.Background(), &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestClient_IssueCredential_BadInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP call made despite invalid input")
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, WithAPIKey("k"))
	_, err := c.IssueCredential(context.Background(), &IssueCredentialRequest{
		UserAddress:   "bad-address",
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

func TestClient_IssueCredential_FileNotFound(t *testing.T) {
	_, c := apiServer(t, 404, map[string]string{"error": "file not found"})
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	}
	_, err := c.IssueCredential(context.Background(), req)
	var nfe *NotFoundError
	if !errors.As(err, &nfe) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestClient_IssueCredential_TreeFull(t *testing.T) {
	_, c := apiServer(t, 409, map[string]string{"error": "tree full"})
	req := &IssueCredentialRequest{
		UserAddress:   validAddress(),
		FileID:        validFileID(),
		UserPublicKey: validPubKey(),
	}
	_, err := c.IssueCredential(context.Background(), req)
	var tfe *TreeFullError
	if !errors.As(err, &tfe) {
		t.Errorf("expected *TreeFullError, got %T: %v", err, err)
	}
}

// ── IssueCredentialBatch ──────────────────────────────────────────────────────

func TestClient_IssueCredentialBatch_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureBatchResp)
	req := &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files: []BatchFileRequest{
			{FileID: validFileID()},
			{FileID: validFileID()},
			{FileID: validFileID()},
		},
	}
	resp, err := c.IssueCredentialBatch(context.Background(), req)
	if err != nil {
		t.Fatalf("IssueCredentialBatch: %v", err)
	}
	if len(resp.Credentials) == 0 {
		t.Error("expected credentials in response")
	}
}

func TestClient_IssueCredentialBatch_TooManyFiles(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP call made despite too many files")
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, WithAPIKey("k"))
	files := make([]BatchFileRequest, 21)
	for i := range files {
		files[i] = BatchFileRequest{FileID: validFileID()}
	}
	_, err := c.IssueCredentialBatch(context.Background(), &BatchIssueCredentialRequest{
		UserAddress:   validAddress(),
		UserPublicKey: validPubKey(),
		Files:         files,
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// ── GenerateProof ─────────────────────────────────────────────────────────────

func TestClient_GenerateProof_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureProofResp)
	req := &GenerateProofRequest{
		UserAddress: validAddress(),
		FileID:      validFileID(),
		N:           "42",
		S:           "99",
	}
	resp, err := c.GenerateProof(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if resp.Proof == nil {
		t.Error("expected proof in response")
	}
}

func TestClient_GenerateProof_NOutOfRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP call made despite n out of range")
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, WithAPIKey("k"))
	_, err := c.GenerateProof(context.Background(), &GenerateProofRequest{
		UserAddress: validAddress(),
		FileID:      validFileID(),
		N:           "21888242871839275222246405745257275088548364400416034343698204186575808495617",
		S:           "1",
	})
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// ── PrepareShare ──────────────────────────────────────────────────────────────

func TestClient_PrepareShare_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureShareResp)
	req := &SharePrepareRequest{
		FileID:                 validFileID(),
		GranteeAddress:         validAddress(),
		GranteePublicKey:       validPubKey(),
		EncryptedKeyForGrantee: "0x" + strings.Repeat("ab", 157),
	}
	resp, err := c.PrepareShare(context.Background(), req)
	if err != nil {
		t.Fatalf("PrepareShare: %v", err)
	}
	if resp.InsertCalldata == nil {
		t.Error("expected InsertCalldata in response")
	}
}

// ── IncomingShares ────────────────────────────────────────────────────────────

func TestClient_IncomingShares_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureIncomingResp)
	resp, err := c.IncomingShares(context.Background(), validAddress())
	if err != nil {
		t.Fatalf("IncomingShares: %v", err)
	}
	if len(resp.Shares) == 0 {
		t.Error("expected shares in response")
	}
}

func TestClient_IncomingShares_BadAddress(t *testing.T) {
	_, c := apiServer(t, 200, nil)
	_, err := c.IncomingShares(context.Background(), "not-an-address")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// ── GetUserPubKey ─────────────────────────────────────────────────────────────

func TestClient_GetUserPubKey_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureUserPubKey)
	resp, err := c.GetUserPubKey(context.Background(), validAddress())
	if err != nil {
		t.Fatalf("GetUserPubKey: %v", err)
	}
	if !resp.Registered {
		t.Error("expected registered=true")
	}
}

func TestClient_GetUserPubKey_Unregistered(t *testing.T) {
	unregistered := UserPubKeyResponse{Address: validAddress(), PubKey: "", Registered: false}
	_, c := apiServer(t, 200, unregistered)
	resp, err := c.GetUserPubKey(context.Background(), validAddress())
	if err != nil {
		t.Fatalf("GetUserPubKey: %v", err)
	}
	if resp.Registered {
		t.Error("expected registered=false")
	}
}

// ── ResolveEmail ──────────────────────────────────────────────────────────────

func TestClient_ResolveEmail_OK(t *testing.T) {
	_, c := apiServer(t, 200, fixtureEmailResp)
	resp, err := c.ResolveEmail(context.Background(), validFileID())
	if err != nil {
		t.Fatalf("ResolveEmail: %v", err)
	}
	if !resp.Registered {
		t.Error("expected registered=true")
	}
}

func TestClient_ResolveEmail_BadHash(t *testing.T) {
	_, c := apiServer(t, 200, nil)
	_, err := c.ResolveEmail(context.Background(), "not-bytes32")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError, got %T: %v", err, err)
	}
}

// ── NewClient ─────────────────────────────────────────────────────────────────

func TestNewClient_EmptyBaseURL(t *testing.T) {
	_, err := NewClient("")
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Errorf("expected *ValidationError for empty baseURL, got %T: %v", err, err)
	}
}

// ── SetAPIKey concurrent safety ───────────────────────────────────────────────

func TestClient_SetAPIKey_ConcurrentSafe(t *testing.T) {
	// A server that records which Authorization header it received.
	var mu sync.Mutex
	received := make([]string, 0, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"status":"ok","chainId":421614}`)
	}))
	defer srv.Close()

	c, _ := NewClient(srv.URL, WithAPIKey("key-0"),
		WithTimeout(5*time.Second),
		WithMaxRetries(0),
	)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Alternate between SetAPIKey and Health calls.
			c.SetAPIKey(fmt.Sprintf("key-%d", i))
			_, _ = c.Health(context.Background())
		}()
	}
	wg.Wait()

	// No race detector violations and no panic = success.
	// We can't assert specific key values since goroutines are concurrent,
	// but we verify every request had some Authorization header (or none if
	// a Health call raced before SetAPIKey — Health is unauthenticated).
	t.Logf("received %d health responses with headers: %v", len(received), received)
}
