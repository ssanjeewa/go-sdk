package zkp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// testConfig returns a clientConfig with short timeouts suitable for unit tests.
func testConfig(timeout time.Duration, maxRetries int, retryDelay time.Duration) *clientConfig {
	return &clientConfig{
		timeout:    timeout,
		maxRetries: maxRetries,
		retryDelay: retryDelay,
	}
}

// jsonServer returns a test server that responds with statusCode and the given body.
func jsonServer(statusCode int, body any, headers ...func(http.Header)) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range headers {
			h(w.Header())
		}
		if statusCode == http.StatusNoContent {
			w.WriteHeader(statusCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
}

// ── Happy paths ───────────────────────────────────────────────────────────────

func TestHTTPClient_200_JSON(t *testing.T) {
	type payload struct {
		Status string `json:"status"`
	}
	srv := jsonServer(200, payload{Status: "ok"})
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))

	var got payload
	if err := h.do(context.Background(), http.MethodGet, "/v1/health", nil, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("got status %q, want %q", got.Status, "ok")
	}
}

func TestHTTPClient_204_NoContent(t *testing.T) {
	srv := jsonServer(http.StatusNoContent, nil)
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	if err := h.do(context.Background(), http.MethodDelete, "/", nil, nil); err != nil {
		t.Fatalf("unexpected error for 204: %v", err)
	}
}

func TestHTTPClient_TextPlain(t *testing.T) {
	metricsBody := "# HELP proof_duration_seconds\nproof_duration_seconds_count 42\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(200)
		fmt.Fprint(w, metricsBody)
	}))
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	var raw string
	if err := h.do(context.Background(), http.MethodGet, "/metrics", nil, &raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw != metricsBody {
		t.Errorf("got %q, want %q", raw, metricsBody)
	}
}

// ── Error status mapping ──────────────────────────────────────────────────────

func TestHTTPClient_401_AuthError(t *testing.T) {
	srv := jsonServer(401, map[string]string{"error": "unauthorized"})
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Errorf("expected *AuthError, got %T: %v", err, err)
	}
}

func TestHTTPClient_404_NotFoundError(t *testing.T) {
	srv := jsonServer(404, map[string]string{"error": "not found"})
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var nfe *NotFoundError
	if !errors.As(err, &nfe) {
		t.Errorf("expected *NotFoundError, got %T: %v", err, err)
	}
}

func TestHTTPClient_409_TreeFullError(t *testing.T) {
	srv := jsonServer(409, map[string]string{"error": "tree full"})
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	err := h.do(context.Background(), http.MethodPost, "/", nil, nil)

	var tfe *TreeFullError
	if !errors.As(err, &tfe) {
		t.Errorf("expected *TreeFullError, got %T: %v", err, err)
	}
}

func TestHTTPClient_429_RateLimitError(t *testing.T) {
	srv := jsonServer(429, map[string]string{"error": "rate limited"},
		func(h http.Header) { h.Set("Retry-After", "2") }, // 2 seconds → 2000 ms
	)
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var rle *RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rle.RetryAfterMs != 2000 {
		t.Errorf("RetryAfterMs = %d, want 2000", rle.RetryAfterMs)
	}
}

func TestHTTPClient_500_ServerError(t *testing.T) {
	srv := jsonServer(500, map[string]string{"error": "internal server error"})
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var se *ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *ServerError, got %T: %v", err, err)
	}
	if se.StatusCode != 500 {
		t.Errorf("StatusCode = %d, want 500", se.StatusCode)
	}
}

// ── Retry logic ───────────────────────────────────────────────────────────────

func TestHTTPClient_Retry_Success(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callCount.Add(1)
		if n < 2 {
			// First call: 503
			w.WriteHeader(503)
			return
		}
		// Second call: 200
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 3, 5*time.Millisecond))

	type result struct{ Status string }
	var got result
	if err := h.do(context.Background(), http.MethodGet, "/", nil, &got); err != nil {
		t.Fatalf("expected success on retry, got: %v", err)
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 calls, got %d", callCount.Load())
	}
}

func TestHTTPClient_Retry_Exhausted(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(503)
	}))
	defer srv.Close()

	// maxRetries=3 → 4 total attempts
	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 3, 5*time.Millisecond))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var se *ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *ServerError after exhausted retries, got %T: %v", err, err)
	}
	if callCount.Load() != 4 {
		t.Errorf("expected 4 attempts (1 + 3 retries), got %d", callCount.Load())
	}
}

func TestHTTPClient_NoRetry_On401(t *testing.T) {
	var callCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(401)
	}))
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 3, 5*time.Millisecond))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	// 401 must NOT be retried — exactly 1 attempt.
	if callCount.Load() != 1 {
		t.Errorf("expected 1 attempt for 401, got %d", callCount.Load())
	}
}

// ── Timeout & cancellation ────────────────────────────────────────────────────

func TestHTTPClient_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // longer than client timeout
		w.WriteHeader(200)
	}))
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(30*time.Millisecond, 0, 0))
	err := h.do(context.Background(), http.MethodGet, "/", nil, nil)

	var ne *NetworkError
	if !errors.As(err, &ne) {
		t.Errorf("expected *NetworkError on timeout, got %T: %v", err, err)
	}
}

func TestHTTPClient_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	err := h.do(ctx, http.MethodGet, "/", nil, nil)

	var ne *NetworkError
	if !errors.As(err, &ne) {
		t.Errorf("expected *NetworkError on cancellation, got %T: %v", err, err)
	}
}

// ── withHeader ────────────────────────────────────────────────────────────────

func TestHTTPClient_WithHeader_ImmutableClone(t *testing.T) {
	h := newHTTPClient("http://localhost", testConfig(5*time.Second, 0, 0))
	clone := h.withHeader("Authorization", "Bearer secret")

	// Original must not have the Authorization header.
	if _, ok := h.headers["Authorization"]; ok {
		t.Error("original httpClient was mutated by withHeader")
	}
	// Clone must have it.
	if clone.headers["Authorization"] != "Bearer secret" {
		t.Errorf("clone missing Authorization header, got: %v", clone.headers["Authorization"])
	}
}

func TestHTTPClient_WithHeader_SendsKey(t *testing.T) {
	var receivedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	h := newHTTPClient(srv.URL, testConfig(5*time.Second, 0, 0))
	authed := h.withHeader("Authorization", "Bearer test-key")

	var dst struct{}
	if err := authed.do(context.Background(), http.MethodGet, "/", nil, &dst); err != nil {
		t.Fatal(err)
	}
	if receivedAuth != "Bearer test-key" {
		t.Errorf("server got Authorization=%q, want %q", receivedAuth, "Bearer test-key")
	}
}
