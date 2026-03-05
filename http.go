package zkp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxBackoff = 30 * time.Second

// httpClient is the internal HTTP transport layer. Not exported (BP-08).
// Safe for concurrent use — do not mutate fields after construction.
type httpClient struct {
	baseURL    string
	headers    map[string]string // includes Authorization when API key set
	timeout    time.Duration
	maxRetries int
	retryDelay time.Duration
	client     *http.Client
}

// newHTTPClient constructs an httpClient from a base URL and client config.
// The trailing slash is normalised away from baseURL.
// Default headers Content-Type and Accept are set (H-10).
func newHTTPClient(baseURL string, cfg *clientConfig) *httpClient {
	return &httpClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
		timeout:    cfg.timeout,
		maxRetries: cfg.maxRetries,
		retryDelay: cfg.retryDelay,
		// No Timeout on the http.Client itself — per-attempt timeouts are
		// applied via context.WithTimeout in each doOnce call (H-04).
		client: &http.Client{},
	}
}

// withHeader returns a shallow clone of h with one additional header set (H-09).
// The original httpClient is not modified (immutable clone pattern).
// Used by SetAPIKey to attach the Authorization header without mutating in-flight requests.
func (h *httpClient) withHeader(key, value string) *httpClient {
	clone := *h
	clone.headers = make(map[string]string, len(h.headers)+1)
	for k, v := range h.headers {
		clone.headers[k] = v
	}
	clone.headers[key] = value
	return &clone
}

// do executes an HTTP request with automatic retries and exponential backoff.
//
// body is JSON-encoded as the request body when non-nil.
// dst controls response decoding:
//   - *string   → raw response body written as-is (used for text/plain Metrics endpoint)
//   - nil        → response body discarded (used when no payload is expected)
//   - any other  → JSON-decoded into dst
//
// Returns a typed error on failure (SEC-02: API key never included in errors).
func (h *httpClient) do(ctx context.Context, method, path string, body, dst any) error {
	var lastErr error

	for attempt := 0; attempt <= h.maxRetries; attempt++ {
		// Wait before retry (not before the first attempt).
		if attempt > 0 {
			delay := h.retryBackoff(attempt-1, lastErr)
			select {
			case <-ctx.Done():
				return &NetworkError{
					ZKPError: ZKPError{Code: ErrCodeNetwork, Message: "request cancelled while waiting to retry"},
					Cause:    ctx.Err(),
				}
			case <-time.After(delay):
			}
		}

		err := h.doOnce(ctx, method, path, body, dst)
		if err == nil {
			return nil
		}
		if isRetryable(err) {
			lastErr = err
			continue
		}
		return err // non-retryable — return immediately
	}
	return lastErr
}

// doOnce performs a single HTTP attempt with a per-attempt context timeout (H-04).
func (h *httpClient) doOnce(ctx context.Context, method, path string, body, dst any) error {
	// Per-attempt deadline (H-04).
	attemptCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Build request body.
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return &ValidationError{ZKPError: ZKPError{
				Code:    ErrCodeValidation,
				Message: fmt.Sprintf("marshal request body: %v", err),
			}}
		}
		bodyReader = bytes.NewReader(data)
	}

	// Construct URL.
	url := h.baseURL
	if path != "" {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		url += path
	}

	req, err := http.NewRequestWithContext(attemptCtx, method, url, bodyReader)
	if err != nil {
		return &NetworkError{
			ZKPError: ZKPError{Code: ErrCodeNetwork, Message: fmt.Sprintf("build request: %v", err)},
			Cause:    err,
		}
	}

	// Apply headers (H-10). Authorization header is in h.headers when key is set.
	// SEC-02: headers are applied here but never echoed into error messages.
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		// Strip any context from the error that could contain auth details.
		return &NetworkError{
			ZKPError: ZKPError{Code: ErrCodeNetwork, Message: "request failed: transport error"},
			Cause:    err,
		}
	}
	defer resp.Body.Close()

	// 204 No Content — success with no body (H-08).
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	// Map non-2xx status codes to typed errors (H-06).
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return statusError(resp)
	}

	// Success — decode response body.
	if dst == nil {
		return nil
	}

	// text/plain response (Metrics endpoint) — H-07.
	if s, ok := dst.(*string); ok {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return &NetworkError{
				ZKPError: ZKPError{Code: ErrCodeNetwork, Message: "read response body"},
				Cause:    err,
			}
		}
		*s = string(raw)
		return nil
	}

	// JSON decode.
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return &APIError{
			ZKPError:   ZKPError{Code: ErrCodeAPI, Message: fmt.Sprintf("decode response: %v", err)},
			StatusCode: resp.StatusCode,
		}
	}
	return nil
}

// statusError maps an HTTP response with a non-2xx status to a typed error (H-06).
// SEC-02: request headers (including Authorization) are never included in the error.
func statusError(resp *http.Response) error {
	// Try to read a short error message from the body.
	msg := http.StatusText(resp.StatusCode)
	if body, err := io.ReadAll(io.LimitReader(resp.Body, 512)); err == nil && len(body) > 0 {
		// Extract "error" field from JSON if possible.
		var envelope struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &envelope) == nil && envelope.Error != "" {
			msg = envelope.Error
		}
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized: // 401
		return &AuthError{ZKPError: ZKPError{Code: ErrCodeAuth, Message: msg}}

	case http.StatusNotFound: // 404
		return &NotFoundError{ZKPError: ZKPError{Code: ErrCodeNotFound, Message: msg}}

	case http.StatusConflict: // 409
		return &TreeFullError{ZKPError: ZKPError{Code: ErrCodeTreeFull, Message: msg}}

	case http.StatusTooManyRequests: // 429
		retryAfterMs := parseRetryAfterMs(resp.Header.Get("Retry-After"))
		return &RateLimitError{
			ZKPError:     ZKPError{Code: ErrCodeRateLimit, Message: msg},
			RetryAfterMs: retryAfterMs,
		}

	default:
		if resp.StatusCode >= 500 {
			return &ServerError{
				ZKPError:   ZKPError{Code: ErrCodeServer, Message: msg},
				StatusCode: resp.StatusCode,
			}
		}
		return &APIError{
			ZKPError:   ZKPError{Code: ErrCodeAPI, Message: msg},
			StatusCode: resp.StatusCode,
		}
	}
}

// parseRetryAfterMs parses the Retry-After header value (seconds) into milliseconds.
// Returns 0 if the header is absent or unparseable.
func parseRetryAfterMs(header string) int {
	if header == "" {
		return 0
	}
	secs, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || secs < 0 {
		return 0
	}
	return secs * 1000
}

// isRetryable reports whether err should trigger a retry attempt.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	switch e := err.(type) {
	case *ServerError:
		// Retry on 500, 502, 503, 504 — not on other 5xx codes.
		return e.StatusCode == 500 || e.StatusCode == 502 ||
			e.StatusCode == 503 || e.StatusCode == 504
	case *RateLimitError:
		return true
	case *NetworkError:
		return true
	}
	return false
}

// retryBackoff computes the wait duration before attempt number `attempt` (0-indexed).
// Uses exponential backoff capped at maxBackoff, with ±10% jitter.
// For RateLimitError, uses the RetryAfterMs value instead when it is larger.
func (h *httpClient) retryBackoff(attempt int, lastErr error) time.Duration {
	base := h.retryDelay * (1 << uint(attempt))
	if base > maxBackoff {
		base = maxBackoff
	}

	// For rate limit errors, honour the Retry-After header if it specifies a
	// longer delay than the computed backoff.
	if rl, ok := lastErr.(*RateLimitError); ok && rl.RetryAfterMs > 0 {
		headerDelay := time.Duration(rl.RetryAfterMs) * time.Millisecond
		if headerDelay > base {
			base = headerDelay
		}
	}

	// Add ±10% jitter to spread thundering herds.
	jitter := time.Duration(rand.Int63n(int64(base)/5+1)) - base/10
	d := base + jitter
	if d < 0 {
		d = 0
	}
	return d
}
