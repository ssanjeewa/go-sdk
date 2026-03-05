package zkp

import "time"

// ClientOption is a functional option for configuring a ZKPClient.
type ClientOption func(*clientConfig)

// clientConfig holds resolved configuration for a ZKPClient.
// All fields have sensible defaults via defaultConfig().
type clientConfig struct {
	apiKey     string
	timeout    time.Duration
	maxRetries int
	retryDelay time.Duration
}

// defaultConfig returns a clientConfig with production-safe defaults.
func defaultConfig() *clientConfig {
	return &clientConfig{
		timeout:    30 * time.Second,
		maxRetries: 3,
		retryDelay: 200 * time.Millisecond,
	}
}

// WithAPIKey sets the Bearer token used to authenticate requests.
func WithAPIKey(key string) ClientOption {
	return func(c *clientConfig) { c.apiKey = key }
}

// WithTimeout sets the per-attempt HTTP request timeout.
// Default: 30s.
func WithTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.timeout = d }
}

// WithMaxRetries sets the maximum number of retry attempts after a retryable
// error (5xx, 429, transport). Default: 3.
func WithMaxRetries(n int) ClientOption {
	return func(c *clientConfig) { c.maxRetries = n }
}

// WithRetryDelay sets the base delay for exponential backoff between retries.
// Default: 200ms.
func WithRetryDelay(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.retryDelay = d }
}
