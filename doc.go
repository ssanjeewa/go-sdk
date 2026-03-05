// Package zkp provides a Go client for the ZKP middleware service.
//
// # Overview
//
// The ZKP middleware issues zero-knowledge credentials and generates Groth16
// proofs for the ZKClaimUpload protocol on Arbitrum Sepolia. This SDK wraps
// the HTTP API with idiomatic Go types, input validation, and automatic retries.
//
// # Basic usage
//
//	client, err := zkp.NewClient("https://middleware.example.com",
//	    zkp.WithAPIKey("your-api-key"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	resp, err := client.Health(context.Background())
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(resp.Status)
//
// # Error handling
//
// All methods return typed errors. Use errors.As to inspect the error type:
//
//	_, err := client.IssueCredential(ctx, req)
//	var authErr *zkp.AuthError
//	var rateLimitErr *zkp.RateLimitError
//	switch {
//	case errors.As(err, &authErr):
//	    fmt.Println("invalid API key")
//	case errors.As(err, &rateLimitErr):
//	    fmt.Printf("retry after %dms\n", rateLimitErr.RetryAfterMs)
//	}
//
// # Concurrency
//
// ZKPClient is safe for concurrent use by multiple goroutines.
package zkp
