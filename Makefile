.PHONY: test test-cover lint tidy check

# Run all tests with race detector (MANDATORY after any change).
test:
	go test -race ./... -count=1 -timeout 60s

# Test with coverage report — opens coverage.html when done.
test-cover:
	go test -race -cover -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Vet + lint.
lint:
	go vet ./...
	golangci-lint run ./...

# go mod tidy + verify (ensures go.sum is not stale).
tidy:
	go mod tidy
	go mod verify

# Full pre-commit gate: tidy → lint → test.
check: tidy lint test
