BINARY   := dbiam
PKG      := github.com/ulagsd/db-iam
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := check

.PHONY: check
check: fmt vet lint test ## Run everything CI runs

.PHONY: build
build: ## Build the CLI
	go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/dbiam

.PHONY: test
test: ## Run unit tests with race detection
	go test -race -shuffle=on ./...

.PHONY: cover
cover: ## Report coverage
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: fmt
fmt: ## Check formatting
	@out=$$(gofmt -l . | grep -v '^bin/' || true); \
	 if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint: ## Lint, if golangci-lint is installed
	@command -v golangci-lint >/dev/null 2>&1 \
	  && golangci-lint run ./... \
	  || echo "golangci-lint not installed, skipping"

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: clean
clean:
	rm -rf bin coverage.out

.PHONY: help
help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  %-10s %s\n", $$1, $$2}'
