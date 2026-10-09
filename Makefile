# SPDX-License-Identifier: Apache-2.0

SHELL := /bin/bash
.DEFAULT_GOAL := help

BIN       := bin/dbauthz
PKG       := github.com/ulagsd/dbauthz
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X $(PKG)/internal/version.version=$(VERSION)

# All production builds are pure Go. See docs/STACK.md section 1.
export CGO_ENABLED := 0

# Release targets. Cross-compiling here checks that every target still builds.
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the dbauthz binary into bin/
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/dbauthz

.PHONY: test
test: ## Run unit tests
	go test ./...

.PHONY: test-race
test-race: ## Run unit tests with the race detector (needs cgo, tests only)
	CGO_ENABLED=1 go test -race ./...

.PHONY: cover
cover: ## Run tests with a coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: fmt
fmt: ## Format code
	golangci-lint fmt

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	go mod tidy

.PHONY: spdx
spdx: ## Check licence headers
	./scripts/check-spdx.sh

.PHONY: cross
cross: ## Build for every release platform without cgo
	@set -e; for p in $(PLATFORMS); do \
		echo "building $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} go build -trimpath -o /dev/null ./cmd/dbauthz; \
	done

.PHONY: check
check: spdx lint test cross ## Run every check CI runs

.PHONY: clean
clean: ## Remove build output
	rm -rf bin dist coverage.out
