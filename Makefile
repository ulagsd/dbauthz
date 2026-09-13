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

COMPOSE := docker compose -f deploy/compose/docker-compose.yml

.PHONY: up
up: ## Start the stack: postgres + db-iam api + console
	$(COMPOSE) up --build -d
	@echo
	@echo "  console   http://127.0.0.1:$${DBIAM_CONSOLE_PORT:-8080}"
	@echo "  api       http://127.0.0.1:$${DBIAM_API_PORT:-8081}"
	@echo "  postgres  127.0.0.1:$${DBIAM_PG_PORT:-15432}"

.PHONY: up-dev
up-dev: ## Same, but serve the console live from internal/server/web
	$(COMPOSE) -f deploy/compose/docker-compose.dev.yml up --build -d
	@echo "console: http://127.0.0.1:$${DBIAM_CONSOLE_PORT:-8080} (live from internal/server/web)"

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) ps

.PHONY: down
down: ## Stop the stack, keeping the database volume
	$(COMPOSE) down

.PHONY: down-clean
down-clean: ## Stop the stack and delete the database volume
	$(COMPOSE) down -v

.PHONY: logs
logs:
	$(COMPOSE) logs -f

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
