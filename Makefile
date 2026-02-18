# Variables
BINARY_NAME=talon
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w \
	-X github.com/dativo-io/talon/internal/cmd.Version=$(VERSION) \
	-X github.com/dativo-io/talon/internal/cmd.Commit=$(COMMIT) \
	-X github.com/dativo-io/talon/internal/cmd.BuildDate=$(BUILD_DATE)"

.PHONY: help build install test test-integration test-e2e test-all lint fmt clean vet mod-tidy check docker-build

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p bin
	@CGO_ENABLED=1 go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/talon/

install: ## Install to $GOPATH/bin
	@CGO_ENABLED=1 go install $(LDFLAGS) ./cmd/talon/

test: ## Run tests (unit + integration). Coverage excludes cmd/talon and internal/testutil.
	@go test -race -coverprofile=coverage.out $$(go list ./internal/... ./cmd/... | grep -v internal/testutil | grep -v 'cmd/talon')
	@go test -race -tags=integration ./tests/integration/...

test-coverage: test ## Show test coverage
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration: ## Run integration tests
	@go test -race -tags=integration ./tests/integration/...

test-e2e: ## Run e2e tests (builds binary in TestMain)
	@go test -tags=e2e -timeout 5m ./tests/e2e/...

test-all: test test-e2e ## Run unit, integration, and e2e tests

lint: ## Run linter
	@golangci-lint run ./...

fmt: ## Format code
	@gofumpt -w .
	@goimports -w .

vet: ## Run go vet
	@go vet ./...

mod-tidy: ## Tidy go modules
	@go mod tidy

clean: ## Clean build artifacts
	@rm -rf bin/ coverage.out coverage.html dist/

check: lint vet test ## Run all checks (CI equivalent)

docker-build: ## Build Docker image
	@docker build -t $(BINARY_NAME):$(VERSION) .

docker-run: ## Run in Docker
	@docker run --rm -p 8080:8080 $(BINARY_NAME):$(VERSION)

.DEFAULT_GOAL := help
