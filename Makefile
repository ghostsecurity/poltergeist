# Polttergeist Secret Scanner Makefile
default: help

# Build configuration
BINARY_NAME = poltergeist
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-X main.version=$(VERSION)"

.PHONY: help
help: ## Show this help
	@echo "Usage: make [target]\n"
	@cat ${MAKEFILE_LIST} | grep "[#]# " | grep -v grep | sort | column -t -s '##' | sed -e 's/^/ /'
	@echo ""

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=1 go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/poltergeist

.PHONY: deps
deps: ## Install Go dependencies
	go mod download
	go mod tidy

.PHONY: clean
clean: ## Clean build artifacts
	rm -f $(BINARY_NAME)
	go clean

.PHONY: test
test: ## Run all tests
	go test -v ./...

.PHONY: test-rules
test-rules: ## Run validation tests on packaged rules
	go test -run ^TestRulesValidation$$ ./pkg -count=1

.PHONY: lint
lint: ## Run linter
	@which golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

.PHONY: docs
docs: ## Generate rules documentation
	go run cmd/docs/main.go > docs/rules.md

.PHONY: benchmarks
benchmarks: ## Run full benchmarks with both engines
	go run cmd/benchmark/main.go

.PHONY: benchmarks-go
benchmarks-go: ## Run benchmarks with Go engine
	go run cmd/benchmark/main.go -engine go

.PHONY: benchmarks-hyperscan
benchmarks-hyperscan: ## Run benchmarks with Hyperscan engine
	go run cmd/benchmark/main.go -engine hyperscan

.PHONY: build-static-linux
build-static-linux: ## Build statically linked Linux binary
	CGO_ENABLED=1 GOOS=linux go build -a $(LDFLAGS) -linkmode external -extldflags "-static" -o $(BINARY_NAME) ./cmd/poltergeist

.PHONY: build-vectorscan
build-vectorscan: ## Build Vectorscan static library for current platform
	bash scripts/build-vectorscan.sh

.PHONY: release
release: ## Create a release using GoReleaser
	goreleaser release --clean

.PHONY: release-snapshot
release-snapshot: ## Create a snapshot release (no tagging required)
	goreleaser build --snapshot --clean --single-target
