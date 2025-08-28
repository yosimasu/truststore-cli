# truststore CLI Makefile

# Variables
BINARY_NAME=truststore
BUILD_DIR=dist
MAIN_PATH=./cmd/truststore

# Default target
.DEFAULT_GOAL := help

## help: Show this help message
.PHONY: help
help:
	@echo "Available targets:"
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ": "}; {sub(/^## /, "", $$1); printf "  %-20s %s\n", $$1, $$2}'

## build: Build binary for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) for current platform..."
	@mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_PATH)
	@echo "Built: $(BUILD_DIR)/$(BINARY_NAME)"

## build-all: Build binaries for all platforms
.PHONY: build-all
build-all:
	@echo "Building $(BINARY_NAME) for all platforms..."
	@mkdir -p $(BUILD_DIR)/darwin/amd64 $(BUILD_DIR)/darwin/arm64
	@mkdir -p $(BUILD_DIR)/linux/amd64 $(BUILD_DIR)/linux/arm64
	@mkdir -p $(BUILD_DIR)/windows/amd64
	
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/darwin/amd64/$(BINARY_NAME) $(MAIN_PATH)
	GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/darwin/arm64/$(BINARY_NAME) $(MAIN_PATH)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/linux/amd64/$(BINARY_NAME) $(MAIN_PATH)
	GOOS=linux GOARCH=arm64 go build -o $(BUILD_DIR)/linux/arm64/$(BINARY_NAME) $(MAIN_PATH)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/windows/amd64/$(BINARY_NAME).exe $(MAIN_PATH)
	@echo "Cross-platform build complete"

## test: Run all tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

## test-coverage: Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

## lint: Run golangci-lint
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run

## clean: Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)/
	rm -f coverage.out coverage.html

## deps: Download and tidy dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

## install: Install binary to $GOPATH/bin
.PHONY: install
install:
	@echo "Installing $(BINARY_NAME)..."
	go install $(MAIN_PATH)