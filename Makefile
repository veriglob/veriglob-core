.PHONY: all build clean test wallet holder issuer verifier fmt vet help

BINARY_DIR=bin

all: fmt vet build test

build: wallet holder issuer verifier

wallet:
	@echo "Building wallet CLI..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/wallet ./cmd/wallet

holder:
	@echo "Building holder CLI..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/holder ./cmd/holder

issuer:
	@echo "Building issuer CLI..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/issuer ./cmd/issuer

verifier:
	@echo "Building verifier CLI..."
	@mkdir -p $(BINARY_DIR)
	go build -o $(BINARY_DIR)/verifier ./cmd/verifier

test:
	@echo "Running tests..."
	go test -v ./...

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Vetting code..."
	go vet ./...

clean:
	@echo "Cleaning up..."
	rm -rf $(BINARY_DIR)

help:
	@echo "Veriglob Protocol Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Format, vet, build, and test"
	@echo "  build     - Build all CLIs (wallet, holder, issuer, verifier)"
	@echo "  test      - Run all tests"
	@echo "  fmt       - Format Go code"
	@echo "  vet       - Run Go vet"
	@echo "  clean     - Remove bin directory"
	@echo "  help      - Show this help message"