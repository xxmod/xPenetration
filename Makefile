# Makefile for xPenetration

.PHONY: all build server client clean test

# Go参数
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# 输出目录
BIN_DIR=bin

# 输出文件
SERVER_BINARY=$(BIN_DIR)/xpen-server
CLIENT_BINARY=$(BIN_DIR)/xpen-client

# Windows输出文件
SERVER_BINARY_WIN=$(BIN_DIR)/xpen-server.exe
CLIENT_BINARY_WIN=$(BIN_DIR)/xpen-client.exe

all: build

build: server client

server:
	@echo "Building server..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(SERVER_BINARY) ./cmd/server

client:
	@echo "Building client..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(CLIENT_BINARY) ./cmd/client

# 交叉编译 Windows
build-windows:
	@echo "Building for Windows..."
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(SERVER_BINARY_WIN) ./cmd/server
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(CLIENT_BINARY_WIN) ./cmd/client

# 交叉编译 Linux
build-linux:
	@echo "Building for Linux..."
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(SERVER_BINARY) ./cmd/server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(CLIENT_BINARY) ./cmd/client

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BIN_DIR)

test:
	$(GOTEST) -v ./...

deps:
	$(GOMOD) download
	$(GOMOD) tidy

run-server:
	$(GOBUILD) -o $(SERVER_BINARY) ./cmd/server
	./$(SERVER_BINARY) -c configs/server.yaml

run-client:
	$(GOBUILD) -o $(CLIENT_BINARY) ./cmd/client
	./$(CLIENT_BINARY) -c configs/client.yaml

help:
	@echo "Available targets:"
	@echo "  all           - Build all binaries"
	@echo "  build         - Build server and client"
	@echo "  server        - Build server only"
	@echo "  client        - Build client only"
	@echo "  build-windows - Cross-compile for Windows"
	@echo "  build-linux   - Cross-compile for Linux"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  deps          - Download dependencies"
	@echo "  run-server    - Build and run server"
	@echo "  run-client    - Build and run client"
