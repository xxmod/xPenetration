# Makefile for xPenetration

.PHONY: all build server client clean test

# 从 .env 文件读取版本号
VERSION := $(shell grep -E '^version=' .env | cut -d'=' -f2)
ifeq ($(VERSION),)
	VERSION := dev
endif

# Go参数
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# LDFLAGS 用于注入版本号
LDFLAGS=-X main.version=$(VERSION)

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
	@echo "Building server... (version: $(VERSION))"
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(SERVER_BINARY) ./cmd/server

client:
	@echo "Building client... (version: $(VERSION))"
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CLIENT_BINARY) ./cmd/client

# 交叉编译 Windows
build-windows:
	@echo "Building for Windows... (version: $(VERSION))"
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(SERVER_BINARY_WIN) ./cmd/server
	GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CLIENT_BINARY_WIN) ./cmd/client

# 交叉编译 Linux
build-linux:
	@echo "Building for Linux... (version: $(VERSION))"
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(SERVER_BINARY) ./cmd/server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CLIENT_BINARY) ./cmd/client

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
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(SERVER_BINARY) ./cmd/server
	./$(SERVER_BINARY) -c configs/server.yaml

run-client:
	$(GOBUILD) -ldflags "$(LDFLAGS)" -o $(CLIENT_BINARY) ./cmd/client
	./$(CLIENT_BINARY) -c configs/client.yaml

version:
	@echo "Version: $(VERSION)"

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
	@echo "  version       - Show current version"
