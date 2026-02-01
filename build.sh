#!/bin/bash

echo "Building xPenetration..."

# 创建输出目录
mkdir -p bin

# 从 .env 文件读取版本号
VERSION=$(grep -E '^version=' .env | cut -d'=' -f2)
if [ -z "$VERSION" ]; then
    VERSION="dev"
fi
echo "Version: $VERSION"

# 设置 ldflags
LDFLAGS="-X main.version=${VERSION}"

# 编译服务端（不含 ACME）
echo "Building server (no ACME)..."
go build -ldflags "$LDFLAGS" -o bin/xpen-server ./cmd/server
if [ $? -ne 0 ]; then
    echo "Failed to build server"
    exit 1
fi

# 编译带 ACME 的服务端
echo "Building server with ACME..."
go build -tags acme -ldflags "$LDFLAGS" -o bin/xpen-server-with-acme ./cmd/server
if [ $? -ne 0 ]; then
    echo "Failed to build server with ACME"
    exit 1
fi

# 编译客户端
echo "Building client..."
go build -ldflags "$LDFLAGS" -o bin/xpen-client ./cmd/client
if [ $? -ne 0 ]; then
    echo "Failed to build client"
    exit 1
fi

echo ""
echo "Build completed successfully!"
echo "Output:"
echo "  bin/xpen-server"
echo "  bin/xpen-server-with-acme"
echo "  bin/xpen-client"
