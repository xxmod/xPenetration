#!/bin/bash

echo "Building xPenetration..."

# 创建输出目录
mkdir -p bin

# 编译服务端
echo "Building server..."
go build -o bin/xpen-server ./cmd/server
if [ $? -ne 0 ]; then
    echo "Failed to build server"
    exit 1
fi

# 编译客户端
echo "Building client..."
go build -o bin/xpen-client ./cmd/client
if [ $? -ne 0 ]; then
    echo "Failed to build client"
    exit 1
fi

echo ""
echo "Build completed successfully!"
echo "Output:"
echo "  bin/xpen-server"
echo "  bin/xpen-client"
