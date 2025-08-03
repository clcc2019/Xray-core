#!/bin/bash

# Xray-core Linux AMD64 构建脚本
# 支持eBPF优化功能

set -e

# 构建配置
export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64

# 版本信息
VERSION=$(git describe --tags --always --dirty)
COMMIT=$(git rev-parse --short HEAD)
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 构建标签
BUILD_TAGS="linux,amd64"

# 构建目录
BUILD_DIR="build"
OUTPUT_NAME="xray-linux-amd64"

echo "========================================="
echo "构建 Xray-core Linux AMD64 版本"
echo "版本: $VERSION"
echo "提交: $COMMIT"
echo "构建时间: $BUILD_TIME"
echo "构建标签: $BUILD_TAGS"
echo "========================================="

# 创建构建目录
mkdir -p $BUILD_DIR

# 构建主程序
echo "正在构建主程序..."
go build -v \
    -tags "$BUILD_TAGS" \
    -ldflags "-X github.com/xtls/xray-core/core.version=$VERSION \
              -X github.com/xtls/xray-core/core.build=$COMMIT \
              -X github.com/xtls/xray-core/core.buildDate=$BUILD_TIME \
              -s -w" \
    -o "$BUILD_DIR/$OUTPUT_NAME" \
    ./main

# 验证构建结果
if [ -f "$BUILD_DIR/$OUTPUT_NAME" ]; then
    echo "构建成功！"
    echo "输出文件: $BUILD_DIR/$OUTPUT_NAME"
    
    # 显示文件信息
    ls -lh "$BUILD_DIR/$OUTPUT_NAME"
    
    # 显示文件类型
    file "$BUILD_DIR/$OUTPUT_NAME"
    
    # 测试基本功能
    echo "测试基本功能..."
    if ./"$BUILD_DIR/$OUTPUT_NAME" version; then
        echo "版本检查通过！"
    else
        echo "警告: 版本检查失败"
    fi
else
    echo "构建失败！"
    exit 1
fi

echo "========================================="
echo "构建完成！"
echo "可执行文件位置: $BUILD_DIR/$OUTPUT_NAME"
echo "========================================="