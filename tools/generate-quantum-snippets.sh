#!/bin/bash

# 🚀 Xray 量子增强配置片段生成器
# 一键生成量子配置片段，方便集成到现有配置

set -e

echo "========================================"
echo "🚀 Xray 量子增强配置片段生成器"
echo "========================================"

# 默认参数
OUTPUT_DIR="./snippets"
SHOW_KEYS=false
MODE="all"
FORMAT="yaml"

# 显示帮助信息
show_help() {
    echo "使用方法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -o, --output DIR          输出目录 (默认: ./snippets)"
    echo "  -m, --mode MODE           生成模式: server, client, env, all (默认: all)"
    echo "  -f, --format FORMAT       输出格式: yaml, json, txt (默认: yaml)"
    echo "  -k, --show-keys           显示生成的密钥"
    echo "  -h, --help                显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0"
    echo "  $0 -k"
    echo "  $0 -m client -f yaml"
    echo "  $0 -o ./my-snippets -m all"
    echo ""
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -k|--show-keys)
            SHOW_KEYS=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "❌ 未知选项: $1"
            show_help
            exit 1
            ;;
    esac
done

# 检查量子片段生成器是否存在
if [[ ! -f "./tools/quantum-snippet-generator" ]]; then
    echo "🔧 构建量子片段生成器..."
    cd tools
    go build -o quantum-snippet-generator quantum-snippet-generator.go
    cd ..
fi

# 构建命令
CMD="./tools/quantum-snippet-generator"
CMD="$CMD -output $OUTPUT_DIR"
CMD="$CMD -mode $MODE"
CMD="$CMD -format $FORMAT"

if [[ "$SHOW_KEYS" == "true" ]]; then
    CMD="$CMD -show-keys"
fi

echo "🎯 生成参数:"
echo "   输出目录: $OUTPUT_DIR"
echo "   生成模式: $MODE"
echo "   输出格式: $FORMAT"
echo "   显示密钥: $SHOW_KEYS"
echo ""

# 执行生成命令
echo "🚀 开始生成量子配置片段..."
eval $CMD

echo ""
echo "========================================"
echo "✅ 量子配置片段生成完成！"
echo "========================================"
echo ""
echo "📁 生成的片段文件:"
if [[ "$MODE" == "all" || "$MODE" == "server" ]]; then
    echo "   服务端片段: $OUTPUT_DIR/server-quantum-snippet.$FORMAT"
fi
if [[ "$MODE" == "all" || "$MODE" == "client" ]]; then
    echo "   客户端片段: $OUTPUT_DIR/client-quantum-snippet.$FORMAT"
fi
if [[ "$MODE" == "all" || "$MODE" == "env" ]]; then
    echo "   环境变量片段: $OUTPUT_DIR/env-quantum-snippet.$FORMAT"
fi
echo ""
echo "🚀 集成步骤:"
echo "1. 将服务端片段添加到服务端 REALITY 配置的 realitySettings 部分"
echo "2. 将客户端片段添加到客户端 REALITY 配置的 realitySettings 部分"
echo "3. 设置环境变量启用 eBPF 和量子加速"
echo "4. 重启 Xray 服务"
echo ""
echo "📋 快速集成命令:"
echo "   # 查看服务端片段"
echo "   cat $OUTPUT_DIR/server-quantum-snippet.$FORMAT"
echo ""
echo "   # 查看客户端片段"
echo "   cat $OUTPUT_DIR/client-quantum-snippet.$FORMAT"
echo ""
echo "   # 查看环境变量片段"
echo "   cat $OUTPUT_DIR/env-quantum-snippet.$FORMAT"
echo ""
echo "🔧 验证集成:"
echo "   # 检查配置语法"
echo "   xray test -c /path/to/your/config.yaml"
echo ""
echo "   # 启动服务并检查日志"
echo "   export XRAY_EBPF=1"
echo "   export XRAY_QUANTUM=1"
echo "   xray run -c /path/to/your/config.yaml"
echo "" 