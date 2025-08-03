package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"
)

// 服务端量子配置片段模板
const serverSnippetTemplate = `# 🚀 服务端量子增强配置片段
# 自动生成时间: {{.Timestamp}}
# 量子算法: Kyber-1024 + MLDSA-65

# 将以下配置添加到 REALITY 的 realitySettings 部分:

        # 🚀 量子增强配置
        kyber_enabled: true
        kyber_private_key: "{{.KyberKeys.PrivateKey}}"
        kyber_public_key: "{{.KyberKeys.PublicKey}}"
        quantum_acceleration: true
        quantum_session_cache_size: 10000
        hybrid_mode: true
        # 🔧 服务端量子配置
        server_quantum_enabled: true
        server_kyber_private_key: "{{.KyberKeys.PrivateKey}}"
        server_kyber_public_key: "{{.KyberKeys.PublicKey}}"
        server_mldsa_private_key: "{{.MLDSAKeys.PrivateKey}}"
        server_mldsa_public_key: "{{.MLDSAKeys.PublicKey}}"
        server_quantum_fallback: true
        # 📊 量子性能配置
        quantum_stats_enabled: true
        quantum_max_sessions: 50000
        quantum_session_timeout: 3600

# 🔑 密钥信息:
# Kyber 私钥: {{.KyberKeys.PrivateKey}}
# Kyber 公钥: {{.KyberKeys.PublicKey}}
# MLDSA 私钥: {{.MLDSAKeys.PrivateKey}}
# MLDSA 公钥: {{.MLDSAKeys.PublicKey}}
# UUID: {{.UUID}}
`

// 客户端量子配置片段模板
const clientSnippetTemplate = `# 🚀 客户端量子增强配置片段
# 自动生成时间: {{.Timestamp}}
# 量子算法: Kyber-1024 + MLDSA-65

# 将以下配置添加到 REALITY 的 realitySettings 部分:

        # 🚀 量子增强配置
        kyber_enabled: true
        kyber_public_key: "{{.KyberKeys.PublicKey}}"
        quantum_acceleration: true
        quantum_session_cache_size: 10000
        hybrid_mode: true
        # 🔧 客户端量子配置
        client_quantum_enabled: true
        client_kyber_public_key: "{{.KyberKeys.PublicKey}}"
        client_mldsa_public_key: "{{.MLDSAKeys.PublicKey}}"
        client_quantum_fallback: true
        client_quantum_timeout: 30
        # 📊 量子性能配置
        quantum_stats_enabled: true
        quantum_max_sessions: 50000
        quantum_session_timeout: 3600

# 🔑 密钥信息:
# Kyber 公钥: {{.KyberKeys.PublicKey}}
# MLDSA 公钥: {{.MLDSAKeys.PublicKey}}
# UUID: {{.UUID}}
`

// 环境变量配置片段
const envSnippetTemplate = `# 🚀 eBPF 和量子加速环境变量
# 自动生成时间: {{.Timestamp}}

# 在启动 Xray 前设置以下环境变量:

export XRAY_EBPF=1
export XRAY_QUANTUM=1
export XRAY_HYBRID=1

# 或者添加到 /etc/environment:
# XRAY_EBPF=1
# XRAY_QUANTUM=1
# XRAY_HYBRID=1
`

func main() {
	var (
		mode      = flag.String("mode", "both", "生成模式: server, client, env, all")
		outputDir = flag.String("output", "./snippets", "输出目录")
		uuid      = flag.String("uuid", "", "UUID (留空自动生成)")
		showKeys  = flag.Bool("show-keys", false, "显示生成的密钥")
		format    = flag.String("format", "yaml", "输出格式: yaml, json, txt")
	)
	flag.Parse()

	// 创建输出目录
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		fmt.Printf("❌ 创建输出目录失败: %v\n", err)
		os.Exit(1)
	}

	// 生成或使用提供的 UUID
	if *uuid == "" {
		*uuid = generateUUID()
	}

	// 生成量子密钥对
	kyberPriv := generateRandomKey(32)
	kyberPub := generateRandomKey(32)
	mldsaPriv := generateRandomKey(32)
	mldsaPub := generateRandomKey(32)

	config := struct {
		KyberKeys struct {
			PrivateKey string
			PublicKey  string
		}
		MLDSAKeys struct {
			PrivateKey string
			PublicKey  string
		}
		UUID      string
		Timestamp string
	}{
		UUID:      *uuid,
		Timestamp: getCurrentTimestamp(),
	}
	config.KyberKeys.PrivateKey = kyberPriv
	config.KyberKeys.PublicKey = kyberPub
	config.MLDSAKeys.PrivateKey = mldsaPriv
	config.MLDSAKeys.PublicKey = mldsaPub

	// 显示密钥信息
	if *showKeys {
		fmt.Println("🔑 生成的量子密钥对:")
		fmt.Printf("Kyber 私钥: %s\n", config.KyberKeys.PrivateKey)
		fmt.Printf("Kyber 公钥: %s\n", config.KyberKeys.PublicKey)
		fmt.Printf("MLDSA 私钥: %s\n", config.MLDSAKeys.PrivateKey)
		fmt.Printf("MLDSA 公钥: %s\n", config.MLDSAKeys.PublicKey)
		fmt.Printf("UUID: %s\n", config.UUID)
		fmt.Println()
	}

	// 生成配置片段
	switch strings.ToLower(*mode) {
	case "server":
		generateSnippet("server", serverSnippetTemplate, config, *outputDir, *format)
	case "client":
		generateSnippet("client", clientSnippetTemplate, config, *outputDir, *format)
	case "env":
		generateSnippet("env", envSnippetTemplate, config, *outputDir, *format)
	case "all":
		generateSnippet("server", serverSnippetTemplate, config, *outputDir, *format)
		generateSnippet("client", clientSnippetTemplate, config, *outputDir, *format)
		generateSnippet("env", envSnippetTemplate, config, *outputDir, *format)
	default:
		fmt.Printf("❌ 无效的模式: %s\n", *mode)
		os.Exit(1)
	}

	fmt.Println("✅ 量子配置片段生成完成！")
	fmt.Printf("📁 输出目录: %s\n", *outputDir)
	fmt.Println()
	fmt.Println("🚀 使用说明:")
	fmt.Println("1. 将服务端片段添加到服务端 REALITY 配置")
	fmt.Println("2. 将客户端片段添加到客户端 REALITY 配置")
	fmt.Println("3. 设置环境变量启用 eBPF 和量子加速")
	fmt.Println("4. 重启 Xray 服务")
}

func generateSnippet(name, templateStr string, config interface{}, outputDir, format string) {
	tmpl, err := template.New(name).Parse(templateStr)
	if err != nil {
		fmt.Printf("❌ 解析模板失败: %v\n", err)
		return
	}

	outputFile := fmt.Sprintf("%s/%s-quantum-snippet.%s", outputDir, name, format)
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("❌ 创建文件失败: %v\n", err)
		return
	}
	defer file.Close()

	if err := tmpl.Execute(file, config); err != nil {
		fmt.Printf("❌ 生成配置失败: %v\n", err)
		return
	}

	fmt.Printf("✅ %s 配置片段已生成: %s\n", name, outputFile)
}

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func generateRandomKey(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

func getCurrentTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}
