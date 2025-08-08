# DNS eBPF Accelerator Makefile

# 编译器设置
CC = clang
CFLAGS = -O2 -g -Wall -target bpf -c
INCLUDES = -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

# 目标文件
DNS_CACHE_TARGET = dns_cache.o
DNS_ACCELERATOR_TARGET = dns_accelerator.o
DNS_ACCELERATOR_SIMPLE_TARGET = dns_accelerator_simple.o
DNS_ROUTER_TC_TARGET = dns_router_tc.o
TARGETS = $(DNS_CACHE_TARGET) $(DNS_ACCELERATOR_TARGET) $(DNS_ACCELERATOR_SIMPLE_TARGET) $(DNS_ROUTER_TC_TARGET)

# 源文件
DNS_CACHE_SOURCES = dns_cache.c
DNS_ACCELERATOR_SOURCES = dns_accelerator.c
DNS_ACCELERATOR_SIMPLE_SOURCES = dns_accelerator_simple.c
DNS_ROUTER_TC_SOURCES = dns_router_tc.c

# 默认目标
all: $(TARGETS)

# 简化版本优先（推荐用于生产环境）
simple: $(DNS_CACHE_TARGET) $(DNS_ACCELERATOR_SIMPLE_TARGET)
	@echo "✅ DNS eBPF programs (simple version) compiled successfully"

# 编译基础DNS缓存eBPF程序
$(DNS_CACHE_TARGET): $(DNS_CACHE_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<
	@echo "✅ DNS Cache eBPF program compiled successfully"

# 编译高级DNS加速器eBPF程序  
$(DNS_ACCELERATOR_TARGET): $(DNS_ACCELERATOR_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<
	@echo "✅ DNS Accelerator eBPF program compiled successfully"

# 编译简化DNS加速器eBPF程序（避免栈溢出）
$(DNS_ACCELERATOR_SIMPLE_TARGET): $(DNS_ACCELERATOR_SIMPLE_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<
	@echo "✅ DNS Accelerator Simple eBPF program compiled successfully"

# 编译 DNS TC 路由/异常检测程序
$(DNS_ROUTER_TC_TARGET): $(DNS_ROUTER_TC_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<
	@echo "✅ DNS Router TC eBPF program compiled successfully"

# 生成Go代码（需要bpf2go工具）
generate:
	@echo "🔧 Generating Go bindings..."
	bpf2go -cc clang -cflags "$(CFLAGS)" -target bpf \
		-type dns_cache_entry \
		-type dns_server_info \
		-type malicious_domain_entry \
		-type dns_query_stats \
		-type dns_perf_metrics \
		dns_cache ./$(DNS_CACHE_SOURCES)
	bpf2go -cc clang -cflags "$(CFLAGS)" -target bpf \
		-type dns_cache_entry \
		-type dns_server_info \
		-type malicious_domain_entry \
		-type dns_query_stats \
		-type dns_perf_metrics \
		-type dns_query_request \
		dns_accelerator ./$(DNS_ACCELERATOR_SOURCES)
	@echo "✅ Go bindings generated successfully"

# 清理
clean:
	rm -f $(TARGETS)
	rm -f dns_cache_bpfel.go dns_cache_bpfel.o dns_cache_bpfeb.go dns_cache_bpfeb.o
	rm -f dns_accelerator_bpfel.go dns_accelerator_bpfel.o dns_accelerator_bpfeb.go dns_accelerator_bpfeb.o
	rm -f dns_accelerator_simple_bpfel.go dns_accelerator_simple_bpfel.o dns_accelerator_simple_bpfeb.go dns_accelerator_simple_bpfeb.o
	@echo "🧹 Cleaned up build artifacts"

# 安装依赖
deps:
	@echo "📦 Installing dependencies..."
	# 安装clang和LLVM
	sudo apt-get update
	sudo apt-get install -y clang llvm make gcc-multilib libc6-dev-i386
	# 安装Linux headers
	sudo apt-get install -y linux-headers-$(shell uname -r)
	# 安装libbpf开发包
	sudo apt-get install -y libbpf-dev
	@echo "✅ Dependencies installed"

# 测试编译
test: clean all
	@echo "🧪 Testing compilation..."
	@if [ -f $(DNS_CACHE_TARGET) ] && [ -f $(DNS_ACCELERATOR_TARGET) ]; then \
		echo "✅ All DNS eBPF programs compiled successfully"; \
	else \
		echo "❌ Compilation test failed"; \
		exit 1; \
	fi

# 检查程序信息
info:
	@echo "📊 eBPF Program Information:"
	@if [ -f $(DNS_CACHE_TARGET) ]; then \
		echo "📁 DNS Cache Program:"; \
		file $(DNS_CACHE_TARGET); \
		du -h $(DNS_CACHE_TARGET); \
	fi
	@if [ -f $(DNS_ACCELERATOR_TARGET) ]; then \
		echo "📁 DNS Accelerator Program:"; \
		file $(DNS_ACCELERATOR_TARGET); \
		du -h $(DNS_ACCELERATOR_TARGET); \
	fi

# 验证eBPF程序
verify: $(TARGETS)
	@echo "🔍 Verifying eBPF programs..."
	@for target in $(TARGETS); do \
		if command -v bpftool > /dev/null 2>&1; then \
			echo "Verifying $$target..."; \
			bpftool prog load $$target /sys/fs/bpf/test_$$target type xdp 2>/dev/null && \
			bpftool prog delete pinned /sys/fs/bpf/test_$$target 2>/dev/null || true; \
		else \
			echo "⚠️  bpftool not available, skipping verification"; \
		fi \
	done
	@echo "✅ eBPF program verification completed"

# 开发模式 - 监控文件变化并自动重编译
dev:
	@echo "🔧 Development mode - watching for changes..."
	@while true; do \
		inotifywait -q -e modify,create,delete $(DNS_CACHE_SOURCES) $(DNS_ACCELERATOR_SOURCES) 2>/dev/null; \
		echo "📝 Source file changed, recompiling..."; \
		$(MAKE) clean && $(MAKE) all; \
		echo "✅ Recompilation completed"; \
	done

# 性能分析
profile: $(TARGETS)
	@echo "📈 Performance analysis:"
	@echo "DNS Cache Program:"
	@objdump -h $(DNS_CACHE_TARGET) | grep -E "(\.text|\.data|\.bss)"
	@echo "DNS Accelerator Program:"  
	@objdump -h $(DNS_ACCELERATOR_TARGET) | grep -E "(\.text|\.data|\.bss)"

# 帮助信息
help:
	@echo "🔧 DNS eBPF Makefile Commands:"
	@echo "  all        - Compile all DNS eBPF programs"
	@echo "  clean      - Remove compiled files"
	@echo "  deps       - Install build dependencies"
	@echo "  test       - Test compilation"
	@echo "  info       - Show program information"
	@echo "  verify     - Verify eBPF programs"
	@echo "  generate   - Generate Go bindings"
	@echo "  dev        - Development mode with auto-rebuild"
	@echo "  profile    - Performance analysis"
	@echo "  help       - Show this help message"

# 调试版本
debug: CFLAGS += -DDEBUG -g3
debug: clean all
	@echo "🐛 Debug version compiled with enhanced debugging"

# 优化版本
release: CFLAGS += -DNDEBUG -O3
release: clean all
	@echo "🚀 Release version compiled with optimizations"

# Docker构建
docker-build:
	@echo "🐳 Building DNS eBPF in Docker..."
	docker run --rm -v $(PWD):/src -w /src \
		ubuntu:22.04 \
		bash -c "apt-get update && \
				 apt-get install -y clang llvm libbpf-dev && \
				 make clean && make all"
	@echo "✅ Docker build completed"

# 安装到系统
install: $(TARGETS)
	@echo "📦 Installing DNS eBPF programs..."
	sudo mkdir -p /usr/local/lib/xray/dns/
	sudo cp $(TARGETS) /usr/local/lib/xray/dns/
	sudo chmod 644 /usr/local/lib/xray/dns/*
	@echo "✅ DNS eBPF programs installed to /usr/local/lib/xray/dns/"

# 卸载
uninstall:
	@echo "🗑️  Uninstalling DNS eBPF programs..."
	sudo rm -f /usr/local/lib/xray/dns/$(TARGETS)
	@echo "✅ DNS eBPF programs uninstalled"

.PHONY: all clean deps test info verify generate dev profile help debug release docker-build install uninstall