# eBPF连接状态跟踪Makefile

# 编译器和工具
CLANG := clang
LLVM_STRIP := llvm-strip
BPF2GO := bpf2go

# 编译标志
CLANG_FLAGS := -O2 -g -Wall \
	-target bpf \
	-D__TARGET_ARCH_x86

# 源文件和目标文件
BPF_SOURCE := connection_tracker.c
BPF_OBJECT := connection_tracker.o
GO_PACKAGE := ebpf

# 检查依赖
.PHONY: check-deps
check-deps:
	@echo "Checking eBPF build dependencies..."
	@which $(CLANG) > /dev/null || (echo "Error: clang not found" && exit 1)
	@which $(LLVM_STRIP) > /dev/null || (echo "Error: llvm-strip not found" && exit 1)
	@which $(BPF2GO) > /dev/null || (echo "Error: bpf2go not found, run: go install github.com/cilium/ebpf/cmd/bpf2go@latest" && exit 1)
	@echo "All dependencies are available"

# 安装依赖
.PHONY: deps
deps:
	@echo "Installing eBPF build dependencies..."
	@echo "Please install the following packages manually:"
	@echo "Ubuntu/Debian: sudo apt-get install -y clang llvm libbpf-dev linux-headers-\$$(uname -r)"
	@echo "CentOS/RHEL: sudo yum install -y clang llvm libbpf-devel kernel-headers"
	@echo "Arch Linux: sudo pacman -S clang llvm libbpf linux-headers"
	@echo ""
	@echo "Install bpf2go tool:"
	@echo "go install github.com/cilium/ebpf/cmd/bpf2go@latest"

# 编译eBPF程序
$(BPF_OBJECT): $(BPF_SOURCE)
	@echo "Compiling eBPF program: $<"
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# 生成Go绑定代码
.PHONY: generate
generate: $(BPF_OBJECT)
	@echo "Generating Go bindings..."
	$(BPF2GO) -cc $(CLANG) -cflags "$(CLANG_FLAGS)" \
		ConnectionTracker $(BPF_SOURCE)

# 编译所有目标
.PHONY: all
all: check-deps $(BPF_OBJECT) generate

# 测试编译
.PHONY: test-compile
test-compile: all
	@echo "Testing Go compilation..."
	go build -v .

# 验证eBPF程序
.PHONY: verify
verify: $(BPF_OBJECT)
	@echo "Verifying eBPF program..."
	@if command -v bpftool > /dev/null 2>&1; then \
		bpftool --legacy prog load $(BPF_OBJECT) /sys/fs/bpf/test_connection_tracker 2>/dev/null && \
		echo "eBPF program verification successful" && \
		rm -f /sys/fs/bpf/test_connection_tracker || \
		echo "eBPF program verification failed, trying without legacy flag..." && \
		bpftool prog load $(BPF_OBJECT) /sys/fs/bpf/test_connection_tracker 2>/dev/null && \
		echo "eBPF program verification successful" && \
		rm -f /sys/fs/bpf/test_connection_tracker || \
		echo "eBPF program verification failed"; \
	else \
		echo "bpftool not available, skipping verification"; \
	fi

# 清理生成的文件
.PHONY: clean
clean:
	@echo "Cleaning generated files..."
	rm -f $(BPF_OBJECT)
	rm -f connection_tracker_*.go
	rm -f connection_tracker_*.o

# 检查代码风格
.PHONY: lint
lint:
	@echo "Checking C code style..."
	@if command -v clang-format > /dev/null 2>&1; then \
		clang-format --dry-run --Werror $(BPF_SOURCE); \
	else \
		echo "clang-format not available, skipping style check"; \
	fi

# 显示帮助信息
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  deps         - Show dependency installation instructions"
	@echo "  check-deps   - Check if all dependencies are available"
	@echo "  all          - Build everything (default target)"
	@echo "  generate     - Generate Go bindings from eBPF program"
	@echo "  test-compile - Test compilation of Go code"
	@echo "  verify       - Verify eBPF program can be loaded"
	@echo "  clean        - Clean generated files"
	@echo "  lint         - Check code style"
	@echo "  help         - Show this help message"

# 默认目标
.DEFAULT_GOAL := all