# XTLS Vision eBPF Makefile

CC = clang
LLC = llc
BPFTOOL = bpftool

# 编译标志
CFLAGS = -O2 -target bpf -c
INCLUDES = -I/usr/include -I/usr/include/x86_64-linux-gnu

# 源文件
SOURCES = xtls_vision_accelerator.c
OBJECTS = $(SOURCES:.c=.o)

# 目标文件
TARGETS = xtls_vision_accelerator.o

.PHONY: all clean install uninstall

all: $(TARGETS)

# 编译入站加速器
xtls_vision_accelerator.o: xtls_vision_accelerator.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<



# 验证eBPF程序
verify: $(TARGETS)
	@echo "Verifying eBPF programs..."
	$(BPFTOOL) prog load xtls_vision_accelerator.o /sys/fs/bpf/xtls_vision_inbound
	@echo "Verification completed"

# 安装eBPF程序
install: $(TARGETS)
	@echo "Installing XTLS Vision eBPF programs..."
	mkdir -p /usr/local/lib/xray-ebpf
	cp $(TARGETS) /usr/local/lib/xray-ebpf/
	@echo "Installation completed"

# 卸载eBPF程序
uninstall:
	@echo "Uninstalling XTLS Vision eBPF programs..."
	rm -f /usr/local/lib/xray-ebpf/xtls_vision_accelerator.o
	rmdir /usr/local/lib/xray-ebpf 2>/dev/null || true
	@echo "Uninstallation completed"

# 清理编译文件
clean:
	rm -f $(TARGETS)
	rm -f /sys/fs/bpf/xtls_vision_inbound

# 检查依赖
check-deps:
	@echo "Checking dependencies..."
	@which $(CC) > /dev/null || (echo "Error: clang not found" && exit 1)
	@which $(LLC) > /dev/null || (echo "Error: llc not found" && exit 1)
	@which $(BPFTOOL) > /dev/null || (echo "Error: bpftool not found" && exit 1)
	@echo "All dependencies found"

# 显示帮助
help:
	@echo "XTLS Vision eBPF Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build all eBPF programs"
	@echo "  verify     - Verify eBPF programs"
	@echo "  install    - Install eBPF programs"
	@echo "  uninstall  - Uninstall eBPF programs"
	@echo "  clean      - Clean build files"
	@echo "  check-deps - Check build dependencies"
	@echo "  help       - Show this help" 