# TCP+REALITY eBPF Accelerator Makefile

# 编译器设置
CC = clang
CFLAGS = -O2 -g -Wall -target bpf -c -fno-stack-protector
INCLUDES = -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

# 目标文件
TCP_REALITY_TARGET = tcp_reality_accelerator.o
TARGETS = $(TCP_REALITY_TARGET)

# 源文件
TCP_REALITY_SOURCES = tcp_reality_accelerator.c

# 默认目标
all: $(TARGETS)

# 编译TCP+REALITY eBPF加速器
$(TCP_REALITY_TARGET): $(TCP_REALITY_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# 清理
clean:
	rm -f $(TARGETS)
	rm -f *.o

# 安装依赖
deps:
	# 安装clang和LLVM
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(shell uname -r)

# 测试编译
test-compile: $(TCP_REALITY_TARGET)
	# 验证eBPF程序
	sudo bpftool prog load $(TCP_REALITY_TARGET) /sys/fs/bpf/xray/tcp_reality_test
	sudo bpftool prog list | grep tcp_reality_test
	sudo bpftool prog unload /sys/fs/bpf/xray/tcp_reality_test

# 加载程序
load: $(TCP_REALITY_TARGET)
	# 创建xray目录
	sudo mkdir -p /sys/fs/bpf/xray/
	
	# 创建maps
	sudo bpftool map create /sys/fs/bpf/xray/tcp_connections type lru_hash key 8 value 64 entries 10000 name tcp_connections
	sudo bpftool map create /sys/fs/bpf/xray/reality_sessions type lru_hash key 8 value 72 entries 5000 name reality_sessions
	sudo bpftool map create /sys/fs/bpf/xray/tcp_syn_cache type lru_hash key 8 value 24 entries 2000 name tcp_syn_cache
	sudo bpftool map create /sys/fs/bpf/xray/hot_connections type hash key 8 value 1 entries 1000 name hot_connections
	sudo bpftool map create /sys/fs/bpf/xray/tcp_reality_stats_map type array key 4 value 64 entries 1 name tcp_reality_stats_map
	sudo bpftool map create /sys/fs/bpf/xray/tcp_reality_config_map type array key 4 value 24 entries 1 name tcp_reality_config_map
	
	# 加载XDP程序
	sudo bpftool prog load $(TCP_REALITY_TARGET) /sys/fs/bpf/xray/tcp_reality_xdp type xdp pinmaps /sys/fs/bpf/xray/
	
	# 加载TC程序
	sudo bpftool prog load $(TCP_REALITY_TARGET) /sys/fs/bpf/xray/tcp_reality_tc type tc pinmaps /sys/fs/bpf/xray/
	
	echo "TCP+REALITY eBPF程序加载成功"

# 卸载程序
unload:
	# 卸载程序
	sudo bpftool prog unload /sys/fs/bpf/xray/tcp_reality_xdp 2>/dev/null || true
	sudo bpftool prog unload /sys/fs/bpf/xray/tcp_reality_tc 2>/dev/null || true
	
	# 删除maps
	sudo bpftool map delete pinned /sys/fs/bpf/xray/tcp_connections 2>/dev/null || true
	sudo bpftool map delete pinned /sys/fs/bpf/xray/reality_sessions 2>/dev/null || true
	sudo bpftool map delete pinned /sys/fs/bpf/xray/tcp_syn_cache 2>/dev/null || true
	sudo bpftool map delete pinned /sys/fs/bpf/xray/hot_connections 2>/dev/null || true
	sudo bpftool map delete pinned /sys/fs/bpf/xray/tcp_reality_stats_map 2>/dev/null || true
	sudo bpftool map delete pinned /sys/fs/bpf/xray/tcp_reality_config_map 2>/dev/null || true
	
	echo "TCP+REALITY eBPF程序卸载完成"

# 查看状态
status:
	echo "=== TCP+REALITY eBPF程序状态 ==="
	sudo bpftool prog list | grep tcp_reality || echo "无TCP+REALITY程序运行"
	echo
	echo "=== TCP+REALITY Maps状态 ==="
	sudo bpftool map list | grep -E "(tcp_connections|reality_sessions|tcp_syn_cache|hot_connections)" || echo "无TCP+REALITY Maps"

# 帮助
help:
	@echo "可用的目标:"
	@echo "  all          - 编译eBPF程序"
	@echo "  clean        - 清理生成的文件"
	@echo "  deps         - 安装依赖"
	@echo "  test-compile - 测试编译和加载"
	@echo "  load         - 加载eBPF程序和Maps"
	@echo "  unload       - 卸载eBPF程序和Maps"
	@echo "  status       - 查看运行状态"
	@echo "  help         - 显示此帮助信息"

.PHONY: all clean deps test-compile load unload status help