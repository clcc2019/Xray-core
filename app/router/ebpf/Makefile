# eBPF GeoIP Matcher Makefile

# 编译器设置
CC = clang
CFLAGS = -O2 -g -Wall -target bpf -c
INCLUDES = -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

# 目标文件
GEOIP_TARGET = geoip_matcher.o
GEOSITE_TARGET = geosite_matcher.o
GEOIP_DYNAMIC_TARGET = geoip_matcher_dynamic.o
GEOSITE_DYNAMIC_TARGET = geosite_matcher_dynamic.o
TARGETS = $(GEOIP_TARGET) $(GEOSITE_TARGET) $(GEOIP_DYNAMIC_TARGET) $(GEOSITE_DYNAMIC_TARGET)

# 源文件
GEOIP_SOURCES = geoip_matcher.c
GEOSITE_SOURCES = geosite_matcher.c
GEOIP_DYNAMIC_SOURCES = geoip_matcher_dynamic.c
GEOSITE_DYNAMIC_SOURCES = geosite_matcher_dynamic.c

# 默认目标
all: $(TARGETS)

# 编译GeoIP eBPF程序
$(GEOIP_TARGET): $(GEOIP_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# 编译GeoSite eBPF程序
$(GEOSITE_TARGET): $(GEOSITE_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# 编译动态GeoIP eBPF程序（优化版）
$(GEOIP_DYNAMIC_TARGET): $(GEOIP_DYNAMIC_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# 编译动态GeoSite eBPF程序（优化版）
$(GEOSITE_DYNAMIC_TARGET): $(GEOSITE_DYNAMIC_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# 只编译动态版本（推荐）
dynamic: $(GEOIP_DYNAMIC_TARGET) $(GEOSITE_DYNAMIC_TARGET)

# 生成Go代码（需要bpf2go工具）
generate:
	bpf2go -cc clang -cflags "-O2 -g" -target bpf -type cidr_entry -type geoip_v6_entry ebpf ./geoip_matcher.c

# 清理
clean:
	rm -f $(TARGETS)
	rm -f ebpf_bpfel.go ebpf_bpfel.o ebpf_bpfeb.go ebpf_bpfeb.o

# 安装依赖
deps:
	# 安装clang和LLVM
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r)
	
	# 安装bpf2go工具
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

# 测试编译
test-compile: $(TARGET)
	# 验证eBPF程序
	sudo bpftool prog load $(TARGET) /sys/fs/bpf/geoip_matcher
	sudo bpftool prog list | grep geoip_matcher
	sudo bpftool prog unload /sys/fs/bpf/geoip_matcher

# 性能测试
benchmark: $(TARGET)
	# 加载eBPF程序
	sudo bpftool prog load $(TARGET) /sys/fs/bpf/geoip_matcher
	
	# 创建测试映射表
	sudo bpftool map create /sys/fs/bpf/geoip_v4_map type hash key 4 value 1 entries 100000
	sudo bpftool map create /sys/fs/bpf/cidr_v4_map type hash key 4 value 4 entries 10000
	
	# 添加测试数据
	echo "Adding test CIDR ranges..."
	for i in {1..1000}; do
		network=$(printf "192.168.%d.0" $((i % 256)))
		sudo bpftool map update pinned /sys/fs/bpf/cidr_v4_map key $network value 24 1 0 0
	done
	
	# 运行性能测试
	echo "Running performance test..."
	time for i in {1..10000}; do
		ip=$(printf "192.168.%d.%d" $((i / 256 % 256)) $((i % 256)))
		sudo bpftool map lookup pinned /sys/fs/bpf/cidr_v4_map key $ip
	done
	
	# 清理
	sudo bpftool map delete pinned /sys/fs/bpf/geoip_v4_map
	sudo bpftool map delete pinned /sys/fs/bpf/cidr_v4_map
	sudo bpftool prog unload /sys/fs/bpf/geoip_matcher

# 帮助
help:
	@echo "可用的目标:"
	@echo "  all          - 编译eBPF程序"
	@echo "  generate     - 生成Go代码"
	@echo "  clean        - 清理生成的文件"
	@echo "  deps         - 安装依赖"
	@echo "  test-compile - 测试编译和加载"
	@echo "  benchmark    - 性能测试"
	@echo "  help         - 显示此帮助信息"

.PHONY: all clean deps test-compile benchmark help generate dynamic 