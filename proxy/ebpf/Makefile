# Xray Proxy eBPF 加速器构建

TARGET_ARCH ?= x86_64
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool

CFLAGS := -O2 -g -Wall -target bpf -c -fno-stack-protector
INCLUDES := -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

all: proxy_accelerator.o clean-gen

proxy_accelerator.o: proxy_accelerator.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -o $@ $<
	@echo "✅ Proxy eBPF程序编译成功"

clean:
	rm -f *.o
	rm -f *_bpfel.go *_bpfel.o *_bpfeb.go *_bpfeb.o
	@echo "🧹 Cleaned up build artifacts"

clean-gen:
	rm -f *_bpfel.go *_bpfel.o *_bpfeb.go *_bpfeb.o

install: proxy_accelerator.o
	@echo "📦 安装Proxy eBPF程序..."
	sudo mkdir -p /sys/fs/bpf/xray
	
	# 创建proxy专用Maps
	sudo $(BPFTOOL) map create /sys/fs/bpf/xray/proxy_connections \
		type lru_hash key 8 value 64 entries 16384 name proxy_connections 2>/dev/null || true
	sudo $(BPFTOOL) map create /sys/fs/bpf/xray/tls_sessions \
		type lru_hash key 8 value 96 entries 8192 name tls_sessions 2>/dev/null || true
	sudo $(BPFTOOL) map create /sys/fs/bpf/xray/proxy_stats_map \
		type array key 4 value 64 entries 1 name proxy_stats_map 2>/dev/null || true
	
	# 加载proxy程序
	sudo $(BPFTOOL) prog load proxy_accelerator.o /sys/fs/bpf/xray/proxy_accelerator_xdp \
		type xdp 2>/dev/null && echo "   ✅ Proxy XDP程序加载成功" || echo "   ❌ Proxy XDP程序加载失败"
	sudo $(BPFTOOL) prog load proxy_accelerator.o /sys/fs/bpf/xray/proxy_accelerator_tc \
		type sched_cls 2>/dev/null && echo "   ✅ Proxy TC程序加载成功" || echo "   ❌ Proxy TC程序加载失败"
	
	@echo "🎉 Proxy eBPF加速器安装完成！"

uninstall:
	@echo "🗑️  卸载Proxy eBPF程序..."
	sudo rm -f /sys/fs/bpf/xray/proxy_accelerator_xdp
	sudo rm -f /sys/fs/bpf/xray/proxy_accelerator_tc
	sudo rm -f /sys/fs/bpf/xray/proxy_connections
	sudo rm -f /sys/fs/bpf/xray/tls_sessions
	sudo rm -f /sys/fs/bpf/xray/proxy_stats_map
	@echo "✅ Proxy eBPF程序卸载完成"

status:
	@echo "📊 Proxy eBPF程序状态:"
	@sudo $(BPFTOOL) prog show | grep -E "proxy_accelerator|xray" || echo "   未找到已加载的程序"
	@echo ""
	@echo "📋 Proxy eBPF Maps状态:"
	@sudo $(BPFTOOL) map show | grep -E "proxy|tls" || echo "   未找到相关maps"

.PHONY: all clean clean-gen install uninstall status