# XTLS Vision eBPF 程序编译Makefile
# 用于编译服务端入站优化的eBPF程序

CC = clang
CFLAGS = -O2 -g -Wall -target bpf -c
INCLUDES = -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu

# 目标文件
TARGETS = xtls_vision_accelerator.o

# 默认目标
all: $(TARGETS)

# 编译XTLS Vision加速器
xtls_vision_accelerator.o: xtls_vision_accelerator.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $<

# 清理
clean:
	rm -f *.o

# 安装到系统目录
install: all
	install -m 644 *.o /usr/lib/xray/ebpf/

# 卸载
uninstall:
	rm -f /usr/lib/xray/ebpf/*.o

.PHONY: all clean install uninstall