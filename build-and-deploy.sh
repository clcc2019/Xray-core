#!/bin/bash

# Xray eBPF构建脚本
# 在macOS上构建Linux版本

set -e

echo "========================================"
echo "Xray eBPF 构建脚本"
echo "========================================"

# 检测操作系统
OS=$(uname -s)

if [ "$OS" = "Darwin" ]; then
    echo "🖥️  在macOS上构建Linux版本..."
    
    # 设置环境变量
    export GOOS=linux
    export GOARCH=amd64
    export CGO_ENABLED=0
    
    # 创建build目录
    echo "📦 创建build目录..."
    mkdir -p build
    
    # 构建Xray
    echo "📦 构建Xray可执行文件..."
    go build -o build/xray-linux-amd64-ebpf ./main
    
    # 复制eBPF源文件
    echo "📦 复制eBPF源文件..."
    mkdir -p build/app/dns
    mkdir -p build/app/router
    mkdir -p build/app/stats
    mkdir -p build/app/loadbalancer
    mkdir -p build/transport/internet
    cp -r app/dns/ebpf build/app/dns/
    cp -r app/router/ebpf build/app/router/
    cp -r app/stats/ebpf build/app/stats/
    cp -r app/loadbalancer build/app/
    cp -r transport/internet/ebpf build/transport/internet/
    cp -r transport/internet/tcp/ebpf build/transport/internet/tcp/
    
    # 创建eBPF挂载脚本
    echo "📦 创建eBPF挂载脚本..."
    cat > build/mount-ebpf.sh << 'EOF'
#!/bin/bash
set -e

echo "🚀 挂载eBPF程序..."

# 检查是否为root
if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用sudo运行此脚本"
    exit 1
fi

# 定义清理函数
cleanup_ebpf_by_name() {
    local pattern="$1"
    echo "   清理匹配 '$pattern' 的eBPF程序..."
    
    # 清理程序
    bpftool prog show 2>/dev/null | grep "$pattern" | awk '{print $1}' | sed 's/://' | while read id; do
        if [ -n "$id" ] && [ "$id" != "0" ]; then
            bpftool prog unload id "$id" 2>/dev/null || true
        fi
    done
}

# 清理历史eBPF程序和Maps
echo "🧹 清理历史eBPF程序和Maps..."

# 清理pinned文件
echo "   清理pinned eBPF文件..."
for prog in /sys/fs/bpf/xray/*; do
    [ -e "$prog" ] && rm -f "$prog" 2>/dev/null || true
done

# 清理特定名称的eBPF程序
cleanup_ebpf_by_name "xray"
cleanup_ebpf_by_name "dns_cache"
cleanup_ebpf_by_name "dns_accelerator"
cleanup_ebpf_by_name "geoip_match"
cleanup_ebpf_by_name "geosite_match"
cleanup_ebpf_by_name "connection_tracker"

# 确保xray目录存在
mkdir -p /sys/fs/bpf/xray 2>/dev/null || true
echo "   ✅ 历史eBPF程序清理完成"

# 检查并安装依赖
echo "📦 检查并安装依赖..."

# 检查依赖缓存文件
DEPS_CACHE="/tmp/.xray_ebpf_deps_checked"
CACHE_VALID=0

# 如果缓存文件存在且在24小时内，认为依赖检查有效
if [ -f "$DEPS_CACHE" ]; then
    CACHE_AGE=$(($(date +%s) - $(stat -c %Y "$DEPS_CACHE" 2>/dev/null || echo 0)))
    if [ "$CACHE_AGE" -lt 86400 ]; then  # 24小时 = 86400秒
        CACHE_VALID=1
        echo "   ✅ 依赖检查缓存有效，跳过重复检查"
    fi
fi

if [ "$CACHE_VALID" -eq 0 ]; then
    # 检查关键依赖是否已安装
    MISSING_DEPS=""
    echo "   检查eBPF编译环境..."
    
    command -v clang >/dev/null 2>&1 || MISSING_DEPS="$MISSING_DEPS clang"
    command -v llvm-config >/dev/null 2>&1 || MISSING_DEPS="$MISSING_DEPS llvm"
    command -v make >/dev/null 2>&1 || MISSING_DEPS="$MISSING_DEPS make"
    command -v bpftool >/dev/null 2>&1 || MISSING_DEPS="$MISSING_DEPS libbpf-dev"
    [ -f /usr/include/bpf/bpf.h ] || MISSING_DEPS="$MISSING_DEPS libbpf-dev"
    [ -f /usr/include/linux/bpf.h ] || MISSING_DEPS="$MISSING_DEPS linux-headers-$(uname -r)"

    if [ -n "$MISSING_DEPS" ]; then
        echo "   需要安装缺失的依赖: $MISSING_DEPS"
        apt update
        apt install -y clang llvm make gcc-multilib libc6-dev-i386 linux-headers-$(uname -r) libbpf-dev
        # 安装成功后创建缓存文件
        touch "$DEPS_CACHE"
        echo "   ✅ 依赖安装完成"
    else
        echo "   ✅ 所有依赖已安装"
        # 创建缓存文件
        touch "$DEPS_CACHE"
    fi
fi

# 编译eBPF程序
echo "🔨 编译eBPF程序..."

# 保存当前目录
BUILD_ROOT=\\\$(pwd)

# 编译DNS eBPF程序
echo "   编译DNS eBPF程序..."
if [ -d "app/dns/ebpf" ]; then
    cd app/dns/ebpf
    make clean 2>/dev/null || true
    if [ -f dns_cache_simple.c ]; then
        echo "   使用简化版本编译DNS缓存eBPF程序..."
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o dns_cache.o dns_cache_simple.c
    else
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o dns_cache.o dns_cache.c
    fi
    echo "   ✅ DNS缓存eBPF程序编译成功"
    cd "\\\$BUILD_ROOT"
fi

# 编译GeoIP/GeoSite eBPF程序
echo "   编译路由eBPF程序..."
if [ -d "app/router/ebpf" ]; then
    cd app/router/ebpf
    make clean 2>/dev/null || true
    if [ -f geoip_matcher_dynamic.c ]; then
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o geoip_matcher.o geoip_matcher_dynamic.c
    else
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o geoip_matcher.o geoip_matcher.c
    fi
    echo "   ✅ GeoIP eBPF程序编译成功"

    if [ -f geosite_matcher_dynamic.c ]; then
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o geosite_matcher.o geosite_matcher_dynamic.c
    else
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o geosite_matcher.o geosite_matcher.c
    fi
    echo "   ✅ GeoSite eBPF程序编译成功"
    cd "\\\$BUILD_ROOT"
fi

# 编译统计eBPF程序
echo "   编译统计eBPF程序..."
if [ -d "app/stats/ebpf" ]; then
    cd app/stats/ebpf
    if [ -f connection_tracker.c ]; then
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o connection_tracker.o connection_tracker.c
        echo "   ✅ 连接跟踪eBPF程序编译成功"
    fi
    cd "\\\$BUILD_ROOT"
fi

# 编译传输层eBPF程序
echo "   编译传输层eBPF程序..."
if [ -d "transport/internet/ebpf" ]; then
    cd transport/internet/ebpf
    if [ -f xray_accelerator.c ]; then
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o xray_accelerator.o xray_accelerator.c
        echo "   ✅ Xray加速器eBPF程序编译成功"
    fi
    cd "\\\$BUILD_ROOT"
fi

# 编译TCP+REALITY eBPF程序
echo "   编译TCP+REALITY eBPF程序..."
if [ -d "transport/internet/tcp/ebpf" ]; then
    cd transport/internet/tcp/ebpf
    if [ -f tcp_reality_accelerator.c ]; then
        clang -O2 -g -Wall -target bpf -c -fno-stack-protector -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o tcp_reality_accelerator.o tcp_reality_accelerator.c
        echo "   ✅ TCP+REALITY eBPF程序编译成功"
    fi
    cd "\\\$BUILD_ROOT"
fi

# 挂载eBPF
echo "📥 挂载eBPF程序..."
mkdir -p /sys/fs/bpf
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
mkdir -p /sys/fs/bpf/xray

# 创建eBPF maps
echo "   创建基础maps..."
bpftool map create /sys/fs/bpf/xray/dns_cache type hash key 8 value 4 entries 50000 name dns_cache 2>/dev/null || true
bpftool map create /sys/fs/bpf/xray/geoip_v4 type hash key 4 value 1 entries 10000 name geoip_v4 2>/dev/null || true
bpftool map create /sys/fs/bpf/xray/geoip_v6 type hash key 8 value 1 entries 10000 name geoip_v6 2>/dev/null || true
bpftool map create /sys/fs/bpf/xray/connection_map type hash key 8 value 64 entries 65536 name connection_map 2>/dev/null || true

# 加载eBPF程序
echo "   加载eBPF程序..."
if [ -f app/dns/ebpf/dns_cache.o ]; then
    bpftool prog load app/dns/ebpf/dns_cache.o /sys/fs/bpf/xray/dns_cache_prog 2>/dev/null || true
    echo "   ✅ DNS缓存eBPF程序加载成功"
fi

if [ -f app/router/ebpf/geoip_matcher.o ]; then
    bpftool prog load app/router/ebpf/geoip_matcher.o /sys/fs/bpf/xray/geoip_matcher 2>/dev/null || true
    echo "   ✅ GeoIP eBPF程序加载成功"
fi

if [ -f app/router/ebpf/geosite_matcher.o ]; then
    bpftool prog load app/router/ebpf/geosite_matcher.o /sys/fs/bpf/xray/geosite_matcher 2>/dev/null || true
    echo "   ✅ GeoSite eBPF程序加载成功"
fi

# 设置Xray权限
echo "🔐 设置Xray权限..."
chmod +x xray-linux-amd64-ebpf
setcap cap_bpf+ep ./xray-linux-amd64-ebpf 2>/dev/null || true

echo "✅ eBPF挂载完成！"
echo "📊 检查状态:"
echo "   bpftool prog list | grep xray"
echo "   bpftool map list | grep xray"

EOF
    
    chmod +x build/mount-ebpf.sh
    
    echo "✅ 构建完成！"
    echo "📦 build目录内容:"
    echo "   xray-linux-amd64-ebpf - Xray可执行文件"
    echo "   app/dns/ebpf/ - DNS eBPF源文件"
    echo "   app/router/ebpf/ - GeoIP & GeoSite eBPF源文件"
    echo "   app/stats/ebpf/ - 统计eBPF源文件"
    echo "   transport/internet/ebpf/ - 传输eBPF源文件"
    echo "   mount-ebpf.sh - eBPF挂载脚本"
    echo "🚀 将整个build目录上传到Linux服务器，然后运行:"
    echo "   rsync -r build root@your-server:/root/ --delete"
    echo "   ssh root@your-server \"cd /root/build/ && bash /root/build/mount-ebpf.sh\""
    echo ""
    echo "📋 eBPF加速功能:"
    echo "   🚀 零配置自动优化 - 无需修改现有配置"
    echo "   🧠 智能路由学习 - 自动学习热点路由"
    echo "   ⚡ XDP快速通道 - 内核层包处理"
    echo "   📊 透明流量统计 - 自动统计和优化"
    echo "   🌐 GeoSite eBPF加速 - 域名匹配内核加速"
    echo "   📍 GeoIP eBPF优化 - IP地理位置内核匹配"
    echo "   🔄 自动fallback - eBPF失败时无缝回退"
    echo ""
    echo "🎯 使用方法:"
    echo "   无需任何配置修改，只需设置环境变量:"
    echo "   export XRAY_EBPF=1"
    echo "   或使用命令行参数: xray -ebpf"
    
else
    echo "❌ 请在macOS上运行此脚本"
    exit 1
fi