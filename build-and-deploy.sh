#!/bin/bash

# Xray eBPF 构建和部署脚本
# 支持多平台构建和自动部署

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# 构建配置
BUILD_DIR="build"
BINARY_NAME="xray"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "unknown")

# 支持的平台
PLATFORMS=(
    "linux/amd64"
    "darwin/amd64"
    "darwin/arm64"
)

echo "========================================"
echo "Xray eBPF 构建脚本 v$VERSION"
echo "========================================"

# 检测操作系统
OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
    log_info "在 macOS 上构建多平台版本..."
else
    log_warning "当前在 $OS 上运行，建议在 macOS 上构建"
fi

# 创建构建目录
log_info "创建构建目录..."
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR

# 构建函数
build_platform() {
    local platform=$1
    local os=$(echo $platform | cut -d'/' -f1)
    local arch=$(echo $platform | cut -d'/' -f2)
    local output="$BUILD_DIR/${BINARY_NAME}-${os}-${arch}"
    
    if [ "$os" = "linux" ]; then
        output="${output}-ebpf"
    fi
    
    log_info "构建 $os/$arch 版本..."
    
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build \
        -v \
        -ldflags="-s -w -X main.version=$VERSION" \
        -o "$output" \
        ./main
    
    if [ $? -eq 0 ]; then
        log_success "$os/$arch 版本构建成功"
    else
        log_error "$os/$arch 版本构建失败"
        exit 1
    fi
}

# 构建所有平台
for platform in "${PLATFORMS[@]}"; do
    build_platform $platform
done

# 复制eBPF源文件
log_info "复制eBPF源文件..."
mkdir -p $BUILD_DIR/app/dns $BUILD_DIR/app/router $BUILD_DIR/app/stats $BUILD_DIR/transport/internet $BUILD_DIR/transport/internet/tcp $BUILD_DIR/proxy

# 分别拷贝（不存在则跳过，不中断）
[ -d app/dns/ebpf ] && cp -r app/dns/ebpf $BUILD_DIR/app/dns/ || true
[ -d app/router/ebpf ] && cp -r app/router/ebpf $BUILD_DIR/app/router/ || true
[ -d app/stats/ebpf ] && cp -r app/stats/ebpf $BUILD_DIR/app/stats/ || true
[ -d transport/internet/ebpf ] && cp -r transport/internet/ebpf $BUILD_DIR/transport/internet/ || true
[ -d transport/internet/tcp/ebpf ] && cp -r transport/internet/tcp/ebpf $BUILD_DIR/transport/internet/tcp/ || true
[ -d proxy/ebpf ] && cp -r proxy/ebpf $BUILD_DIR/proxy/ || true

# 创建优化的eBPF挂载脚本
log_info "创建eBPF挂载脚本..."
cat > $BUILD_DIR/mount-ebpf.sh << 'EOF'
#!/bin/bash

# Xray eBPF 挂载脚本
# 自动编译、加载和管理eBPF程序

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}❌ $1${NC}"; }

# 配置
BPF_ROOT="/sys/fs/bpf/xray"
CACHE_FILE="/tmp/.xray_ebpf_deps_checked"

echo "🚀 Xray eBPF 挂载脚本"
echo "================================"

# 权限检查
if [ "$EUID" -ne 0 ]; then
    log_error "请使用 sudo 运行此脚本"
    exit 1
fi

  # 确保 bpffs 已挂载
  if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    log_info "挂载 bpffs 到 /sys/fs/bpf..."
    mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
    mountpoint -q /sys/fs/bpf && log_success "bpffs 已挂载" || log_warning "bpffs 挂载失败（可能已挂载），继续"
  fi

# 清理函数
cleanup_ebpf() {
    log_info "清理历史eBPF程序..."
    mkdir -p $BPF_ROOT
    chmod 755 /sys/fs/bpf 2>/dev/null || true
    chmod 755 $BPF_ROOT 2>/dev/null || true
    # 尝试卸载 tc 过滤器
    if command -v tc >/dev/null 2>&1; then
      IFACES=$(ip -o link show | awk -F': ' '{print $2}')
      for IF in $IFACES; do
        tc filter del dev "$IF" ingress 2>/dev/null || true
        tc qdisc del dev "$IF" clsact 2>/dev/null || true
        ip link set dev "$IF" xdp off 2>/dev/null || true
      done
    fi
    # 清理pinned文件（遇权限问题继续）
    find "$BPF_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
    log_success "历史eBPF程序清理完成"
}

# 依赖检查
check_dependencies() {
    log_info "检查依赖..."
    
    # 检查缓存
    if [ -f "$CACHE_FILE" ]; then
        local cache_age=$(($(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0)))
        if [ "$cache_age" -lt 86400 ]; then
            log_success "依赖检查缓存有效，跳过重复检查"
            return 0
        fi
    fi
    
    # 检查必要工具
    local missing_deps=""
    for tool in clang llvm-config make bpftool tc ip; do
        if ! command -v $tool >/dev/null 2>&1; then
            missing_deps="$missing_deps $tool"
        fi
    done
    
    # 检查头文件
    [ -f /usr/include/bpf/bpf.h ] || missing_deps="$missing_deps libbpf-dev"
    [ -f /usr/include/linux/bpf.h ] || missing_deps="$missing_deps linux-headers-$(uname -r)"
    
    if [ -n "$missing_deps" ]; then
        log_warning "需要安装依赖: $missing_deps"
        apt update
        apt install -y clang llvm make gcc-multilib libc6-dev-i386 \
            linux-headers-$(uname -r) libbpf-dev iproute2
    fi
    
    touch "$CACHE_FILE"
    log_success "依赖检查完成"
}

# 编译eBPF程序（按目录通配）
compile_ebpf() {
    log_info "编译eBPF程序..."
    local build_root=$(pwd)
    local success_count=0
    local total_count=0
    compile_program() {
        local dir=$1
        if [ -d "$dir" ]; then
            cd "$dir"
            make -s clean 2>/dev/null || true
            for file in *.c; do
                [ -f "$file" ] || continue
                total_count=$((total_count + 1))
                if clang -O2 -g -Wall -target bpf -c -fno-stack-protector \
                    -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -o "${file%.c}.o" "$file" 2>/dev/null; then
                    log_success "$dir/$file 编译成功"
                    success_count=$((success_count + 1))
                else
                    log_warning "$dir/$file 编译失败"
                fi
            done
            cd "$build_root"
        fi
    }
    compile_program "app/dns/ebpf"
    compile_program "app/router/ebpf"
    compile_program "app/stats/ebpf"
    compile_program "transport/internet/ebpf"
    compile_program "transport/internet/tcp/ebpf"
    compile_program "proxy/ebpf"
    log_success "eBPF编译完成: $success_count/$total_count 成功"
}

# 加载eBPF程序
load_ebpf() {
    log_info "加载eBPF程序..."
    
    # 创建基础maps
    log_info "创建基础maps..."
    # DNS 缓存映射（与 app/dns/ebpf/dns_cache.c 对齐）
    # dns_cache: LRU_HASH, key=4 (FNV-1a 32bit), value=16 (u32 ip + u32 ttl + u64 expire)
    # dns_cache_v6: LRU_HASH, key=4, value=28 (u128 ip + u32 ttl + u64 expire)
    # dns_stats: HASH, key=4, value=4 (u32 count)
    bpftool map create $BPF_ROOT/dns_cache type lru_hash key 4 value 16 entries 50000 name dns_cache 2>/dev/null || true
    bpftool map create $BPF_ROOT/dns_cache_v6 type lru_hash key 4 value 28 entries 25000 name dns_cache_v6 2>/dev/null || true
    bpftool map create $BPF_ROOT/dns_stats type hash key 4 value 4 entries 20000 name dns_stats 2>/dev/null || true
    bpftool map create $BPF_ROOT/geoip_v4 type hash key 4 value 1 entries 10000 name geoip_v4 2>/dev/null || true
    bpftool map create $BPF_ROOT/geoip_v6 type hash key 8 value 1 entries 10000 name geoip_v6 2>/dev/null || true
    bpftool map create $BPF_ROOT/connection_map type hash key 8 value 64 entries 65536 name connection_map 2>/dev/null || true
    bpftool map create $BPF_ROOT/route_geoip_v4_hint type lru_hash key 4 value 4 entries 65536 name route_geoip_v4_hint 2>/dev/null || true
    bpftool map create $BPF_ROOT/xtls_direct_copy_hint type hash key 8 value 1 entries 65536 name xtls_direct_copy_hint 2>/dev/null || true
    
    # 加载函数
    load_program() {
        local obj_file=$1
        local prog_name=$2
        local prog_type=$3
        local map_name=$4
        local attach_interface=$5
        
        if [ -f "$obj_file" ]; then
            # 创建专用maps
            if [ -n "$map_name" ]; then
                for map in $map_name; do
                    bpftool map create $BPF_ROOT/$map 2>/dev/null || true
                done
            fi
            
            # 加载程序
            if bpftool prog load "$obj_file" $BPF_ROOT/$prog_name type $prog_type 2>/dev/null; then
                log_success "$prog_name 加载成功"
                
                # 如果是XDP程序且有指定接口，则附加到网络接口
                if [ "$prog_type" = "xdp" ] && [ -n "$attach_interface" ]; then
                    # 尝试原生XDP
                    if ip link set dev $attach_interface xdp obj $BPF_ROOT/$prog_name 2>/dev/null; then
                        log_success "$prog_name 附加到 $attach_interface 成功 (原生XDP)"
                    else
                        # 尝试通用XDP
                        if ip link set dev $attach_interface xdp obj $BPF_ROOT/$prog_name mode skb 2>/dev/null; then
                            log_success "$prog_name 附加到 $attach_interface 成功 (通用XDP)"
                        else
                            log_warning "$prog_name 附加到 $attach_interface 失败"
                        fi
                    fi
                fi
                
                return 0
            else
                log_warning "$prog_name 加载失败"
                return 1
            fi
        fi
        return 1
    }
    
    # 获取网络接口名称（可由 XRAY_IFACE 覆盖）
    local interface_name=${XRAY_IFACE:-}
    if [ -z "$interface_name" ]; then
      interface_name=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
    fi
    if [ -z "$interface_name" ]; then
        interface_name="ens5"  # 默认接口
    fi
    
    log_info "使用网络接口: $interface_name"
    
    # 通用加载：XDP 使用 prog load + ip link；TC 使用 prog loadall 并 pin maps，然后 attach_tc 使用 pinned
    load_xdp() {
      local obj=$1; local pinned_name=$2
      if [ -f "$obj" ]; then
        if bpftool prog load "$obj" "$BPF_ROOT/$pinned_name" type xdp 2>/dev/null; then
          log_success "$pinned_name 加载成功 (XDP)"
          ip link set dev "$interface_name" xdp off 2>/dev/null || true
          if ip link set dev "$interface_name" xdp pinned "$BPF_ROOT/$pinned_name" 2>/dev/null; then
            log_success "$pinned_name 附加到 $interface_name 成功 (原生XDP)"
          elif ip link set dev "$interface_name" xdp pinned "$BPF_ROOT/$pinned_name" mode skb 2>/dev/null; then
            log_success "$pinned_name 附加到 $interface_name 成功 (通用XDP)"
          else
            log_info "$pinned_name 附加失败，已忽略（继续）"
          fi
        else
          log_info "$pinned_name 加载失败 (XDP)，已忽略"
        fi
      fi
    }

    attach_tc() {
      local obj_or_pinned=$1
      local ifname=$2
      local prio=${3:-60}
      local handle=${4:-60}
      local use_pinned=${5:-0}
      tc qdisc add dev "$ifname" clsact 2>/dev/null || true
      tc filter del dev "$ifname" ingress prio "$prio" 2>/dev/null || true
      if [ "$use_pinned" = "1" ]; then
        tc filter replace dev "$ifname" ingress prio "$prio" handle "$handle" bpf da pinned "$obj_or_pinned"
      else
        tc filter replace dev "$ifname" ingress prio "$prio" handle "$handle" bpf da obj "$obj_or_pinned" sec tc
      fi
    }

    load_tc_with_pinmaps() {
      local obj=$1; local pinned_name=$2
      if [ -f "$obj" ]; then
        if bpftool prog loadall "$obj" "$BPF_ROOT/$pinned_name" pinmaps "$BPF_ROOT" 2>/dev/null; then
          log_success "$pinned_name 加载成功 (TC, 已 pin maps)"
          # 使用 obj+sec 方式附加，避免读取 pinned program 失败
          attach_tc "$obj" "$interface_name" 60 60 0
        else
          log_info "$pinned_name 加载失败 (TC)，已忽略"
        fi
      fi
    }

    # 加载各模块
      # 默认 DNS 走 TC，避免与主 XDP 冲突；如需 XDP 可设置 XRAY_XDP_EXTRA=dns
      load_tc_with_pinmaps "app/dns/ebpf/dns_router_tc.o" "dns_router_tc"
      # 兼容 legacy section 名称：强制以 sec classifier 再尝试一次（忽略失败）
      tc qdisc add dev "$interface_name" clsact 2>/dev/null || true
      tc filter replace dev "$interface_name" ingress prio 60 handle 60 bpf da obj app/dns/ebpf/dns_router_tc.o sec classifier 2>/dev/null || true
    if [ "$XRAY_XDP_EXTRA" = "dns" ]; then
      # 为 dns_cache.o 绑定已 pin 的 maps，确保与用户态一致
      if [ -f "app/dns/ebpf/dns_cache.o" ]; then
        if bpftool prog load app/dns/ebpf/dns_cache.o "$BPF_ROOT/dns_cache_prog" type xdp \
            map name dns_cache pinned "$BPF_ROOT/dns_cache" \
            map name dns_cache_v6 pinned "$BPF_ROOT/dns_cache_v6" \
            map name dns_stats pinned "$BPF_ROOT/dns_stats" 2>/dev/null; then
          log_success "dns_cache_prog 加载成功 (XDP+pin maps)"
          ip link set dev "$interface_name" xdp off 2>/dev/null || true
          if ip link set dev "$interface_name" xdp pinned "$BPF_ROOT/dns_cache_prog" 2>/dev/null; then
            log_success "dns_cache_prog 附加到 $interface_name 成功 (原生XDP)"
          elif ip link set dev "$interface_name" xdp pinned "$BPF_ROOT/dns_cache_prog" mode skb 2>/dev/null; then
            log_success "dns_cache_prog 附加到 $interface_name 成功 (通用XDP)"
          else
            log_info "dns_cache_prog 附加失败，已忽略（继续）"
          fi
        else
          log_info "dns_cache_prog 加载失败 (XDP)，已忽略"
        fi
      fi
    fi

    # 避免多 XDP 并存，默认不附加 Geo XDP；如需启用请设置 XRAY_XDP_EXTRA=geo
    if [ "$XRAY_XDP_EXTRA" = "geo" ]; then
      load_xdp "app/router/ebpf/geoip_matcher.o" "geoip_matcher"
      load_xdp "app/router/ebpf/geosite_matcher.o" "geosite_matcher"
    fi

    # 动态 GeoSite 学习缓存（如果存在动态目标文件则加载并确保 map pin）
    if [[ -f "app/router/ebpf/geosite_matcher_dynamic.o" ]]; then
        log_info "加载 GeoSite 动态匹配器..."
        if bpftool prog loadall app/router/ebpf/geosite_matcher_dynamic.o /sys/fs/bpf/xray 2>/dev/null; then
            log_success "geosite_matcher_dynamic 加载成功"
        else
            log_warning "geosite_matcher_dynamic 加载失败"
        fi
        # 确保关键 maps 已 pin（名称需与C文件中的section名一致）
        for m in geosite_dynamic_cache domain_access_stats hot_domain_list geosite_config_dynamic geosite_stats_dynamic; do
            if [[ -e "/sys/fs/bpf/xray/$m" ]]; then
                :
            else
                # 尝试从已加载对象中pin map（不同内核/版本下名称解析可能不同，这里尽力而为）
                bpftool map show | awk '/name '$m'/{print $1}' | sed 's/://g' | while read -r id; do
                    bpftool map pin id $id /sys/fs/bpf/xray/$m || true
                done
            fi
        done
        # 尝试附着 TC，实现域名热缓存打标（失败忽略）
        tc qdisc add dev "$interface_name" clsact 2>/dev/null || true
        tc filter replace dev "$interface_name" ingress prio 61 handle 61 bpf da obj app/router/ebpf/geosite_matcher_dynamic.o sec tc 2>/dev/null || true
    fi

    # 动态 GeoIP 学习缓存
    if [[ -f "app/router/ebpf/geoip_matcher_dynamic.o" ]]; then
        log_info "加载 GeoIP 动态匹配器..."
        if bpftool prog loadall app/router/ebpf/geoip_matcher_dynamic.o /sys/fs/bpf/xray 2>/dev/null; then
            log_success "geoip_matcher_dynamic 加载成功"
        else
            log_warning "geoip_matcher_dynamic 加载失败"
        fi
        for m in geoip_dynamic_cache ip_access_stats hot_ip_list geoip_config_dynamic geoip_stats_dynamic; do
            if [[ -e "/sys/fs/bpf/xray/$m" ]]; then
                :
            else
                bpftool map show | awk '/name '$m'/{print $1}' | sed 's/://g' | while read -r id; do
                    bpftool map pin id $id /sys/fs/bpf/xray/$m || true
                done
            fi
        done
        # 尝试附着 TC，实现 GeoIP 热缓存打标（失败忽略）
        tc qdisc add dev "$interface_name" clsact 2>/dev/null || true
        tc filter replace dev "$interface_name" ingress prio 62 handle 62 bpf da obj app/router/ebpf/geoip_matcher_dynamic.o sec tc 2>/dev/null || true
    fi

    load_xdp "transport/internet/tcp/ebpf/tcp_reality_accelerator.o" "tcp_reality_accelerator_xdp"
    load_tc_with_pinmaps "transport/internet/tcp/ebpf/tcp_reality_tc.o" "tcp_reality_accelerator_tc"

    load_xdp "proxy/ebpf/proxy_accelerator.o" "proxy_accelerator_xdp"
    load_tc_with_pinmaps "proxy/ebpf/proxy_accelerator.o" "proxy_accelerator_tc"

    load_xdp "transport/internet/tcp/ebpf/xtls_vision_xdp.o" "xtls_vision_inbound_accelerator_xdp"
    load_tc_with_pinmaps "transport/internet/tcp/ebpf/xtls_vision_tc.o" "xtls_vision_inbound_accelerator_tc"

    load_xdp "transport/internet/tcp/ebpf/tcp_congestion_basic.o" "tcp_congestion_basic_xdp"
}

# 设置权限
setup_permissions() {
    log_info "设置权限..."
    chmod +x xray-linux-amd64-ebpf
    setcap cap_bpf+ep ./xray-linux-amd64-ebpf 2>/dev/null || true
    systemctl stop xray
    cp xray-linux-amd64-ebpf /usr/local/bin/xray
    systemctl start xray
    log_success "权限设置完成"
}

# 显示状态
show_status() {
    log_info "eBPF程序状态:"
    bpftool prog list | grep -E "dns|xray|tcp|xtls|proxy" || true
    bpftool map list | grep -E "dns|xray|tcp|xtls|proxy" || true
    
    log_info "策略路由规则:"
    ip rule list | grep -E 'fwmark 0x1|fwmark 0x2' | cat
    ip route show table 100 | cat
    ip route show table 200 | cat
}

# 主流程
main() {
    cleanup_ebpf
    check_dependencies
    compile_ebpf
    load_ebpf
    setup_permissions
    show_status
    
    log_success "eBPF挂载完成！"
}

main "$@"
EOF

chmod +x $BUILD_DIR/mount-ebpf.sh
# 覆盖为仓库中的增强版本，确保你对 build/mount-ebpf.sh 的修改生效
if [ -f build/mount-ebpf.sh ]; then
    cp build/mount-ebpf.sh $BUILD_DIR/mount-ebpf.sh
    chmod +x $BUILD_DIR/mount-ebpf.sh
fi

# 创建部署脚本
log_info "创建部署脚本..."
cat > $BUILD_DIR/deploy.sh << 'EOF'
#!/bin/bash

# Xray eBPF 部署脚本

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${YELLOW}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }

echo "🚀 Xray eBPF 部署脚本"
echo "===================="

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用 sudo 运行此脚本"
    exit 1
fi

# 停止服务并备份
log_info "停止 Xray 服务..."
systemctl stop xray 2>/dev/null || true
if [ -f /usr/local/bin/xray ]; then
    log_info "备份原文件..."
    cp /usr/local/bin/xray /usr/local/bin/xray.backup.$(date +%Y%m%d_%H%M%S)
fi

# 部署新二进制（不立即启动）
log_info "部署新文件..."
cp xray-linux-amd64-ebpf /usr/local/bin/xray
chmod +x /usr/local/bin/xray

# 先挂载/创建 eBPF maps 与程序，再启动服务，避免程序启动时找不到 maps
log_info "挂载eBPF程序..."
bash mount-ebpf.sh

# 检查状态
log_info "检查服务状态..."
if systemctl is-active --quiet xray; then
    log_success "Xray 服务启动成功"
else
    echo "❌ Xray 服务启动失败"
    exit 1
fi

log_success "部署完成！"
EOF

chmod +x $BUILD_DIR/deploy.sh

# 创建README
log_info "创建部署说明..."
cat > $BUILD_DIR/README.md << 'EOF'
# Xray eBPF 部署包

## 功能特性

- 🚀 **零配置自动优化** - 无需修改现有配置
- 🧠 **智能路由学习** - 自动学习热点路由
- ⚡ **XDP快速通道** - 内核层包处理
- 📊 **透明流量统计** - 自动统计和优化
- 🌐 **GeoSite eBPF加速** - 域名匹配内核加速
- 📍 **GeoIP eBPF优化** - IP地理位置内核匹配
- 🔄 **自动fallback** - eBPF失败时无缝回退
- 🔒 **TCP+REALITY优化** - REALITY协议内核加速
- 👁️ **XTLS Vision优化** - Vision协议内核加速
- 🚦 **TCP拥塞控制** - 智能拥塞控制算法

## 使用方法

### 1. 上传到服务器
```bash
rsync -r build/ root@your-server:/root/xray-ebpf/
```

### 2. 部署
```bash
ssh root@your-server
cd /root/xray-ebpf
bash deploy.sh
```

### 3. 验证
```bash
# 检查eBPF程序
bpftool prog list | grep xray

# 检查eBPF maps
bpftool map list | grep xray

# 检查服务状态
systemctl status xray
```

## 环境变量

设置以下环境变量启用eBPF功能：
```bash
export XRAY_EBPF=1
```

## 故障排除

1. **eBPF程序加载失败**
   - 检查内核版本 (需要 4.18+)
   - 检查依赖是否安装完整
   - 查看系统日志: `journalctl -u xray`

2. **权限问题**
   - 确保使用 root 权限运行
   - 检查 eBPF 文件系统挂载

3. **性能问题**
   - 检查 eBPF 程序是否正确加载
   - 查看统计信息: `bpftool map dump`

## 支持平台

- Linux AMD64 (主要支持)
# - macOS AMD64 (开发测试)
- macOS ARM64 (开发测试)
EOF

log_success "构建完成！"
echo ""
echo "📦 构建目录内容:"
echo "   xray-linux-amd64-ebpf - Linux Xray可执行文件"
echo "   xray-darwin-amd64 - macOS AMD64可执行文件"
echo "   xray-darwin-arm64 - macOS ARM64可执行文件"
echo "   mount-ebpf.sh - eBPF挂载脚本"
echo "   deploy.sh - 一键部署脚本"
echo "   README.md - 部署说明"
echo ""
echo "🚀 部署命令:"
echo "   rsync -r build/ root@your-server:/root/xray-ebpf/"
echo "   ssh root@your-server 'cd /root/xray-ebpf && bash deploy.sh'"