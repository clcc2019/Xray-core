# Xray-core eBPF 加速版（中文）

本分支在 Xray-core 基础上，加入了面向 Linux 服务器的 eBPF 加速能力，覆盖 REALITY/XTLS、DNS 缓存、路由匹配与 TCP 优化，追求“默认开启、失败忽略、无需改配置”的简单易用体验。

- 英文版文档: [README.md](README.md)

## 主要特性
- 核心加速：
  - REALITY 握手优化与预采集（ALPN/RTT/SPKI），支持 0-RTT（仅内部信号，自动回退）
  - XTLS Vision 内核侧加速与自适应填充/节奏（可回退）
  - DNS 内核缓存（A/AAAA 双栈）、内核侧路由器（DoT/DoH 识别，IPv4/IPv6 支持）
  - GeoSite/GeoIP eBPF 动态匹配与学习缓存（配合用户态策略写入）
  - TCP 优化（BBR/QUICKACK/NOTSENT_LOWAT/零拷贝）
- 部署与运行：
  - `build-and-deploy.sh` 一键构建与打包
  - 服务器上执行 `mount-ebpf.sh` 自动挂载 eBPF 程序与 maps
  - eBPF 加载失败不阻断主流程，自动回退用户态

## 快速开始
```bash
# 本地构建（建议在 macOS/Linux 上执行）
./build-and-deploy.sh

# 上传与部署
rsync -r build/ root@your-server:/root/xray-ebpf/
ssh root@your-server 'cd /root/xray-ebpf && bash deploy.sh'
```

## 运行示例（服务端）
```bash
export XRAY_EBPF=1              # 开启 eBPF 加速（默认脚本已设置）
# 可选：子特性开关（均默认为 1，可显式设为 0 关闭）
export XRAY_EBPF_DNS_ROUTER=1
export XRAY_EBPF_GEOSITE=1
export XRAY_EBPF_IP_FASTPATH=1

/usr/local/bin/xray run -config /etc/xray/config.yaml
```

## 验证
```bash
bpftool prog list | grep xray
bpftool map list  | grep xray
journalctl -u xray -n 200 --no-pager
```

## 注意事项
- 仅面向 Linux 服务器；本仓库已精简为 Linux 专用构建
- 不修改既有 Xray 配置文件的前提下生效（通过环境变量与 eBPF pinned maps 管理）
- 若内核/权限不足以加载 eBPF，系统会自动回退到用户态逻辑

## 常见问题
1) 程序加载失败
   - 检查依赖：clang/llvm/bpftool/libbpf-dev
   - 确认 bpffs 已挂载：`mount | grep /sys/fs/bpf`
   - 由 `mount-ebpf.sh` 自动创建/挂载 maps 与程序，失败会忽略并继续

2) 路由误判/阻断
   - eBPF 仅作为“提示/学习”层，最终决策以用户态为准
   - GeoSite/GeoIP 策略通过用户态小管理器写入 pinned maps

3) REALITY 日志泄露
   - 生产环境请确保 `reality.Config.Show=false`，禁用敏感调试输出

## 许可证
与上游一致，采用 Mozilla Public License 2.0。
