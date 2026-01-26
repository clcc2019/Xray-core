# Xray-core Performance Fork

基于 [Xray-core](https://github.com/XTLS/Xray-core) 的性能优化分支。

## 性能优化

本分支专注于以下性能优化：

### 内存管理优化

- **MultiBuffer 切片池化** (`common/buf/multi_buffer.go`)
  - 新增 `multiBufferPool` 池化 MultiBuffer 切片
  - 新增 `GetMultiBuffer()` / `PutMultiBuffer()` 接口
  - 新增 `ReleaseMultiAndReturn()` 释放并回收到池
  - 减少高吞吐场景下的切片分配

- **Buffer 结构体池化** (`common/buf/buffer.go`)
  - 已有的 `bufferPool` 池化 Buffer 结构体
  - 已有的 `bytespool` 多级内存池 (2KB/8KB/32KB/128KB)

### 数据传输优化

- **Copy 函数快速路径** (`common/buf/copy.go`)
  - 新增 `copyFast()` 无 handler 快速路径
  - 无 option 时跳过 handler 分配和迭代
  - 减少热路径上的开销

### 管道传输优化

- **Pipe 无锁长度查询** (`transport/pipe/impl.go`)
  - 新增 `dataLen` 原子变量缓存数据长度
  - `Len()` 和 `hasData()` 无需获取锁
  - 减少锁竞争，提高并发性能

### 信号通知优化

- **Notifier 池化** (`common/signal/notifier.go`)
  - 新增 `notifierPool` 池化 Notifier 实例
  - 新增 `Release()` 方法回收到池
  - 减少频繁创建销毁的开销

## License

[Mozilla Public License Version 2.0](https://github.com/XTLS/Xray-core/blob/main/LICENSE)

## 文档

[Project X 官方文档](https://xtls.github.io)

## Telegram

[Project X](https://t.me/projectXray)

[Project X Channel](https://t.me/projectXtls)

[Project VLESS](https://t.me/projectVless) (Русский)

[Project XHTTP](https://t.me/projectXhttp) (Persian)

## Installation

- Linux Script
  - [XTLS/Xray-install](https://github.com/XTLS/Xray-install) (**Official**)
  - [tempest](https://github.com/team-cloudchaser/tempest) (supports [`systemd`](https://systemd.io) and [OpenRC](https://github.com/OpenRC/openrc); Linux-only)
- Docker
  - [ghcr.io/xtls/xray-core](https://ghcr.io/xtls/xray-core) (**Official**)
  - [teddysun/xray](https://hub.docker.com/r/teddysun/xray)
  - [wulabing/xray_docker](https://github.com/wulabing/xray_docker)
- Web Panel
  - [Remnawave](https://github.com/remnawave/panel)
  - [3X-UI](https://github.com/MHSanaei/3x-ui)
  - [PasarGuard](https://github.com/PasarGuard/panel)
  - [Xray-UI](https://github.com/qist/xray-ui)
  - [X-Panel](https://github.com/xeefei/X-Panel)
  - [Marzban](https://github.com/Gozargah/Marzban)
  - [Hiddify](https://github.com/hiddify/Hiddify-Manager)
  - [TX-UI](https://github.com/AghayeCoder/tx-ui)
- One Click
  - [Xray-REALITY](https://github.com/zxcvos/Xray-script), [xray-reality](https://github.com/sajjaddg/xray-reality), [reality-ezpz](https://github.com/aleskxyz/reality-ezpz)
  - [Xray_bash_onekey](https://github.com/hello-yunshu/Xray_bash_onekey), [XTool](https://github.com/LordPenguin666/XTool), [VPainLess](https://github.com/vpainless/vpainless)
  - [v2ray-agent](https://github.com/mack-a/v2ray-agent), [Xray_onekey](https://github.com/wulabing/Xray_onekey), [ProxySU](https://github.com/proxysu/ProxySU)
- Magisk
  - [Xray4Magisk](https://github.com/Asterisk4Magisk/Xray4Magisk)
  - [Xray_For_Magisk](https://github.com/E7KMbb/Xray_For_Magisk)
- Homebrew
  - `brew install xray`

## Usage

- Example
  - [VLESS-XTLS-uTLS-REALITY](https://github.com/XTLS/REALITY#readme)
  - [VLESS-TCP-XTLS-Vision](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision)
  - [All-in-One-fallbacks-Nginx](https://github.com/XTLS/Xray-examples/tree/main/All-in-One-fallbacks-Nginx)
- Xray-examples
  - [XTLS/Xray-examples](https://github.com/XTLS/Xray-examples)
  - [chika0801/Xray-examples](https://github.com/chika0801/Xray-examples)
  - [lxhao61/integrated-examples](https://github.com/lxhao61/integrated-examples)
- Tutorial
  - [XTLS Vision](https://github.com/chika0801/Xray-install)
  - [REALITY (English)](https://cscot.pages.dev/2023/03/02/Xray-REALITY-tutorial/)
  - [XTLS-Iran-Reality (English)](https://github.com/SasukeFreestyle/XTLS-Iran-Reality)
  - [Xray REALITY with 'steal oneself' (English)](https://computerscot.github.io/vless-xtls-utls-reality-steal-oneself.html)
  - [Xray with WireGuard inbound (English)](https://g800.pages.dev/wireguard)

## GUI Clients

- OpenWrt
  - [PassWall](https://github.com/Openwrt-Passwall/openwrt-passwall), [PassWall 2](https://github.com/Openwrt-Passwall/openwrt-passwall2)
  - [ShadowSocksR Plus+](https://github.com/fw876/helloworld)
  - [luci-app-xray](https://github.com/yichya/luci-app-xray) ([openwrt-xray](https://github.com/yichya/openwrt-xray))
- Asuswrt-Merlin
  - [XRAYUI](https://github.com/DanielLavrushin/asuswrt-merlin-xrayui)
  - [fancyss](https://github.com/hq450/fancyss)
- Windows
  - [v2rayN](https://github.com/2dust/v2rayN)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [Invisible Man - Xray](https://github.com/InvisibleManVPN/InvisibleMan-XRayClient)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
- Android
  - [v2rayNG](https://github.com/2dust/v2rayNG)
  - [X-flutter](https://github.com/XTLS/X-flutter)
  - [SaeedDev94/Xray](https://github.com/SaeedDev94/Xray)
  - [SimpleXray](https://github.com/lhear/SimpleXray)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
- iOS & macOS arm64 & tvOS
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) | [Happ RU](https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973) | [Happ tvOS](https://apps.apple.com/us/app/happ-proxy-utility-for-tv/id6748297274)
  - [Streisand](https://apps.apple.com/app/streisand/id6450534064)
  - [OneXray](https://github.com/OneXray/OneXray)
- macOS arm64 & x64
  - [Happ](https://apps.apple.com/app/happ-proxy-utility/id6504287215) | [Happ RU](https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973)
  - [V2rayU](https://github.com/yanue/V2rayU)
  - [V2RayXS](https://github.com/tzmax/V2RayXS)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [OneXray](https://github.com/OneXray/OneXray)
  - [GoXRay](https://github.com/goxray/desktop)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [v2rayN](https://github.com/2dust/v2rayN)
- Linux
  - [v2rayA](https://github.com/v2rayA/v2rayA)
  - [Furious](https://github.com/LorenEteval/Furious)
  - [GorzRay](https://github.com/ketetefid/GorzRay)
  - [GoXRay](https://github.com/goxray/desktop)
  - [AnyPortal](https://github.com/AnyPortal/AnyPortal)
  - [v2rayN](https://github.com/2dust/v2rayN)

## Others that support VLESS, XTLS, REALITY, XUDP, PLUX...

- iOS & macOS arm64 & tvOS
  - [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118)
  - [Loon](https://apps.apple.com/us/app/loon/id1373567447)
- Xray Tools
  - [xray-knife](https://github.com/lilendian0x00/xray-knife)
  - [xray-checker](https://github.com/kutovoys/xray-checker)
- Xray Wrapper
  - [XTLS/libXray](https://github.com/XTLS/libXray)
  - [xtls-sdk](https://github.com/remnawave/xtls-sdk)
  - [xtlsapi](https://github.com/hiddify/xtlsapi)
  - [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite)
  - [Xray-core-python](https://github.com/LorenEteval/Xray-core-python)
  - [xray-api](https://github.com/XVGuardian/xray-api)
- [XrayR](https://github.com/XrayR-project/XrayR)
  - [XrayR-release](https://github.com/XrayR-project/XrayR-release)
  - [XrayR-V2Board](https://github.com/missuo/XrayR-V2Board)
- Cores
  - [Amnezia VPN](https://github.com/amnezia-vpn)
  - [mihomo](https://github.com/MetaCubeX/mihomo)
  - [sing-box](https://github.com/SagerNet/sing-box)

## Contributing

[Code of Conduct](https://github.com/XTLS/Xray-core/blob/main/CODE_OF_CONDUCT.md)

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/XTLS/Xray-core)

## Credits

- 基于 [XTLS/Xray-core](https://github.com/XTLS/Xray-core)
- [Xray-core v1.0.0](https://github.com/XTLS/Xray-core/releases/tag/v1.0.0) was forked from [v2fly-core 9a03cc5](https://github.com/v2fly/v2ray-core/commit/9a03cc5c98d04cc28320fcee26dbc236b3291256)
- 第三方依赖详见 [go.mod](https://github.com/XTLS/Xray-core/blob/main/go.mod)

## 编译

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### 可复现构建

确保使用相同的 Go 版本，并设置 git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```
