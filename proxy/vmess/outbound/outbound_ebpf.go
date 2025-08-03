//go:build linux

package outbound

import (
	"context"
	"net"
	"os"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/ebpf"
	xraynet "github.com/xtls/xray-core/common/net"
)

// EnableVMessEBPFAcceleration 为VMess outbound启用eBPF加速
func EnableVMessEBPFAcceleration(ctx context.Context, conn net.Conn, target xraynet.Destination) {
	if os.Getenv("XRAY_EBPF") != "1" {
		return
	}
	
	accelerator := ebpf.GetProxyAccelerator()
	if accelerator == nil || !accelerator.IsEnabled() {
		return
	}
	
	// 从连接中提取地址信息
	localAddr := conn.LocalAddr()
	remoteAddr := conn.RemoteAddr()
	
	if localAddr == nil || remoteAddr == nil {
		return
	}

	// 解析地址
	localTCP, ok1 := localAddr.(*net.TCPAddr)
	remoteTCP, ok2 := remoteAddr.(*net.TCPAddr)
	
	if !ok1 || !ok2 {
		return
	}

	// 注册VMess连接
	if err := accelerator.RegisterConnection(
		localTCP.IP, remoteTCP.IP,
		uint16(localTCP.Port), uint16(remoteTCP.Port),
		2, // VMess类型
	); err != nil {
		errors.LogDebug(ctx, "Failed to register VMess eBPF connection: ", err)
		return
	}
	
	// 如果目标是域名且可能是TLS，启用TLS优化
	if target.Address.Family().IsDomain() {
		sni := target.Address.Domain()
		if err := accelerator.EnableTLSOptimization(conn, sni); err != nil {
			errors.LogDebug(ctx, "Failed to enable TLS optimization for VMess: ", err)
		}
	}
	
	errors.LogDebug(ctx, "VMess eBPF acceleration enabled for: ", remoteAddr, " target: ", target)
}