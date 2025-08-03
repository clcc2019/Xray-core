//go:build linux

package outbound

import (
	"context"
	"net"
	"os"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/ebpf"
)

// EnableVLESSEBPFAcceleration 为VLESS outbound启用eBPF加速
func EnableVLESSEBPFAcceleration(ctx context.Context, conn net.Conn, sni string) {
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

	// 注册VLESS连接
	if err := accelerator.RegisterConnection(
		localTCP.IP, remoteTCP.IP,
		uint16(localTCP.Port), uint16(remoteTCP.Port),
		1, // VLESS类型
	); err != nil {
		errors.LogDebug(ctx, "Failed to register VLESS eBPF connection: ", err)
		return
	}
	
	// 如果有SNI，启用TLS优化
	if sni != "" {
		if err := accelerator.EnableTLSOptimization(conn, sni); err != nil {
			errors.LogDebug(ctx, "Failed to enable TLS optimization for VLESS: ", err)
		}
	}
	
	errors.LogDebug(ctx, "VLESS eBPF acceleration enabled for: ", remoteAddr, " SNI: ", sni)
}