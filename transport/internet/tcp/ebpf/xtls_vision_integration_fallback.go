//go:build !linux
// +build !linux

package ebpf

import (
	"context"
	"net"
)

// EnableXTLSVisionInboundEBPFAcceleration 启用XTLS Vision入站eBPF加速的便捷函数（非Linux平台）
func EnableXTLSVisionInboundEBPFAcceleration(ctx context.Context, clientAddr net.Addr, serverAddr net.Addr) error {
	// 非Linux平台，返回nil表示不启用
	return nil
} 