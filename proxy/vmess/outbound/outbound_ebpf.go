//go:build linux

package outbound

import (
	"context"
	"net"
	xraynet "github.com/xtls/xray-core/common/net"
)

// EnableVMessEBPFAcceleration 为VMess outbound启用eBPF加速
// 注意：根据项目要求，eBPF优化主要针对服务端入站，客户端出站优化已禁用
func EnableVMessEBPFAcceleration(ctx context.Context, conn net.Conn, target xraynet.Destination) {
	// 客户端出站eBPF优化已禁用，专注于服务端入站优化
	// 保持函数接口不变，但内部实现为空，避免影响现有代码
	return
}