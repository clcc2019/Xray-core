//go:build linux

package freedom

import (
	"context"
	"net"
	"os"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/ebpf"
)

// EnableEBPFAcceleration 为freedom proxy启用Cilium eBPF加速
func EnableEBPFAcceleration(ctx context.Context, conn net.Conn) {
	if os.Getenv("XRAY_EBPF") != "1" {
		return
	}

	accelerator := ebpf.GetProxyAccelerator()
	if accelerator == nil || !accelerator.IsEnabled() {
		return
	}

	// 启用Cilium splice优化
	if err := accelerator.EnableSplice(conn); err != nil {
		errors.LogDebug(ctx, "Failed to enable Cilium eBPF splice for freedom connection: ", err)
		return
	}

	errors.LogDebug(ctx, "Freedom Cilium eBPF acceleration enabled for connection: ", conn.RemoteAddr(),
		" (active connections: ", accelerator.GetConnectionCount(), ")")
}