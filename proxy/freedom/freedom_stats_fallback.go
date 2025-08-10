//go:build !linux

package freedom

import (
	"context"
	"net"

	ebpfproxy "github.com/xtls/xray-core/proxy/ebpf"
)

// 非 Linux 平台：统计记录占位，无操作
func recordConnectionStats(ctx context.Context, conn *net.TCPConn, accelerator *ebpfproxy.ProxyAcceleratorCilium) {
}
