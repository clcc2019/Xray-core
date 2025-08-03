//go:build !linux

package freedom

import (
	"context"
	"net"
	
	"github.com/xtls/xray-core/proxy/ebpf"
)

// recordConnectionStats fallback实现（非Linux系统）
func recordConnectionStats(ctx context.Context, conn *net.TCPConn, accelerator *ebpf.ProxyAcceleratorCilium) {}