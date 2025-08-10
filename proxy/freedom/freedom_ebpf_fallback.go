//go:build !linux

package freedom

import (
	"context"
	"net"
)

// 非 Linux 平台：eBPF 加速占位，无操作
func EnableEBPFAcceleration(ctx context.Context, conn net.Conn) {}
