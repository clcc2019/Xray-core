//go:build linux

package ebpfhooks

import (
	"net"

	tcpbpf "github.com/xtls/xray-core/transport/internet/tcp/ebpf"
)

// HookListen is a small indirection to avoid import cycles.
func HookListen(addr net.Addr) {
	tcpbpf.HookListen(addr)
}
