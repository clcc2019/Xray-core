//go:build !linux

package ebpfhooks

import "net"

func HookListen(addr net.Addr) {}
