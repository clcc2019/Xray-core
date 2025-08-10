//go:build !linux

package proxy

import "net"

// 非 Linux 平台：no-op，避免构建错误
func OptimizeTCPForDirectCopy(conn net.Conn) {}
