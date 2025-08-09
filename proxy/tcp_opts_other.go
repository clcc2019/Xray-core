//go:build !linux

package proxy

import "net"

func optimizeTCPForDirectCopy(conn net.Conn) {}
