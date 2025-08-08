//go:build linux

package tcpinfo

import (
	"net"
	"syscall"
	"time"
)

// DetectRTT attempts to fetch smoothed RTT of a TCP connection via TCP_INFO.
// Returns (rtt, true) on success; otherwise (0, false).
func DetectRTT(conn net.Conn) (time.Duration, bool) {
	if conn == nil {
		return 0, false
	}

	// Unwrap common wrappers to try to reach a type exposing SyscallConn or NetConn
	// First, if the connection provides SyscallConn directly
	type syscallConner interface {
		SyscallConn() (syscall.RawConn, error)
	}
	if sc, ok := conn.(syscallConner); ok {
		// 暂时禁用直接读取 TCP_INFO，避免在交叉编译链路上引入不兼容
		_, _ = sc.SyscallConn()
		return 0, false
	}

	// Next, if it exposes NetConn(), recurse into underlying
	type netConner interface{ NetConn() net.Conn }
	if nc, ok := any(conn).(netConner); ok {
		return DetectRTT(nc.NetConn())
	}

	return 0, false
}
