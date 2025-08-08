//go:build linux

package tcpinfo

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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
		var rttUs uint32
		var okFlag bool
		rc, err := sc.SyscallConn()
		if err != nil {
			return 0, false
		}
		_ = rc.Control(func(fd uintptr) {
			var info unix.TCPInfo
			if err := unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO, &info); err == nil {
				rttUs = info.Rtt
				okFlag = true
			}
		})
		if okFlag && rttUs > 0 {
			return time.Duration(rttUs) * time.Microsecond, true
		}
		return 0, false
	}

	// Next, if it exposes NetConn(), recurse into underlying
	type netConner interface{ NetConn() net.Conn }
	if nc, ok := any(conn).(netConner); ok {
		return DetectRTT(nc.NetConn())
	}

	return 0, false
}
