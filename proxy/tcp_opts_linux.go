//go:build linux

package proxy

import (
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// optimizeTCPForDirectCopy applies optional TCP/socket options to improve direct-copy phase.
// Controlled via env flags; failures are ignored.
func optimizeTCPForDirectCopy(conn net.Conn) {
	sc, ok := conn.(interface{ SyscallConn() (syscallConn, error) })
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	// TCP_QUICKACK
	if v := os.Getenv("XRAY_TCP_QUICKACK"); v != "" && v != "0" && v != "false" {
		_ = controlFD(raw, func(fd int) error {
			return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
		})
	}
	// SO_ZEROCOPY (experimental)
	if v := os.Getenv("XRAY_SO_ZEROCOPY"); v != "" && v != "0" && v != "false" {
		_ = controlFD(raw, func(fd int) error {
			return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1)
		})
	}
	// TCP_NOTSENT_LOWAT (bytes). Example: XRAY_TCP_NOTSENT_LOWAT=16384
	if s := os.Getenv("XRAY_TCP_NOTSENT_LOWAT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			_ = controlFD(raw, func(fd int) error {
				return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
			})
		}
	}
}

type syscallConn interface{ Control(func(fd uintptr)) error }

func controlFD(sc syscallConn, fn func(fd int) error) error {
	var ret error
	_ = sc.Control(func(fd uintptr) {
		ret = fn(int(fd))
	})
	return ret
}
