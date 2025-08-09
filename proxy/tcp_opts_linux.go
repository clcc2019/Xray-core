//go:build linux

package proxy

import (
	"net"
	"os"
	"strconv"
	"time"

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
			if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1); err == nil {
				// optional: start draining MSG_ERRQUEUE to prevent buffer retention
				if os.Getenv("XRAY_SO_ZEROCOPY_DRAIN") != "0" && os.Getenv("XRAY_SO_ZEROCOPY_DRAIN") != "false" {
					go drainZeroCopyErrQueue(fd)
				}
			}
			return nil
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

// drainZeroCopyErrQueue continuously drains MSG_ERRQUEUE for SO_ZEROCOPY
// Note: We cannot dup fd inside Control; here we assume fd stays valid for lifetime of connection.
// If recvmsg returns EAGAIN or not supported, we back off and retry.
func drainZeroCopyErrQueue(fd int) {
	// set non-blocking to avoid stalls
	_ = unix.SetNonblock(fd, true)
	buf := make([]byte, 256)
	oob := make([]byte, 256)
	for {
		// MSG_ERRQUEUE fetches tx completion notifications for zerocopy
		_, _, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE)
		if err != nil {
			// EAGAIN / EWOULDBLOCK: nothing to drain, small sleep
			// Any other error: keep trying but with larger backoff
			time.Sleep(5 * time.Millisecond)
		} else {
			// drained one notification, yield briefly
			time.Sleep(1 * time.Millisecond)
		}
	}
}
