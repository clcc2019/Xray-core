//go:build !linux

package tcpinfo

import (
	"net"
	"time"
)

func DetectRTT(conn net.Conn) (time.Duration, bool) {
	return 0, false
}
