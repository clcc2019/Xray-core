//go:build !linux

package outbound

import (
	"context"
	"net"
)

func EnableVLESSEBPFAcceleration(ctx context.Context, conn net.Conn, sni string) {}
