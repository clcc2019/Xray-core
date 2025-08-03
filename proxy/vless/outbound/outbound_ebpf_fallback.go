//go:build !linux

package outbound

import (
	"context"
	"net"
)

// EnableVLESSEBPFAcceleration fallback for non-Linux platforms
func EnableVLESSEBPFAcceleration(ctx context.Context, conn net.Conn, sni string) {
	// No-op on non-Linux platforms
}