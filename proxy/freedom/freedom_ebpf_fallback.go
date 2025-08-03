//go:build !linux

package freedom

import (
	"context"
	"net"
)

// EnableEBPFAcceleration fallback for non-Linux platforms
func EnableEBPFAcceleration(ctx context.Context, conn net.Conn) {
	// No-op on non-Linux platforms
}