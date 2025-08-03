//go:build !linux

package outbound

import (
	"context"
	"net"

	xraynet "github.com/xtls/xray-core/common/net"
)

// EnableVMessEBPFAcceleration fallback for non-Linux platforms
func EnableVMessEBPFAcceleration(ctx context.Context, conn net.Conn, target xraynet.Destination) {
	// No-op on non-Linux platforms
}