//go:build !linux || !amd64

package ebpf

import (
	"context"
	"net"
	"time"
)

// TCPRealityAccelerator fallback implementation
type TCPRealityAccelerator struct {
	enabled bool
}

// AcceleratedConnection fallback connection info
type AcceleratedConnection struct {
	ID             string    `json:"id"`
	LocalAddr      string    `json:"local_addr"`
	RemoteAddr     string    `json:"remote_addr"`
	State          int       `json:"state"`
	RealityEnabled bool      `json:"reality_enabled"`
	FastPathCount  int       `json:"fast_path_count"`
	LastActivity   time.Time `json:"last_activity"`
	BytesSent      uint64    `json:"bytes_sent"`
	BytesReceived  uint64    `json:"bytes_received"`
	IsHot          bool      `json:"is_hot"`
}

// TCPRealityStats fallback stats
type TCPRealityStats struct {
	TotalConnections       uint64 `json:"total_connections"`
	RealityConnections     uint64 `json:"reality_connections"`
	FastPathHits           uint64 `json:"fast_path_hits"`
	SynAccelerations       uint64 `json:"syn_accelerations"`
	HandshakeAccelerations uint64 `json:"handshake_accelerations"`
	DataFastForwards       uint64 `json:"data_fast_forwards"`
	SessionReuses          uint64 `json:"session_reuses"`
	ConnectionDrops        uint64 `json:"connection_drops"`
}

// TCPRealityConfig fallback config
type TCPRealityConfig struct {
	AccelerationEnabled bool `json:"acceleration_enabled"`
	FastPathEnabled     bool `json:"fast_path_enabled"`
	SynAcceleration     bool `json:"syn_acceleration"`
	RealityOptimization bool `json:"reality_optimization"`
	MaxConnections      int  `json:"max_connections"`
	SessionTimeout      int  `json:"session_timeout"`
}

// NewTCPRealityAccelerator creates fallback accelerator
func NewTCPRealityAccelerator() *TCPRealityAccelerator {
	return &TCPRealityAccelerator{
		enabled: false, // fallback is disabled
	}
}

// Start fallback implementation
func (a *TCPRealityAccelerator) Start(ctx context.Context) error {
	return nil // no-op
}

// Stop fallback implementation
func (a *TCPRealityAccelerator) Stop() error {
	return nil // no-op
}

// AccelerateConnection fallback implementation
func (a *TCPRealityAccelerator) AccelerateConnection(conn net.Conn, realityEnabled bool) error {
	return nil // no-op
}

// OptimizeHandshake fallback implementation
func (a *TCPRealityAccelerator) OptimizeHandshake(conn net.Conn, config interface{}) error {
	return nil // no-op
}

// GetConnectionStats fallback implementation
func (a *TCPRealityAccelerator) GetConnectionStats(conn net.Conn) (*AcceleratedConnection, error) {
	return &AcceleratedConnection{}, nil
}

// GetStats fallback implementation
func (a *TCPRealityAccelerator) GetStats() (*TCPRealityStats, error) {
	return &TCPRealityStats{}, nil
}

// UpdateConfig fallback implementation
func (a *TCPRealityAccelerator) UpdateConfig(config *TCPRealityConfig) error {
	return nil // no-op
}

// GetConnectionCount fallback implementation
func (a *TCPRealityAccelerator) GetConnectionCount() int {
	return 0
}

// IsEnabled fallback implementation
func (a *TCPRealityAccelerator) IsEnabled() bool {
	return false
}

// GetHotConnections fallback implementation
func (a *TCPRealityAccelerator) GetHotConnections() []string {
	return []string{}
}

// MarkRealityVerified fallback implementation
func (a *TCPRealityAccelerator) MarkRealityVerified(conn net.Conn) error {
	return nil // no-op
}
