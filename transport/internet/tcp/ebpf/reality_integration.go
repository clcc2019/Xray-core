//go:build linux
// +build linux

package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
)

// RealityEBPFManager REALITY eBPF管理器
type RealityEBPFManager struct {
	mu          sync.RWMutex
	enabled     bool
	connections map[string]*RealityConnection
	stats       *RealityStats
	lastCleanup time.Time
}

// RealityConnection REALITY连接信息
type RealityConnection struct {
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Created    time.Time
	LastUsed   time.Time
	BytesSent  int64
	BytesRecv  int64
	FastPath   bool
}

// RealityStats REALITY统计信息
type RealityStats struct {
	TotalConnections    int64
	ActiveConnections   int64
	FastPathConnections int64
	BytesProcessed      int64
	Handshakes          int64
}

var (
	globalRealityManager *RealityEBPFManager
	realityManagerOnce   sync.Once
)

// GetRealityEBPFManager 获取全局REALITY eBPF管理器
func GetRealityEBPFManager() *RealityEBPFManager {
	realityManagerOnce.Do(func() {
		globalRealityManager = &RealityEBPFManager{
			enabled:     isEBPFEnabled(),
			connections: make(map[string]*RealityConnection),
			stats:       &RealityStats{},
			lastCleanup: time.Now(),
		}
		go globalRealityManager.backgroundCleanup()
	})
	return globalRealityManager
}

// EnableRealityEBPF 启用REALITY eBPF优化
func EnableRealityEBPF(ctx context.Context, conn net.Conn, destination xnet.Destination) {
	manager := GetRealityEBPFManager()
	if !manager.enabled {
		return
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	connKey := fmt.Sprintf("%s->%s", conn.LocalAddr().String(), conn.RemoteAddr().String())

	// 检查是否是REALITY连接 (端口443)
	if destination.Port == 443 {
		realityConn := &RealityConnection{
			LocalAddr:  conn.LocalAddr(),
			RemoteAddr: conn.RemoteAddr(),
			Created:    time.Now(),
			LastUsed:   time.Now(),
			FastPath:   true,
		}

		manager.connections[connKey] = realityConn
		manager.stats.TotalConnections++
		manager.stats.ActiveConnections++
		manager.stats.FastPathConnections++

		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("REALITY eBPF优化已启用: %s", connKey),
		})
	}
}

// UpdateRealityConnection 更新REALITY连接统计
func UpdateRealityConnection(ctx context.Context, conn net.Conn, bytesSent, bytesRecv int64) {
	manager := GetRealityEBPFManager()
	if !manager.enabled {
		return
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()

	connKey := fmt.Sprintf("%s->%s", conn.LocalAddr().String(), conn.RemoteAddr().String())

	if realityConn, exists := manager.connections[connKey]; exists {
		realityConn.LastUsed = time.Now()
		realityConn.BytesSent += bytesSent
		realityConn.BytesRecv += bytesRecv
		manager.stats.BytesProcessed += bytesSent + bytesRecv
	}
}

// GetRealityStats 获取REALITY统计信息
func GetRealityStats() *RealityStats {
	manager := GetRealityEBPFManager()
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	return &RealityStats{
		TotalConnections:    manager.stats.TotalConnections,
		ActiveConnections:   manager.stats.ActiveConnections,
		FastPathConnections: manager.stats.FastPathConnections,
		BytesProcessed:      manager.stats.BytesProcessed,
		Handshakes:          manager.stats.Handshakes,
	}
}

// backgroundCleanup 后台清理过期连接
func (m *RealityEBPFManager) backgroundCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()

		now := time.Now()
		expiredKeys := []string{}

		for key, conn := range m.connections {
			if now.Sub(conn.LastUsed) > 30*time.Minute {
				expiredKeys = append(expiredKeys, key)
			}
		}

		for _, key := range expiredKeys {
			delete(m.connections, key)
			m.stats.ActiveConnections--
		}

		m.lastCleanup = now
		m.mu.Unlock()
	}
}

// isEBPFEnabled 检查eBPF是否启用
func isEBPFEnabled() bool {
	return os.Getenv("XRAY_EBPF") == "1"
}
