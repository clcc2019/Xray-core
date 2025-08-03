package ebpf

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
)

var (
	// 全局TCP+REALITY加速器实例
	globalAccelerator *TCPRealityAccelerator
	acceleratorOnce   sync.Once
)

// GetGlobalAccelerator 获取全局加速器实例
func GetGlobalAccelerator() *TCPRealityAccelerator {
	acceleratorOnce.Do(func() {
		globalAccelerator = NewTCPRealityAccelerator()
	})
	return globalAccelerator
}

// InitAccelerator 初始化加速器
func InitAccelerator(ctx context.Context) error {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		errors.LogInfo(ctx, "TCP REALITY eBPF accelerator not available on this platform")
		return nil
	}

	if err := accelerator.Start(ctx); err != nil {
		errors.LogWarning(ctx, "Failed to start TCP REALITY eBPF accelerator: ", err)
		return err
	}

	errors.LogInfo(ctx, "TCP REALITY eBPF accelerator initialized successfully")
	return nil
}

// AccelerateDialedConnection 为已拨号的连接启用加速
func AccelerateDialedConnection(ctx context.Context, conn net.Conn, streamSettings *internet.MemoryStreamConfig) error {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return nil // 静默跳过，不影响正常功能
	}

	// 检查是否启用了REALITY
	realityEnabled := false
	if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		realityEnabled = true
		errors.LogInfo(ctx, "TCP connection to ", conn.RemoteAddr().String(), " using REALITY encryption")
	}

	// 为连接启用eBPF加速
	if err := accelerator.AccelerateConnection(conn, realityEnabled); err != nil {
		errors.LogDebug(ctx, "Failed to accelerate connection: ", err)
		return nil // 不影响正常连接
	}

	// 启用TCP拥塞控制优化
	if destination, err := xnet.ParseDestination(conn.RemoteAddr().String()); err == nil {
		EnableTCPCongestionControl(ctx, conn, destination)
	}

	if realityEnabled {
		errors.LogInfo(ctx, "TCP+REALITY eBPF acceleration enabled for ", conn.RemoteAddr().String())
	} else {
		errors.LogDebug(ctx, "TCP eBPF acceleration enabled for ", conn.RemoteAddr().String(), " (without REALITY)")
	}
	return nil
}

// OptimizeRealityHandshake 优化REALITY握手过程
func OptimizeRealityHandshake(ctx context.Context, conn net.Conn, config interface{}) error {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return nil
	}

	if err := accelerator.OptimizeHandshake(conn, config); err != nil {
		errors.LogDebug(ctx, "Failed to optimize REALITY handshake: ", err)
		return nil // 不影响正常握手
	}

	errors.LogDebug(ctx, "REALITY handshake optimized for ", conn.RemoteAddr().String())
	return nil
}

// MarkRealityHandshakeComplete 标记REALITY握手完成 🔒
// 这个方法应该在REALITY握手成功验证后调用
func MarkRealityHandshakeComplete(ctx context.Context, conn net.Conn) error {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return nil
	}

	if err := accelerator.MarkRealityVerified(conn); err != nil {
		errors.LogDebug(ctx, "Failed to mark REALITY handshake as verified: ", err)
		return nil // 不影响正常连接
	}

	errors.LogInfo(ctx, "🔒 REALITY handshake marked as verified for ", conn.RemoteAddr().String())
	return nil
}

// GetConnectionStats 获取连接统计信息
func GetConnectionStats(conn net.Conn) (*AcceleratedConnection, error) {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return nil, errors.New("accelerator not enabled")
	}

	return accelerator.GetConnectionStats(conn)
}

// GetAcceleratorStats 获取加速器总体统计信息
func GetAcceleratorStats() (*TCPRealityStats, error) {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return nil, errors.New("accelerator not enabled")
	}

	return accelerator.GetStats()
}

// IsAccelerated 检查连接是否已加速
func IsAccelerated(conn net.Conn) bool {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return false
	}

	_, err := accelerator.GetConnectionStats(conn)
	return err == nil
}

// GetAcceleratorInfo 获取加速器信息
func GetAcceleratorInfo() map[string]interface{} {
	accelerator := GetGlobalAccelerator()

	info := map[string]interface{}{
		"enabled":          accelerator.IsEnabled(),
		"connection_count": accelerator.GetConnectionCount(),
		"hot_connections":  accelerator.GetHotConnections(),
		"platform_support": true,
	}

	if accelerator.IsEnabled() {
		if stats, err := accelerator.GetStats(); err == nil {
			info["stats"] = stats
		}
	}

	return info
}

// UpdateAcceleratorConfig 更新加速器配置
func UpdateAcceleratorConfig(config *TCPRealityConfig) error {
	accelerator := GetGlobalAccelerator()
	if !accelerator.IsEnabled() {
		return errors.New("accelerator not enabled")
	}

	return accelerator.UpdateConfig(config)
}

// CleanupAccelerator 清理加速器资源
func CleanupAccelerator() error {
	if globalAccelerator != nil && globalAccelerator.IsEnabled() {
		return globalAccelerator.Stop()
	}
	return nil
}

// TCPRealityAcceleratorInterface 定义加速器接口
type TCPRealityAcceleratorInterface interface {
	Start(ctx context.Context) error
	Stop() error
	AccelerateConnection(conn net.Conn, realityEnabled bool) error
	OptimizeHandshake(conn net.Conn, config interface{}) error
	GetConnectionStats(conn net.Conn) (*AcceleratedConnection, error)
	GetStats() (*TCPRealityStats, error)
	UpdateConfig(config *TCPRealityConfig) error
	GetConnectionCount() int
	IsEnabled() bool
	GetHotConnections() []string
}

// 确保实现了接口
var _ TCPRealityAcceleratorInterface = (*TCPRealityAccelerator)(nil)
