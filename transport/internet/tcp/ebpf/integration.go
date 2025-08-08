package ebpf

import (
	"context"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
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

// 注意：客户端出站 eBPF 优化已禁用，此处移除对 transport/internet 的依赖以避免导入环。

// OptimizeRealityHandshake 优化REALITY握手过程
// 注意：根据项目要求，eBPF优化主要针对服务端入站，客户端出站优化已禁用
func OptimizeRealityHandshake(ctx context.Context, conn net.Conn, config interface{}) error {
	// 客户端出站eBPF优化已禁用，专注于服务端入站优化
	// 保持函数接口不变，但内部实现为空，避免影响现有代码
	return nil
}

// MarkRealityHandshakeComplete 标记REALITY握手完成 🔒
// 注意：根据项目要求，eBPF优化主要针对服务端入站，客户端出站优化已禁用
func MarkRealityHandshakeComplete(ctx context.Context, conn net.Conn) error {
	// 客户端出站eBPF优化已禁用，专注于服务端入站优化
	// 保持函数接口不变，但内部实现为空，避免影响现有代码
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
