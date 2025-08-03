package ebpf

import (
	"context"
	"net"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	feature_stats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

// Manager 扩展的统计管理器，集成eBPF功能
type Manager struct {
	*stats.Manager

	ebpfStateManager StateManager
	enabled          bool
}

// NewManager 创建集成了eBPF的统计管理器
func NewManager(ctx context.Context, config *Config) (*Manager, error) {
	// 创建基础统计管理器
	baseManager, err := stats.NewManager(ctx, &config.Stats)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		Manager: baseManager,
		enabled: config.EnableEBPF,
	}

	// 如果启用eBPF，创建eBPF状态管理器
	if config.EnableEBPF {
		ebpfConfig := &StateManagerConfig{
			EnableEBPF:          config.EnableEBPF,
			FallbackToUserspace: config.FallbackToUserspace,
			CleanupInterval:     config.CleanupInterval,
			MaxConnections:      config.MaxConnections,
			MaxUsers:            config.MaxUsers,
			EnableDetailedStats: config.EnableDetailedStats,
			StatsUpdateInterval: config.StatsUpdateInterval,
			MaxErrorCount:       config.MaxErrorCount,
			ErrorResetInterval:  config.ErrorResetInterval,
		}

		stateManager, err := NewEBpfStateManager(ctx, ebpfConfig, baseManager)
		if err != nil {
			errors.LogInfo(ctx, "Failed to create eBPF state manager: ", err)
			if !config.FallbackToUserspace {
				return nil, err
			}
		} else {
			m.ebpfStateManager = stateManager
		}
	}

	return m, nil
}

// Start 启动管理器
func (m *Manager) Start() error {
	// 启动基础统计管理器
	if err := m.Manager.Start(); err != nil {
		return err
	}

	// 启动eBPF状态管理器
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.Start()
	}

	return nil
}

// Close 关闭管理器
func (m *Manager) Close() error {
	var errs []error

	// 关闭eBPF状态管理器
	if m.ebpfStateManager != nil {
		if err := m.ebpfStateManager.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	// 关闭基础统计管理器
	if err := m.Manager.Close(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return errs[0] // 返回第一个错误
	}

	return nil
}

// TrackConnection 跟踪新连接（eBPF扩展功能）
func (m *Manager) TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32 {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.TrackConnection(userUUID, protocol, localAddr, remoteAddr)
	}
	return 0
}

// CloseConnection 关闭连接跟踪（eBPF扩展功能）
func (m *Manager) CloseConnection(connID uint32) error {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.CloseConnection(connID)
	}
	return errors.New("eBPF connection tracking not available")
}

// UpdateTraffic 更新流量统计（eBPF扩展功能）
func (m *Manager) UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.UpdateTraffic(connID, uplinkBytes, downlinkBytes)
	}
	return errors.New("eBPF traffic tracking not available")
}

// UpdateTrafficState 更新流量状态（eBPF扩展功能）
func (m *Manager) UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.UpdateTrafficState(connID, trafficState)
	}
	return errors.New("eBPF traffic state tracking not available")
}

// GetConnectionStats 获取连接统计（eBPF扩展功能）
func (m *Manager) GetConnectionStats(connID uint32) (*ConnectionState, error) {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.GetConnectionStats(connID)
	}
	return nil, errors.New("eBPF connection stats not available")
}

// GetUserStats 获取用户统计（eBPF扩展功能）
func (m *Manager) GetUserStats(userUUID []byte) (*UserStats, error) {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.GetUserStats(userUUID)
	}
	return nil, errors.New("eBPF user stats not available")
}

// GetEBPFStats 获取eBPF统计信息
func (m *Manager) GetEBPFStats() (map[string]interface{}, error) {
	if m.ebpfStateManager != nil {
		return m.ebpfStateManager.GetGlobalStats()
	}
	return nil, errors.New("eBPF not available")
}

// IsEBPFEnabled 检查eBPF是否启用
func (m *Manager) IsEBPFEnabled() bool {
	return m.ebpfStateManager != nil && m.ebpfStateManager.IsEnabled()
}

// Config eBPF集成配置
type Config struct {
	// 基础统计配置
	Stats stats.Config `json:"stats"`

	// eBPF配置
	EnableEBPF          bool          `json:"enable_ebpf"`
	FallbackToUserspace bool          `json:"fallback_to_userspace"`
	CleanupInterval     time.Duration `json:"cleanup_interval"`
	MaxConnections      uint32        `json:"max_connections"`
	MaxUsers            uint32        `json:"max_users"`
	EnableDetailedStats bool          `json:"enable_detailed_stats"`
	StatsUpdateInterval time.Duration `json:"stats_update_interval"`
	MaxErrorCount       uint64        `json:"max_error_count"`
	ErrorResetInterval  time.Duration `json:"error_reset_interval"`
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		Stats:               stats.Config{},
		EnableEBPF:          true,
		FallbackToUserspace: true,
		CleanupInterval:     60 * time.Second,
		MaxConnections:      65536,
		MaxUsers:            8192,
		EnableDetailedStats: true,
		StatsUpdateInterval: 10 * time.Second,
		MaxErrorCount:       100,
		ErrorResetInterval:  5 * time.Minute,
	}
}

// ConnectionTracker 连接跟踪器接口
type ConnectionTracker interface {
	TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32
	CloseConnection(connID uint32) error
	UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error
	UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error
	GetConnectionStats(connID uint32) (*ConnectionState, error)
	GetUserStats(userUUID []byte) (*UserStats, error)
	GetGlobalStats() (map[string]interface{}, error)
	IsEnabled() bool
}

// TrafficStateTracker 流量状态跟踪器接口
type TrafficStateTracker interface {
	UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error
	GetTrafficState(connID uint32) (*TrafficState, error)
}

// StatsIntegrator 统计集成器接口
type StatsIntegrator interface {
	// 传统统计方法
	RegisterCounter(string) (feature_stats.Counter, error)
	GetCounter(string) feature_stats.Counter

	// eBPF增强方法
	TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32
	UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error
	GetConnectionStats(connID uint32) (*ConnectionState, error)

	// 统一查询接口
	GetAllStats() (map[string]interface{}, error)
}

// 确保Manager实现了相关接口
var (
	_ feature_stats.Manager = (*Manager)(nil)
	// ConnectionTracker和StatsIntegrator接口稍后验证
	// _ ConnectionTracker     = (*Manager)(nil)
	// _ StatsIntegrator       = (*Manager)(nil)
)

// GetAllStats 获取所有统计信息（包括传统和eBPF）
func (m *Manager) GetAllStats() (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// 获取传统统计
	result["traditional"] = make(map[string]interface{})
	m.Manager.VisitCounters(func(name string, counter feature_stats.Counter) bool {
		if traditionalStats, ok := result["traditional"].(map[string]interface{}); ok {
			traditionalStats[name] = counter.Value()
		}
		return true
	})

	// 获取eBPF统计
	if m.ebpfStateManager != nil {
		if ebpfStats, err := m.ebpfStateManager.GetGlobalStats(); err == nil {
			result["ebpf"] = ebpfStats
		}
	}

	// 获取管理器统计
	if m.ebpfStateManager != nil {
		if managerStats, ok := m.ebpfStateManager.(*EBpfStateManager); ok {
			result["manager"] = managerStats.GetManagerStats()
		}
	}

	result["enabled"] = m.IsEBPFEnabled()

	return result, nil
}

// 初始化函数，注册到common系统
func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewManager(ctx, config.(*Config))
	}))
}
