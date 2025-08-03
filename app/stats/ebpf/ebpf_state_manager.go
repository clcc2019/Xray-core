package ebpf

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

// StateManager eBPF状态管理器接口
type StateManager interface {
	common.Runnable

	// 连接管理
	TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32
	CloseConnection(connID uint32) error

	// 流量更新
	UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error
	UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error

	// 统计查询
	GetConnectionStats(connID uint32) (*ConnectionState, error)
	GetUserStats(userUUID []byte) (*UserStats, error)
	GetGlobalStats() (map[string]interface{}, error)

	// 状态检查
	IsEnabled() bool
}

// EBpfStateManager eBPF状态管理器实现
type EBpfStateManager struct {
	sync.RWMutex

	tracker             *EBpfConnectionTracker
	statsManager        stats.Manager
	enabled             bool
	fallbackToUserspace bool

	// 性能统计
	operationCount uint64
	errorCount     uint64
	lastErrorTime  time.Time

	// 配置
	config *StateManagerConfig
}

// StateManagerConfig 状态管理器配置
type StateManagerConfig struct {
	// eBPF配置
	EnableEBPF          bool `json:"enable_ebpf"`
	FallbackToUserspace bool `json:"fallback_to_userspace"`

	// 性能配置
	CleanupInterval time.Duration `json:"cleanup_interval"`
	MaxConnections  uint32        `json:"max_connections"`
	MaxUsers        uint32        `json:"max_users"`

	// 统计配置
	EnableDetailedStats bool          `json:"enable_detailed_stats"`
	StatsUpdateInterval time.Duration `json:"stats_update_interval"`

	// 错误处理
	MaxErrorCount      uint64        `json:"max_error_count"`
	ErrorResetInterval time.Duration `json:"error_reset_interval"`
}

// DefaultStateManagerConfig 默认配置
func DefaultStateManagerConfig() *StateManagerConfig {
	return &StateManagerConfig{
		EnableEBPF:          true,
		FallbackToUserspace: true,
		CleanupInterval:     60 * time.Second,
		MaxConnections:      65536,
		MaxUsers:            8192,
		EnableDetailedStats: true,
		StatsUpdateInterval: 10 * time.Second,
		MaxErrorCount:       100,
		ErrorResetInterval:  300 * time.Second,
	}
}

// NewEBpfStateManager 创建新的eBPF状态管理器
func NewEBpfStateManager(ctx context.Context, config *StateManagerConfig, statsManager stats.Manager) (*EBpfStateManager, error) {
	if config == nil {
		config = DefaultStateManagerConfig()
	}

	manager := &EBpfStateManager{
		statsManager:        statsManager,
		enabled:             false,
		fallbackToUserspace: config.FallbackToUserspace,
		config:              config,
	}

	if config.EnableEBPF {
		// 尝试创建eBPF连接跟踪器
		tracker, err := NewEBpfConnectionTracker()
		if err != nil {
			errors.LogInfo(ctx, "Failed to create eBPF connection tracker: ", err)
			if !config.FallbackToUserspace {
				return nil, err
			}
		} else {
			manager.tracker = tracker
			manager.enabled = tracker.IsEnabled()
		}
	}

	errors.LogInfo(ctx, "eBPF state manager created, enabled: ", manager.enabled)
	return manager, nil
}

// Start 启动状态管理器
func (m *EBpfStateManager) Start() error {
	// 启动统计更新协程
	if m.config.EnableDetailedStats {
		go m.runStatsUpdateLoop()
	}

	// 启动错误重置协程
	go m.runErrorResetLoop()

	return nil
}

// Close 关闭状态管理器
func (m *EBpfStateManager) Close() error {
	if m.tracker != nil {
		return m.tracker.Close()
	}
	return nil
}

// TrackConnection 跟踪新连接
func (m *EBpfStateManager) TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32 {
	m.operationCount++

	if m.enabled && m.tracker != nil {
		connID := m.tracker.TrackConnection(userUUID, protocol, localAddr, remoteAddr)
		if connID != 0 {
			// 同时更新传统统计系统
			m.updateLegacyStats(userUUID, "connection", 1)
			return connID
		}
	}

	// Fallback到用户态实现
	if m.fallbackToUserspace {
		return m.trackConnectionUserspace(userUUID, protocol, localAddr, remoteAddr)
	}

	return 0
}

// CloseConnection 关闭连接跟踪
func (m *EBpfStateManager) CloseConnection(connID uint32) error {
	m.operationCount++

	if m.enabled && m.tracker != nil {
		if err := m.tracker.CloseConnection(connID); err == nil {
			return nil
		} else {
			m.recordError(err)
		}
	}

	// Fallback到用户态实现
	if m.fallbackToUserspace {
		return m.closeConnectionUserspace(connID)
	}

	return errors.New("connection tracking not available")
}

// UpdateTraffic 更新流量统计
func (m *EBpfStateManager) UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error {
	m.operationCount++

	if m.enabled && m.tracker != nil {
		if err := m.tracker.UpdateTraffic(connID, uplinkBytes, downlinkBytes); err == nil {
			return nil
		} else {
			m.recordError(err)
		}
	}

	// Fallback到用户态实现
	if m.fallbackToUserspace {
		return m.updateTrafficUserspace(connID, uplinkBytes, downlinkBytes)
	}

	return errors.New("traffic tracking not available")
}

// UpdateTrafficState 更新流量状态
func (m *EBpfStateManager) UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error {
	m.operationCount++

	if m.enabled && m.tracker != nil {
		if err := m.tracker.UpdateTrafficState(connID, trafficState); err == nil {
			return nil
		} else {
			m.recordError(err)
		}
	}

	// Fallback到用户态实现
	if m.fallbackToUserspace {
		return m.updateTrafficStateUserspace(connID, trafficState)
	}

	return errors.New("traffic state tracking not available")
}

// GetConnectionStats 获取连接统计
func (m *EBpfStateManager) GetConnectionStats(connID uint32) (*ConnectionState, error) {
	if m.enabled && m.tracker != nil {
		if stats, err := m.tracker.GetConnectionStats(connID); err == nil {
			return stats, nil
		} else {
			m.recordError(err)
		}
	}

	// Fallback到用户态实现
	if m.fallbackToUserspace {
		return m.getConnectionStatsUserspace(connID)
	}

	return nil, errors.New("connection stats not available")
}

// GetUserStats 获取用户统计
func (m *EBpfStateManager) GetUserStats(userUUID []byte) (*UserStats, error) {
	if m.enabled && m.tracker != nil {
		if stats, err := m.tracker.GetUserStats(userUUID); err == nil {
			return stats, nil
		} else {
			m.recordError(err)
		}
	}

	// Fallback到用户态实现
	if m.fallbackToUserspace {
		return m.getUserStatsUserspace(userUUID)
	}

	return nil, errors.New("user stats not available")
}

// GetGlobalStats 获取全局统计
func (m *EBpfStateManager) GetGlobalStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// 基本信息
	stats["enabled"] = m.enabled
	stats["fallback_enabled"] = m.fallbackToUserspace
	stats["operation_count"] = m.operationCount
	stats["error_count"] = m.errorCount

	if m.enabled && m.tracker != nil {
		if ebpfStats, err := m.tracker.GetGlobalStats(); err == nil {
			for k, v := range ebpfStats {
				stats["ebpf_"+k] = v
			}
		} else {
			m.recordError(err)
		}
	}

	// 添加用户态统计
	if m.fallbackToUserspace {
		userspaceStats := m.getGlobalStatsUserspace()
		for k, v := range userspaceStats {
			stats["userspace_"+k] = v
		}
	}

	return stats, nil
}

// IsEnabled 检查是否启用
func (m *EBpfStateManager) IsEnabled() bool {
	return m.enabled || m.fallbackToUserspace
}

// GetManagerStats 获取管理器本身的统计信息
func (m *EBpfStateManager) GetManagerStats() map[string]interface{} {
	m.RLock()
	defer m.RUnlock()

	stats := make(map[string]interface{})
	stats["enabled"] = m.enabled
	stats["fallback_enabled"] = m.fallbackToUserspace
	stats["operation_count"] = m.operationCount
	stats["error_count"] = m.errorCount
	stats["last_error_time"] = m.lastErrorTime.Format(time.RFC3339)

	if m.config != nil {
		stats["config"] = map[string]interface{}{
			"enable_ebpf":           m.config.EnableEBPF,
			"fallback_to_userspace": m.config.FallbackToUserspace,
			"cleanup_interval":      m.config.CleanupInterval.String(),
			"max_connections":       m.config.MaxConnections,
			"max_users":             m.config.MaxUsers,
			"enable_detailed_stats": m.config.EnableDetailedStats,
			"stats_update_interval": m.config.StatsUpdateInterval.String(),
		}
	}

	return stats
}

// 私有方法

func (m *EBpfStateManager) recordError(err error) {
	m.Lock()
	m.errorCount++
	m.lastErrorTime = time.Now()
	m.Unlock()

	// 如果错误太多，可能需要禁用eBPF
	if m.errorCount > m.config.MaxErrorCount {
		errors.LogWarning(context.Background(), "Too many eBPF errors, consider disabling eBPF")
	}
}

func (m *EBpfStateManager) updateLegacyStats(userUUID []byte, statType string, delta int64) {
	if m.statsManager == nil {
		return
	}

	// 构造统计名称
	// 格式: user>>>[uuid]>>>traffic>>>uplink
	// 这里简化实现，实际需要根据具体需求调整
	counterName := "user>>>" + string(userUUID) + ">>>traffic>>>" + statType

	counter, err := stats.GetOrRegisterCounter(m.statsManager, counterName)
	if err == nil {
		counter.Add(delta)
	}
}

func (m *EBpfStateManager) runStatsUpdateLoop() {
	ticker := time.NewTicker(m.config.StatsUpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		// 定期同步eBPF统计到传统统计系统
		m.syncStatsToLegacySystem()
	}
}

func (m *EBpfStateManager) runErrorResetLoop() {
	ticker := time.NewTicker(m.config.ErrorResetInterval)
	defer ticker.Stop()

	for range ticker.C {
		m.Lock()
		if time.Since(m.lastErrorTime) > m.config.ErrorResetInterval {
			m.errorCount = 0
		}
		m.Unlock()
	}
}

func (m *EBpfStateManager) syncStatsToLegacySystem() {
	// 实现eBPF统计到传统系统的同步
	// 这里是占位符实现
}

// Userspace fallback实现（占位符）

func (m *EBpfStateManager) trackConnectionUserspace(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32 {
	// 用户态连接跟踪实现
	return 0
}

func (m *EBpfStateManager) closeConnectionUserspace(connID uint32) error {
	// 用户态连接关闭实现
	return nil
}

func (m *EBpfStateManager) updateTrafficUserspace(connID uint32, uplinkBytes, downlinkBytes uint64) error {
	// 用户态流量更新实现
	return nil
}

func (m *EBpfStateManager) updateTrafficStateUserspace(connID uint32, trafficState *proxy.TrafficState) error {
	// 用户态流量状态更新实现
	return nil
}

func (m *EBpfStateManager) getConnectionStatsUserspace(connID uint32) (*ConnectionState, error) {
	// 用户态连接统计查询实现
	return nil, errors.New("userspace connection stats not implemented")
}

func (m *EBpfStateManager) getUserStatsUserspace(userUUID []byte) (*UserStats, error) {
	// 用户态用户统计查询实现
	return nil, errors.New("userspace user stats not implemented")
}

func (m *EBpfStateManager) getGlobalStatsUserspace() map[string]interface{} {
	// 用户态全局统计查询实现
	return make(map[string]interface{})
}
