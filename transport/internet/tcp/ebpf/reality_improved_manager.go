//go:build linux
// +build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// RealityImprovedManager 改进的REALITY管理器
type RealityImprovedManager struct {
	mu      sync.RWMutex
	enabled bool
	ctx     context.Context
	cancel  context.CancelFunc

	// eBPF映射表
	connections    *ebpf.Map
	stats          *ebpf.Map
	uuidWhitelist  *ebpf.Map
	securityEvents *ebpf.Map

	// 配置
	uuidWhitelistEnabled bool
	retryLimit           int
	handshakeTimeout     time.Duration
	zeroCopyEnabled      bool

	// 统计信息
	statsData *RealityImprovedStats

	// ringbuf reader
	realityEventsReader *ringbuf.Reader
}

// RealityImprovedStats 改进的REALITY统计信息
type RealityImprovedStats struct {
	TotalConnections     uint64
	ValidConnections     uint64
	InvalidConnections   uint64
	SuccessfulHandshakes uint64
	FailedHandshakes     uint64
	RetryAttempts        uint64
	ZeroCopyOperations   uint64
	SecurityViolations   uint64
}

// NewRealityImprovedManager 创建改进的REALITY管理器
func NewRealityImprovedManager() *RealityImprovedManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &RealityImprovedManager{
		ctx:                  ctx,
		cancel:               cancel,
		uuidWhitelistEnabled: true,
		retryLimit:           5,
		handshakeTimeout:     30 * time.Second,
		zeroCopyEnabled:      true,
		statsData:            &RealityImprovedStats{},
	}
}

// Enable 启用改进的REALITY管理器
func (rim *RealityImprovedManager) Enable() error {
	rim.mu.Lock()
	defer rim.mu.Unlock()

	if rim.enabled {
		return nil
	}

	// 检查eBPF支持
	if os.Getenv("XRAY_EBPF") != "1" {
		return fmt.Errorf("eBPF not enabled")
	}

	// 加载eBPF映射表
	if err := rim.loadMaps(); err != nil {
		log.Printf("Warning: Failed to load eBPF maps: %v. Continuing with userspace optimization only", err)
		// 继续使用用户空间优化
	}

	// 初始化UUID白名单
	if err := rim.initializeUUIDWhitelist(); err != nil {
		log.Printf("Warning: Failed to initialize UUID whitelist: %v", err)
	}

	// 启动统计更新协程
	go rim.updateStatsLoop()
	// 启动事件读取协程
	go rim.consumeEvents()

	rim.enabled = true
	log.Printf("Reality Improved Manager enabled")
	return nil
}

// Disable 禁用改进的REALITY管理器
func (rim *RealityImprovedManager) Disable() error {
	rim.mu.Lock()
	defer rim.mu.Unlock()

	if !rim.enabled {
		return nil
	}

	rim.cancel()
	if rim.realityEventsReader != nil {
		_ = rim.realityEventsReader.Close()
		rim.realityEventsReader = nil
	}
	rim.enabled = false
	log.Printf("Reality Improved Manager disabled")
	return nil
}

// IsEnabled 检查是否启用
func (rim *RealityImprovedManager) IsEnabled() bool {
	rim.mu.RLock()
	defer rim.mu.RUnlock()
	return rim.enabled
}

// loadMaps 加载eBPF映射表
func (rim *RealityImprovedManager) loadMaps() error {
	// 尝试加载改进的REALITY映射表
	connections, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/reality_improved_connections", nil)
	if err != nil {
		return fmt.Errorf("failed to load reality_improved_connections map: %w", err)
	}
	rim.connections = connections

	stats, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/reality_improved_stats", nil)
	if err != nil {
		return fmt.Errorf("failed to load reality_improved_stats map: %w", err)
	}
	rim.stats = stats

	uuidWhitelist, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/uuid_whitelist", nil)
	if err != nil {
		return fmt.Errorf("failed to load uuid_whitelist map: %w", err)
	}
	rim.uuidWhitelist = uuidWhitelist

	securityEvents, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/security_events", nil)
	if err != nil {
		return fmt.Errorf("failed to load security_events map: %w", err)
	}
	rim.securityEvents = securityEvents

	// 尝试加载 ringbuf（如果存在）
	if rbMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/reality_events", nil); err == nil {
		if reader, rErr := ringbuf.NewReader(rbMap); rErr == nil {
			rim.realityEventsReader = reader
		} else {
			log.Printf("Warning: failed to open ringbuf reader: %v", rErr)
		}
	} else {
		log.Printf("Info: reality_events ringbuf not present: %v", err)
	}

	return nil
}

// initializeUUIDWhitelist 初始化UUID白名单
func (rim *RealityImprovedManager) initializeUUIDWhitelist() error {
	if !rim.uuidWhitelistEnabled || rim.uuidWhitelist == nil {
		return nil
	}

	// 从配置文件或环境变量获取UUID列表
	// 这里使用示例UUID，实际应该从配置读取
	exampleUUIDs := []string{
		"12345678-1234-1234-1234-123456789abc",
		"87654321-4321-4321-4321-cba987654321",
	}

	for _, uuid := range exampleUUIDs {
		hash := rim.calculateUUIDHash(uuid)
		valid := uint8(1)
		if err := rim.uuidWhitelist.Update(&hash, &valid, ebpf.UpdateAny); err != nil {
			log.Printf("Warning: Failed to add UUID to whitelist: %v", err)
		}
	}

	log.Printf("UUID whitelist initialized with %d entries", len(exampleUUIDs))
	return nil
}

// calculateUUIDHash 计算UUID哈希
func (rim *RealityImprovedManager) calculateUUIDHash(uuid string) uint32 {
	hash := uint32(0)
	for i := 0; i < len(uuid) && i < 16; i++ {
		hash = hash*31 + uint32(uuid[i])
	}
	return hash
}

// AddUUIDToWhitelist 添加UUID到白名单
func (rim *RealityImprovedManager) AddUUIDToWhitelist(uuid string) error {
	if !rim.IsEnabled() || rim.uuidWhitelist == nil {
		return fmt.Errorf("manager not enabled or whitelist not available")
	}

	hash := rim.calculateUUIDHash(uuid)
	valid := uint8(1)

	if err := rim.uuidWhitelist.Update(&hash, &valid, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("failed to add UUID to whitelist: %w", err)
	}

	log.Printf("Added UUID %s (hash: %d) to whitelist", uuid, hash)
	return nil
}

// RemoveUUIDFromWhitelist 从白名单移除UUID
func (rim *RealityImprovedManager) RemoveUUIDFromWhitelist(uuid string) error {
	if !rim.IsEnabled() || rim.uuidWhitelist == nil {
		return fmt.Errorf("manager not enabled or whitelist not available")
	}

	hash := rim.calculateUUIDHash(uuid)

	if err := rim.uuidWhitelist.Delete(&hash); err != nil {
		return fmt.Errorf("failed to remove UUID from whitelist: %w", err)
	}

	log.Printf("Removed UUID %s (hash: %d) from whitelist", uuid, hash)
	return nil
}

// GetStats 获取统计信息
func (rim *RealityImprovedManager) GetStats() *RealityImprovedStats {
	if !rim.IsEnabled() {
		return &RealityImprovedStats{}
	}

	if rim.stats != nil {
		var key uint32 = 0
		cpuCount := runtime.NumCPU()
		perCPU := make([]RealityImprovedStats, cpuCount)
		if err := rim.stats.Lookup(&key, &perCPU); err == nil {
			var agg RealityImprovedStats
			for i := range perCPU {
				agg.TotalConnections += perCPU[i].TotalConnections
				agg.ValidConnections += perCPU[i].ValidConnections
				agg.InvalidConnections += perCPU[i].InvalidConnections
				agg.SuccessfulHandshakes += perCPU[i].SuccessfulHandshakes
				agg.FailedHandshakes += perCPU[i].FailedHandshakes
				agg.RetryAttempts += perCPU[i].RetryAttempts
				agg.ZeroCopyOperations += perCPU[i].ZeroCopyOperations
				agg.SecurityViolations += perCPU[i].SecurityViolations
			}
			return &agg
		}
	}

	return &RealityImprovedStats{
		TotalConnections:     atomic.LoadUint64(&rim.statsData.TotalConnections),
		ValidConnections:     atomic.LoadUint64(&rim.statsData.ValidConnections),
		InvalidConnections:   atomic.LoadUint64(&rim.statsData.InvalidConnections),
		SuccessfulHandshakes: atomic.LoadUint64(&rim.statsData.SuccessfulHandshakes),
		FailedHandshakes:     atomic.LoadUint64(&rim.statsData.FailedHandshakes),
		RetryAttempts:        atomic.LoadUint64(&rim.statsData.RetryAttempts),
		ZeroCopyOperations:   atomic.LoadUint64(&rim.statsData.ZeroCopyOperations),
		SecurityViolations:   atomic.LoadUint64(&rim.statsData.SecurityViolations),
	}
}

// GetSecurityEvents 获取安全事件
func (rim *RealityImprovedManager) GetSecurityEvents() map[uint32]uint64 {
	if !rim.IsEnabled() || rim.securityEvents == nil {
		return make(map[uint32]uint64)
	}

	events := make(map[uint32]uint64)
	var key uint32
	var value uint64

	iter := rim.securityEvents.Iterate()
	for iter.Next(&key, &value) {
		events[key] = value
	}

	return events
}

// updateStatsLoop 统计更新循环
func (rim *RealityImprovedManager) updateStatsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rim.ctx.Done():
			return
		case <-ticker.C:
			rim.updateStats()
		}
	}
}

// consumeEvents 消费 ringbuf 事件
func (rim *RealityImprovedManager) consumeEvents() {
	if rim.realityEventsReader == nil {
		return
	}
	type RealityEvent struct {
		Ts     uint64
		Type   uint32
		ConnID uint64
	}
	for {
		record, err := rim.realityEventsReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if len(record.RawSample) >= 20 {
			var ev RealityEvent
			b := record.RawSample
			ev.Ts = binary.LittleEndian.Uint64(b[0:8])
			ev.Type = binary.LittleEndian.Uint32(b[8:12])
			ev.ConnID = binary.LittleEndian.Uint64(b[12:20])
			_ = ev
		}
	}
}

// updateStats 更新统计信息
func (rim *RealityImprovedManager) updateStats() {
	if rim.stats == nil {
		return
	}

	var key uint32 = 0
	cpuCount := runtime.NumCPU()
	perCPU := make([]RealityImprovedStats, cpuCount)
	if err := rim.stats.Lookup(&key, &perCPU); err == nil {
		var stats RealityImprovedStats
		for i := range perCPU {
			stats.TotalConnections += perCPU[i].TotalConnections
			stats.ValidConnections += perCPU[i].ValidConnections
			stats.InvalidConnections += perCPU[i].InvalidConnections
			stats.SuccessfulHandshakes += perCPU[i].SuccessfulHandshakes
			stats.FailedHandshakes += perCPU[i].FailedHandshakes
			stats.RetryAttempts += perCPU[i].RetryAttempts
			stats.ZeroCopyOperations += perCPU[i].ZeroCopyOperations
			stats.SecurityViolations += perCPU[i].SecurityViolations
		}
		// 更新内存中的统计信息
		atomic.StoreUint64(&rim.statsData.TotalConnections, stats.TotalConnections)
		atomic.StoreUint64(&rim.statsData.ValidConnections, stats.ValidConnections)
		atomic.StoreUint64(&rim.statsData.InvalidConnections, stats.InvalidConnections)
		atomic.StoreUint64(&rim.statsData.SuccessfulHandshakes, stats.SuccessfulHandshakes)
		atomic.StoreUint64(&rim.statsData.FailedHandshakes, stats.FailedHandshakes)
		atomic.StoreUint64(&rim.statsData.RetryAttempts, stats.RetryAttempts)
		atomic.StoreUint64(&rim.statsData.ZeroCopyOperations, stats.ZeroCopyOperations)
		atomic.StoreUint64(&rim.statsData.SecurityViolations, stats.SecurityViolations)

		// 记录性能指标
		if stats.ValidConnections > 0 {
			validRatio := float64(stats.ValidConnections) / float64(stats.TotalConnections)
			log.Printf("Reality Improved: Valid connection ratio: %.2f%% (%d/%d)",
				validRatio*100, stats.ValidConnections, stats.TotalConnections)
		}

		if stats.ZeroCopyOperations > 0 {
			log.Printf("Reality Improved: Zero-copy operations: %d", stats.ZeroCopyOperations)
		}
	}
}

// RecordConnection 记录连接
func (rim *RealityImprovedManager) RecordConnection(connType string, isValid bool) {
	if !rim.IsEnabled() {
		return
	}

	atomic.AddUint64(&rim.statsData.TotalConnections, 1)

	if isValid {
		atomic.AddUint64(&rim.statsData.ValidConnections, 1)
		log.Printf("Reality Improved: Valid %s connection recorded", connType)
	} else {
		atomic.AddUint64(&rim.statsData.InvalidConnections, 1)
		log.Printf("Reality Improved: Invalid %s connection recorded", connType)
	}
}

// RecordHandshake 记录握手
func (rim *RealityImprovedManager) RecordHandshake(success bool) {
	if !rim.IsEnabled() {
		return
	}

	if success {
		atomic.AddUint64(&rim.statsData.SuccessfulHandshakes, 1)
		log.Printf("Reality Improved: Successful handshake recorded")
	} else {
		atomic.AddUint64(&rim.statsData.FailedHandshakes, 1)
		log.Printf("Reality Improved: Failed handshake recorded")
	}
}

// RecordZeroCopy 记录零拷贝操作
func (rim *RealityImprovedManager) RecordZeroCopy() {
	if !rim.IsEnabled() {
		return
	}

	atomic.AddUint64(&rim.statsData.ZeroCopyOperations, 1)
	log.Printf("Reality Improved: Zero-copy operation recorded")
}

// 全局实例
var realityImprovedManager *RealityImprovedManager
var realityImprovedManagerOnce sync.Once

// GetRealityImprovedManager 获取改进的REALITY管理器实例
func GetRealityImprovedManager() *RealityImprovedManager {
	realityImprovedManagerOnce.Do(func() {
		realityImprovedManager = NewRealityImprovedManager()
	})
	return realityImprovedManager
}

// RecordRealityConnection 记录REALITY连接
func RecordRealityConnection(connType string, isValid bool) {
	GetRealityImprovedManager().RecordConnection(connType, isValid)
}

// RecordRealityHandshake 记录REALITY握手
func RecordRealityHandshake(success bool) {
	GetRealityImprovedManager().RecordHandshake(success)
}

// RecordRealityZeroCopy 记录REALITY零拷贝操作
func RecordRealityZeroCopy() {
	GetRealityImprovedManager().RecordZeroCopy()
}

// GetRealityImprovedStats 获取改进的REALITY统计信息
func GetRealityImprovedStats() *RealityImprovedStats {
	return GetRealityImprovedManager().GetStats()
}
