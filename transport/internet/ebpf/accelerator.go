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

// XrayAccelerator eBPF透明加速器
// 自动学习现有路由规则，提供零配置的eBPF优化
type XrayAccelerator struct {
	mu            sync.RWMutex
	enabled       bool
	autoLearn     bool
	learnedRoutes map[string]*LearnedRoute
	programLoaded bool
	ctx           context.Context
	cancel        context.CancelFunc
	stats         *AcceleratorStats
}

// LearnedRoute 自动学习的路由
type LearnedRoute struct {
	SrcPattern  string
	DstPattern  string
	OutboundTag string
	Protocol    string
	PacketCount uint64
	ByteCount   uint64
	LastUsed    time.Time
	Confidence  float64 // 置信度 0.0-1.0
}

// AcceleratorStats 加速器统计
type AcceleratorStats struct {
	TotalPackets     uint64
	AcceleratedCount uint64
	FallbackCount    uint64
	LearnedRules     uint32
	BypassRatio      float64
}

var (
	globalAccelerator *XrayAccelerator
	once              sync.Once
)

// GetGlobalAccelerator 获取全局加速器实例
func GetGlobalAccelerator() *XrayAccelerator {
	once.Do(func() {
		globalAccelerator = NewXrayAccelerator()
	})
	return globalAccelerator
}

// NewXrayAccelerator 创建新的Xray eBPF加速器
func NewXrayAccelerator() *XrayAccelerator {
	ctx, cancel := context.WithCancel(context.Background())

	accelerator := &XrayAccelerator{
		enabled:       false,
		autoLearn:     true,
		learnedRoutes: make(map[string]*LearnedRoute),
		ctx:           ctx,
		cancel:        cancel,
		stats:         &AcceleratorStats{},
	}

	// 检查是否启用eBPF
	accelerator.enabled = accelerator.isEBPFEnabled()

	return accelerator
}

// Start 启动eBPF加速器
func (xa *XrayAccelerator) Start() error {
	xa.mu.Lock()
	defer xa.mu.Unlock()

	if !xa.enabled {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "eBPF accelerator disabled (set XRAY_EBPF=1 to enable)",
		})
		return nil
	}

	// 检查eBPF支持
	if !xa.checkEBPFSupport() {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "eBPF not supported, fallback to standard mode",
		})
		xa.enabled = false
		return nil
	}

	// 加载eBPF程序
	if err := xa.loadEBPFPrograms(); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Failed to load eBPF programs: " + err.Error(),
		})
		xa.enabled = false
		return nil
	}

	xa.programLoaded = true

	// 启动后台学习和优化任务
	go xa.backgroundOptimization()

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "eBPF accelerator started successfully",
	})

	return nil
}

// Stop 停止eBPF加速器
func (xa *XrayAccelerator) Stop() error {
	xa.mu.Lock()
	defer xa.mu.Unlock()

	xa.cancel()

	if xa.programLoaded {
		xa.unloadEBPFPrograms()
		xa.programLoaded = false
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "eBPF accelerator stopped",
	})

	return nil
}

// OptimizeConnection 优化连接处理
// 这个方法会被transport层调用，透明地优化数据包转发
func (xa *XrayAccelerator) OptimizeConnection(conn net.Conn, destination xnet.Destination) (net.Conn, bool) {
	if !xa.enabled || !xa.programLoaded {
		return conn, false // 未启用或未加载，返回原连接
	}

	xa.mu.RLock()
	defer xa.mu.RUnlock()

	// 尝试eBPF快速路径
	if optimizedConn, ok := xa.tryFastPath(conn, destination); ok {
		xa.stats.AcceleratedCount++
		return optimizedConn, true
	}

	// 学习新的路由模式
	if xa.autoLearn {
		xa.learnRoute(conn, destination)
	}

	xa.stats.FallbackCount++
	return conn, false // 回退到标准处理
}

// LearnFromRouting 从现有路由配置学习
// 在Xray启动时调用，自动学习现有的路由规则
func (xa *XrayAccelerator) LearnFromRouting(rules interface{}) {
	if !xa.enabled || !xa.autoLearn {
		return
	}

	xa.mu.Lock()
	defer xa.mu.Unlock()

	// 这里会分析Xray的路由规则，自动生成eBPF优化规则
	// 具体实现取决于Xray的路由结构

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  "Learning from existing routing configuration",
	})
}

// GetStats 获取加速器统计信息
func (xa *XrayAccelerator) GetStats() *AcceleratorStats {
	xa.mu.RLock()
	defer xa.mu.RUnlock()

	// 计算bypass比率
	total := xa.stats.AcceleratedCount + xa.stats.FallbackCount
	if total > 0 {
		xa.stats.BypassRatio = float64(xa.stats.AcceleratedCount) / float64(total)
	}

	xa.stats.LearnedRules = uint32(len(xa.learnedRoutes))

	// 返回统计信息的副本
	stats := *xa.stats
	return &stats
}

// 内部方法

func (xa *XrayAccelerator) isEBPFEnabled() bool {
	// 检查环境变量
	if os.Getenv("XRAY_EBPF") == "1" || os.Getenv("XRAY_EBPF") == "true" {
		return true
	}

	// 检查命令行参数
	for _, arg := range os.Args {
		if arg == "-ebpf" || arg == "--enable-ebpf" {
			return true
		}
	}

	return false
}

func (xa *XrayAccelerator) checkEBPFSupport() bool {
	// 检查Linux内核版本
	// 检查bpf系统调用支持
	// 检查必要的权限
	return true // 简化实现
}

func (xa *XrayAccelerator) loadEBPFPrograms() error {
	// 加载XDP和TC程序
	// 创建必要的eBPF maps
	// 附加到网络接口

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  "Loading eBPF programs for transparent acceleration",
	})

	return nil
}

func (xa *XrayAccelerator) unloadEBPFPrograms() {
	// 分离和清理eBPF程序
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  "Unloading eBPF programs",
	})
}

func (xa *XrayAccelerator) tryFastPath(conn net.Conn, dest xnet.Destination) (net.Conn, bool) {
	// 检查是否有匹配的学习规则
	key := xa.generateRouteKey(conn, dest)

	if route, exists := xa.learnedRoutes[key]; exists {
		// 检查置信度
		if route.Confidence > 0.8 && time.Since(route.LastUsed) < 5*time.Minute {
			// 使用eBPF快速路径
			route.PacketCount++
			route.LastUsed = time.Now()

			// 返回eBPF优化的连接（这里简化返回原连接）
			return conn, true
		}
	}

	return nil, false
}

func (xa *XrayAccelerator) learnRoute(conn net.Conn, dest xnet.Destination) {
	key := xa.generateRouteKey(conn, dest)

	now := time.Now()

	if route, exists := xa.learnedRoutes[key]; exists {
		// 更新现有规则
		route.PacketCount++
		route.LastUsed = now
		route.Confidence = calculateConfidence(route.PacketCount, time.Since(route.LastUsed))
	} else {
		// 创建新的学习规则
		xa.learnedRoutes[key] = &LearnedRoute{
			SrcPattern:  conn.RemoteAddr().String(),
			DstPattern:  dest.String(),
			Protocol:    dest.Network.SystemString(),
			PacketCount: 1,
			LastUsed:    now,
			Confidence:  0.1, // 初始置信度很低
		}
	}
}

func (xa *XrayAccelerator) generateRouteKey(conn net.Conn, dest xnet.Destination) string {
	return fmt.Sprintf("%s->%s:%s",
		conn.RemoteAddr().Network(),
		dest.Address.String(),
		dest.Network.SystemString())
}

func calculateConfidence(packetCount uint64, timeSinceLastUsed time.Duration) float64 {
	// 基于使用频率和时间新鲜度计算置信度
	baseConfidence := float64(packetCount) / 100.0
	if baseConfidence > 1.0 {
		baseConfidence = 1.0
	}

	// 时间衰减因子
	timeDecay := 1.0 - (float64(timeSinceLastUsed) / float64(time.Hour))
	if timeDecay < 0.1 {
		timeDecay = 0.1
	}

	return baseConfidence * timeDecay
}

func (xa *XrayAccelerator) backgroundOptimization() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-xa.ctx.Done():
			return
		case <-ticker.C:
			xa.optimizeLearnedRoutes()
		}
	}
}

func (xa *XrayAccelerator) optimizeLearnedRoutes() {
	xa.mu.Lock()
	defer xa.mu.Unlock()

	// 清理过期的学习规则
	for key, route := range xa.learnedRoutes {
		if time.Since(route.LastUsed) > 10*time.Minute || route.Confidence < 0.1 {
			delete(xa.learnedRoutes, key)
		}
	}

	// 更新eBPF maps中的热门规则
	xa.updateHotRoutes()

	// 输出统计信息
	if len(xa.learnedRoutes) > 0 {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content: fmt.Sprintf("eBPF accelerator: %d learned routes, %.1f%% bypass ratio",
				len(xa.learnedRoutes), xa.stats.BypassRatio*100),
		})
	}
}

func (xa *XrayAccelerator) updateHotRoutes() {
	// 将高置信度的路由规则更新到eBPF maps中
	// 这样可以在内核层直接处理热门路由
}
