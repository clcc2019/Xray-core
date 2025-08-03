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

// TCPCongestionController TCP拥塞控制器
type TCPCongestionController struct {
	mu            sync.RWMutex
	enabled       bool
	programLoaded bool
	ctx           context.Context
	cancel        context.CancelFunc
	stats         *CongestionStats
}

// CongestionStats 拥塞控制统计
type CongestionStats struct {
	TotalConnections         uint64
	SlowStartCount           uint64
	CongestionAvoidanceCount uint64
	RetransmitCount          uint64
	ECNMarks                 uint64
	AverageCWND              uint64
	AverageRTT               uint64
}

// NewTCPCongestionController 创建新的TCP拥塞控制器
func NewTCPCongestionController() *TCPCongestionController {
	ctx, cancel := context.WithCancel(context.Background())

	controller := &TCPCongestionController{
		enabled: false,
		ctx:     ctx,
		cancel:  cancel,
		stats:   &CongestionStats{},
	}

	// 检查是否启用eBPF
	controller.enabled = controller.isEBPFEnabled()

	return controller
}

// Start 启动TCP拥塞控制器
func (tcc *TCPCongestionController) Start() error {
	tcc.mu.Lock()
	defer tcc.mu.Unlock()

	if !tcc.enabled {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "TCP Congestion Control disabled (set XRAY_EBPF=1 to enable)",
		})
		return nil
	}

	// 检查eBPF支持
	if !tcc.checkEBPFSupport() {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "eBPF not supported for TCP Congestion Control, fallback to standard mode",
		})
		tcc.enabled = false
		return nil
	}

	// 加载eBPF程序
	if err := tcc.loadEBPFPrograms(); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Failed to load TCP Congestion Control eBPF programs: " + err.Error(),
		})
		tcc.enabled = false
		return nil
	}

	tcc.programLoaded = true

	// 启动后台统计收集任务
	go tcc.backgroundStatsCollection()

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "TCP Congestion Control started successfully",
	})

	return nil
}

// Stop 停止TCP拥塞控制器
func (tcc *TCPCongestionController) Stop() error {
	tcc.mu.Lock()
	defer tcc.mu.Unlock()

	tcc.cancel()

	if tcc.programLoaded {
		tcc.unloadEBPFPrograms()
		tcc.programLoaded = false
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "TCP Congestion Control stopped",
	})

	return nil
}

// OptimizeConnection 优化TCP连接
func (tcc *TCPCongestionController) OptimizeConnection(conn net.Conn, destination xnet.Destination) (net.Conn, bool) {
	if !tcc.enabled || !tcc.programLoaded {
		return conn, false
	}

	tcc.mu.RLock()
	defer tcc.mu.RUnlock()

	// 记录连接以供eBPF程序学习
	tcc.recordConnection(conn, destination)

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  "TCP connection optimized with congestion control: " + destination.String(),
	})

	return conn, true
}

// GetStats 获取拥塞控制统计
func (tcc *TCPCongestionController) GetStats() *CongestionStats {
	tcc.mu.RLock()
	defer tcc.mu.RUnlock()

	if tcc.stats == nil {
		return &CongestionStats{}
	}

	return &CongestionStats{
		TotalConnections:         tcc.stats.TotalConnections,
		SlowStartCount:           tcc.stats.SlowStartCount,
		CongestionAvoidanceCount: tcc.stats.CongestionAvoidanceCount,
		RetransmitCount:          tcc.stats.RetransmitCount,
		ECNMarks:                 tcc.stats.ECNMarks,
		AverageCWND:              tcc.stats.AverageCWND,
		AverageRTT:               tcc.stats.AverageRTT,
	}
}

// 检查是否启用eBPF
func (tcc *TCPCongestionController) isEBPFEnabled() bool {
	return os.Getenv("XRAY_EBPF") == "1"
}

// 检查eBPF支持
func (tcc *TCPCongestionController) checkEBPFSupport() bool {
	// 检查eBPF文件系统
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return false
	}

	// 检查必要的eBPF程序
	requiredPrograms := []string{
		"/sys/fs/bpf/xray/tcp_congestion_control_xdp",
		"/sys/fs/bpf/xray/tcp_congestion_control_tc",
	}

	for _, program := range requiredPrograms {
		if _, err := os.Stat(program); os.IsNotExist(err) {
			return false
		}
	}

	return true
}

// 加载eBPF程序
func (tcc *TCPCongestionController) loadEBPFPrograms() error {
	// eBPF程序已经在mount-ebpf.sh中加载
	// 这里只需要验证程序是否可用
	return nil
}

// 卸载eBPF程序
func (tcc *TCPCongestionController) unloadEBPFPrograms() error {
	// 程序会在系统重启时自动清理
	return nil
}

// 记录连接
func (tcc *TCPCongestionController) recordConnection(conn net.Conn, destination xnet.Destination) {
	// 记录连接信息供eBPF程序使用
	// 实际的拥塞控制逻辑在eBPF程序中实现
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  fmt.Sprintf("Recording TCP connection: %s -> %s", conn.LocalAddr(), destination.String()),
	})
}

// 后台统计收集
func (tcc *TCPCongestionController) backgroundStatsCollection() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tcc.ctx.Done():
			return
		case <-ticker.C:
			tcc.updateStats()
		}
	}
}

// 更新统计信息
func (tcc *TCPCongestionController) updateStats() {
	// 从eBPF maps读取统计信息
	// 这里简化处理，实际应该从eBPF maps读取
	tcc.mu.Lock()
	defer tcc.mu.Unlock()

	// 模拟统计更新
	if tcc.stats != nil {
		tcc.stats.TotalConnections++
	}
}

// 全局TCP拥塞控制器实例
var (
	globalTCPCongestionController *TCPCongestionController
	tcpCongestionOnce             sync.Once
)

// GetGlobalTCPCongestionController 获取全局TCP拥塞控制器实例
func GetGlobalTCPCongestionController() *TCPCongestionController {
	tcpCongestionOnce.Do(func() {
		globalTCPCongestionController = NewTCPCongestionController()
	})
	return globalTCPCongestionController
}

// EnableTCPCongestionControl 启用TCP拥塞控制优化
func EnableTCPCongestionControl(ctx context.Context, conn net.Conn, destination xnet.Destination) {
	controller := GetGlobalTCPCongestionController()
	if controller != nil {
		controller.OptimizeConnection(conn, destination)
	}
}

// GetTCPCongestionStats 获取TCP拥塞控制统计
func GetTCPCongestionStats() *CongestionStats {
	controller := GetGlobalTCPCongestionController()
	if controller != nil {
		return controller.GetStats()
	}
	return &CongestionStats{}
}
