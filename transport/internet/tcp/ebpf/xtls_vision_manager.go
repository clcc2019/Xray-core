//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/xtls/xray-core/common/log"
)

// XTLSVisionManager XTLS Vision eBPF管理器
type XTLSVisionManager struct {
	mu                 sync.RWMutex
	enabled            bool
	inboundProgram     *ebpf.Program
	inboundLink        link.Link
	inboundConnections *ebpf.Map
	inboundStats       *ebpf.Map
	userUUIDWhitelist  *ebpf.Map
	hotConnections     *ebpf.Map
	ctx                context.Context
	cancel             context.CancelFunc
	stats              *XTLSVisionStats
}

// XTLSVisionStats 统计信息
type XTLSVisionStats struct {
	TotalInboundConnections uint64
	VisionConnections       uint64
	HandshakeCount          uint64
	SpliceCount             uint64
	VisionPackets           uint64
	ZeroCopyPackets         uint64
	PaddingOptimized        uint64
	CommandParsed           uint64
	TotalBytesReceived      uint64
	TotalBytesSent          uint64
	AvgHandshakeTime        uint64
}

var (
	globalXTLSVisionManager *XTLSVisionManager
	initXTLSVisionOnce      sync.Once
)

// GetXTLSVisionManager 获取全局XTLS Vision管理器
func GetXTLSVisionManager() *XTLSVisionManager {
	initXTLSVisionOnce.Do(func() {
		globalXTLSVisionManager = &XTLSVisionManager{
			enabled: os.Getenv("XRAY_EBPF") == "1",
			stats:   &XTLSVisionStats{},
		}
		if globalXTLSVisionManager.enabled {
			if err := globalXTLSVisionManager.init(); err != nil {
				log.Record(&log.GeneralMessage{
					Severity: log.Severity_Warning,
					Content:  "Failed to initialize XTLS Vision eBPF manager: " + err.Error(),
				})
				globalXTLSVisionManager.enabled = false
			}
		}
	})
	return globalXTLSVisionManager
}

// init 初始化XTLS Vision eBPF管理器
func (xvm *XTLSVisionManager) init() error {
	xvm.ctx, xvm.cancel = context.WithCancel(context.Background())

	// 加载入站eBPF程序
	if err := xvm.loadInboundProgram(); err != nil {
		return fmt.Errorf("failed to load inbound program: %w", err)
	}

	// 启动统计收集
	go xvm.collectStats()

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "XTLS Vision eBPF manager initialized successfully",
	})

	return nil
}

// loadInboundProgram 加载入站eBPF程序
func (xvm *XTLSVisionManager) loadInboundProgram() error {
	// 加载XDP程序
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		// 这里应该加载编译好的eBPF字节码
		// 实际实现中需要从文件或嵌入的字节码加载
	})
	if err != nil {
		return err
	}
	xvm.inboundProgram = prog

	// 附加到网络接口
	iface, err := net.InterfaceByName("eth0") // 默认接口
	if err != nil {
		return err
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	xvm.inboundLink = link

	// 加载映射表
	xvm.inboundConnections, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  64, // 根据结构体大小调整
		MaxEntries: 100000,
	})
	if err != nil {
		return err
	}

	xvm.inboundStats, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  88, // 根据统计结构体大小调整
		MaxEntries: 1000,
	})
	if err != nil {
		return err
	}

	xvm.userUUIDWhitelist, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 1000,
	})
	if err != nil {
		return err
	}

	xvm.hotConnections, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LRUHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 10000,
	})
	if err != nil {
		return err
	}

	return nil
}

// AddUserUUID 添加用户UUID到白名单
func (xvm *XTLSVisionManager) AddUserUUID(uuid []byte) error {
	if !xvm.enabled || xvm.userUUIDWhitelist == nil {
		return fmt.Errorf("eBPF not enabled or user UUID whitelist not initialized")
	}

	hash := xvm.calculateUUIDHash(uuid)
	valid := uint8(1)

	return xvm.userUUIDWhitelist.Update(&hash, &valid, ebpf.UpdateAny)
}

// RemoveUserUUID 从白名单移除用户UUID
func (xvm *XTLSVisionManager) RemoveUserUUID(uuid []byte) error {
	if !xvm.enabled || xvm.userUUIDWhitelist == nil {
		return fmt.Errorf("eBPF not enabled or user UUID whitelist not initialized")
	}

	hash := xvm.calculateUUIDHash(uuid)
	return xvm.userUUIDWhitelist.Delete(&hash)
}

// calculateUUIDHash 计算UUID哈希
func (xvm *XTLSVisionManager) calculateUUIDHash(uuid []byte) uint64 {
	var hash uint64
	for i := 0; i < 16 && i < len(uuid); i++ {
		hash = hash*31 + uint64(uuid[i])
	}
	return hash
}

// GetStats 获取统计信息
func (xvm *XTLSVisionManager) GetStats() *XTLSVisionStats {
	xvm.mu.RLock()
	defer xvm.mu.RUnlock()

	// 从eBPF映射表读取最新统计
	if xvm.inboundStats != nil {
		key := uint32(0)
		var stats struct {
			TotalInboundConnections uint64
			RealityConnections      uint64
			VisionConnections       uint64
			HandshakeCount          uint64
			SpliceCount             uint64
			VisionPackets           uint64
			ZeroCopyPackets         uint64
			PaddingOptimized        uint64
			CommandParsed           uint64
			TotalBytesReceived      uint64
			TotalBytesSent          uint64
		}

		if err := xvm.inboundStats.Lookup(&key, &stats); err == nil {
			xvm.stats.TotalInboundConnections = stats.TotalInboundConnections
			xvm.stats.VisionConnections = stats.VisionConnections
			xvm.stats.HandshakeCount = stats.HandshakeCount
			xvm.stats.SpliceCount = stats.SpliceCount
			xvm.stats.VisionPackets = stats.VisionPackets
			xvm.stats.ZeroCopyPackets = stats.ZeroCopyPackets
			xvm.stats.PaddingOptimized = stats.PaddingOptimized
			xvm.stats.CommandParsed = stats.CommandParsed
			xvm.stats.TotalBytesReceived = stats.TotalBytesReceived
		}
	}

	return xvm.stats
}

// collectStats 定期收集统计信息
func (xvm *XTLSVisionManager) collectStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-xvm.ctx.Done():
			return
		case <-ticker.C:
			xvm.GetStats()
		}
	}
}

// Close 关闭XTLS Vision管理器
func (xvm *XTLSVisionManager) Close() error {
	xvm.mu.Lock()
	defer xvm.mu.Unlock()

	if xvm.cancel != nil {
		xvm.cancel()
	}

	if xvm.inboundLink != nil {
		xvm.inboundLink.Close()
	}

	if xvm.inboundProgram != nil {
		xvm.inboundProgram.Close()
	}

	if xvm.inboundConnections != nil {
		xvm.inboundConnections.Close()
	}

	if xvm.inboundStats != nil {
		xvm.inboundStats.Close()
	}

	if xvm.userUUIDWhitelist != nil {
		xvm.userUUIDWhitelist.Close()
	}

	if xvm.hotConnections != nil {
		xvm.hotConnections.Close()
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "XTLS Vision eBPF manager closed",
	})

	return nil
}

// IsEnabled 检查是否启用
func (xvm *XTLSVisionManager) IsEnabled() bool {
	return xvm.enabled
}
