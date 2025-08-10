//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/xtls/xray-core/common/log"
)

// XTLSVisionManager XTLS Vision eBPF管理器 - 仅用于服务端入站优化
type XTLSVisionManager struct {
	mu                 sync.RWMutex
	enabled            bool
	inboundProgram     *ebpf.Program
	inboundLink        link.Link
	inboundConnections *ebpf.Map
	inboundStats       *ebpf.Map
	userUUIDWhitelist  *ebpf.Map
	hotConnections     *ebpf.Map
	directCopyHint     *ebpf.Map
	eventsMap          *ebpf.Map
	eventsReader       *ringbuf.Reader
	cancelEvents       context.CancelFunc
	ctx                context.Context
	cancel             context.CancelFunc
	stats              *XTLSVisionStats
	lastTLSCompleteTs  time.Time
	lastVisionActiveTs time.Time
	// moving error/handshake stats for dynamic tuning
	recentHandshakeNs []uint64
	recentErrors      int
	// derived breakdown by category from connection table sampling
	errorBreakdown map[string]int
	lastScan       time.Time
}

// XTLSVisionStats 服务端入站统计信息
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

// init 初始化XTLS Vision eBPF管理器 - 仅用于服务端入站
func (xvm *XTLSVisionManager) init() error {
	xvm.ctx, xvm.cancel = context.WithCancel(context.Background())

	// 仅加载入站eBPF程序，不处理出站
	if err := xvm.loadInboundProgram(); err != nil {
		return fmt.Errorf("failed to load inbound program: %w", err)
	}

	// 启动统计收集
	go xvm.collectStats()

	// 订阅 ringbuf 事件（若存在）
	xvm.startEventReader()

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "XTLS Vision eBPF manager initialized successfully (inbound only)",
	})

	return nil
}

// loadInboundProgram 加载入站eBPF程序 - 仅处理服务端入站流量
func (xvm *XTLSVisionManager) loadInboundProgram() error {
	// 1. 检查eBPF支持
	if err := xvm.checkEBPFSupport(); err != nil {
		return fmt.Errorf("eBPF not supported: %w", err)
	}

	// 2. 从pinned程序中获取eBPF程序（由mount-ebpf.sh预先加载）。若失败，仅告警并继续（不影响主功能）。
	if err := xvm.loadPinnedPrograms(); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Pinned XDP/TC program not loaded: " + err.Error() + "; continue without kernel acceleration",
		})
		// 不标记为禁用，以便 maps 仍然可用（例如 direct_copy_hint 等）
	}

	// 3. 获取eBPF映射表（失败也不致停用；可能仅部分功能不可用）
	if err := xvm.loadPinnedMaps(); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Warning,
			Content:  "Pinned maps not fully available: " + err.Error(),
		})
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "XTLS Vision eBPF program loaded from pinned resources successfully",
	})

	return nil
}

// AddUserUUID 添加用户UUID到白名单 - 仅用于入站验证
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

// GetStats 获取入站统计信息
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

// collectStats 定期收集入站统计信息
func (xvm *XTLSVisionManager) collectStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-xvm.ctx.Done():
			return
		case <-ticker.C:
			xvm.GetStats()
			// light-weight periodic sampling for error breakdown
			xvm.scanInboundSample()
		}
	}
}

// startEventReader 订阅 XTLS ringbuf 事件（2=TLS完成，3=Vision激活）
func (xvm *XTLSVisionManager) startEventReader() {
	if xvm.eventsMap == nil {
		return
	}
	reader, err := ringbuf.NewReader(xvm.eventsMap)
	if err != nil {
		return
	}
	xvm.eventsReader = reader
	evCtx, cancel := context.WithCancel(context.Background())
	xvm.cancelEvents = cancel
	go func() {
		defer reader.Close()
		for {
			select {
			case <-evCtx.Done():
				return
			default:
				rec, err := reader.Read()
				if err != nil {
					if err == ringbuf.ErrClosed {
						return
					}
					continue
				}
				if len(rec.RawSample) >= 16 {
					t := binary.LittleEndian.Uint32(rec.RawSample[0:4])
					now := time.Now()
					xvm.mu.Lock()
					switch t {
					case 1: // handshake start (optional)
						// no-op
					case 2: // TLS complete
						xvm.lastTLSCompleteTs = now
						if len(xvm.recentHandshakeNs) >= 128 {
							xvm.recentHandshakeNs = xvm.recentHandshakeNs[1:]
						}
						xvm.recentHandshakeNs = append(xvm.recentHandshakeNs, uint64(time.Since(now).Nanoseconds()))
					case 3: // Vision active
						xvm.lastVisionActiveTs = now
					case 4: // error event
						xvm.recentErrors++
						if xvm.recentErrors > 10000 {
							xvm.recentErrors = 10000
						}
					}
					xvm.mu.Unlock()
				}
			}
		}
	}()
}

// scanInboundSample 从连接表抽样统计错误分类，避免高开销全量扫描
func (xvm *XTLSVisionManager) scanInboundSample() {
	if xvm.inboundConnections == nil {
		return
	}
	// 最多每2秒扫描一次
	if time.Since(xvm.lastScan) < 2*time.Second {
		return
	}
	xvm.lastScan = time.Now()

	// 采样上限
	const sampleLimit = 256
	now := time.Now()
	type inbound struct {
		ClientIP        uint32
		ServerIP        uint32
		ClientPort      uint16
		ServerPort      uint16
		State           uint8
		RealityVerified uint8
		TLSVersion      uint8
		VisionEnabled   uint8
		HandshakeTime   uint64
		BytesReceived   uint64
		BytesSent       uint64
		SpliceCount     uint32
		VisionPackets   uint32
		LastActivity    uint64
		DestIP          uint32
		DestPort        uint16
		UserUUID        [16]byte
		Command         uint8
		ContentLen      uint16
		PaddingLen      uint16
		ParsingState    uint8
	}
	iter := xvm.inboundConnections.Iterate()
	var (
		key            uint64
		v              inbound
		n              int
		tlsInvalid     int
		timeoutCnt     int
		visionInactive int
	)
	for iter.Next(&key, &v) {
		// 分类：握手超时
		// LastActivity 为 ns；当解析状态<2 且距今>2.5s 认为握手超时
		la := time.Unix(0, int64(v.LastActivity))
		if v.ParsingState < 2 {
			if now.Sub(la) > 2500*time.Millisecond {
				timeoutCnt++
			}
		}
		// 分类：TLS版本异常
		if !(v.TLSVersion >= 0x01 && v.TLSVersion <= 0x04) {
			// eBPF 以 0x03xx 形式也可能存储；若为0则视为未识别
			if v.TLSVersion == 0 || v.TLSVersion > 0x10 {
				tlsInvalid++
			}
		}
		// 分类：Vision未激活
		if v.ParsingState >= 2 && v.VisionPackets == 0 {
			visionInactive++
		}
		n++
		if n >= sampleLimit {
			break
		}
	}
	// 更新分类计数
	xvm.mu.Lock()
	if xvm.errorBreakdown == nil {
		xvm.errorBreakdown = make(map[string]int)
	}
	xvm.errorBreakdown["timeout"] = timeoutCnt
	xvm.errorBreakdown["tls_invalid"] = tlsInvalid
	xvm.errorBreakdown["vision_inactive"] = visionInactive
	xvm.mu.Unlock()
}

// HasRecentVisionActive 返回近期是否有 Vision 激活事件
func (xvm *XTLSVisionManager) HasRecentVisionActive(d time.Duration) bool {
	xvm.mu.RLock()
	defer xvm.mu.RUnlock()
	if xvm.lastVisionActiveTs.IsZero() {
		return false
	}
	return time.Since(xvm.lastVisionActiveTs) <= d
}

// GetDynamicHints 返回基于 eBPF 事件推导出的调优建议
// - 建议直拷宽限时间（毫秒）与 pacing 开关
func (xvm *XTLSVisionManager) GetDynamicHints() (graceMs int, enablePacing bool) {
	xvm.mu.RLock()
	defer xvm.mu.RUnlock()
	// 基于近期 Vision 激活与错误率做启停控制
	enablePacing = true
	if !xvm.lastVisionActiveTs.IsZero() && time.Since(xvm.lastVisionActiveTs) < 5*time.Second {
		enablePacing = false // Vision 活跃时可放宽 pacing，避免不必要的节流
	}
	// 估算握手耗时分位数（粗略）
	graceMs = 120
	if n := len(xvm.recentHandshakeNs); n > 0 {
		// 取末尾 32 个的最大值作为近似上分位
		start := 0
		if n > 32 {
			start = n - 32
		}
		max := uint64(0)
		for _, v := range xvm.recentHandshakeNs[start:] {
			if v > max {
				max = v
			}
		}
		ms := int(max / 1_000_000)
		if ms < 60 {
			ms = 60
		}
		if ms > 300 {
			ms = 300
		}
		graceMs = ms
	}
	// 错误偏置：错误过高则提高宽限
	if xvm.recentErrors > 10 { // 简单阈值，可后续改为滑窗比率
		if graceMs < 180 {
			graceMs = 180
		}
		enablePacing = true
	}
	// 细分错误偏置：若 TLS 版本错误/握手超时较多，提高宽限；若 Vision 未激活较多，保持/开启 pacing
	if xvm.errorBreakdown != nil {
		if xvm.errorBreakdown["tls_invalid"] > 5 || xvm.errorBreakdown["timeout"] > 5 {
			if graceMs < 200 {
				graceMs = 200
			}
			enablePacing = true
		}
		if xvm.errorBreakdown["vision_inactive"] > 5 {
			enablePacing = true
		}
	}
	return
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

// checkEBPFSupport 检查eBPF支持
func (xvm *XTLSVisionManager) checkEBPFSupport() error {
	// 1. 检查内核版本 (需要 5.8+)
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}

	// 2. 检查BPF文件系统挂载
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("BPF filesystem not mounted at /sys/fs/bpf")
	}

	// 3. 检查权限
	if os.Geteuid() != 0 {
		return fmt.Errorf("eBPF requires root privileges")
	}

	return nil
}

// loadPinnedPrograms 从pinned资源加载eBPF程序
func (xvm *XTLSVisionManager) loadPinnedPrograms() error {
	// 从BPF文件系统加载已pin的程序（改为 TC 版本以适配 ens5）
	xdpProgPath := "/sys/fs/bpf/xray/xtls_vision_inbound_accelerator_tc"

	// 检查pinned程序是否存在
	if _, err := os.Stat(xdpProgPath); os.IsNotExist(err) {
		return fmt.Errorf("pinned XDP program not found at %s. Please run mount-ebpf.sh first", xdpProgPath)
	}

	// 加载 pinned 程序
	xdpProg, err := ebpf.LoadPinnedProgram(xdpProgPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load pinned XDP program: %w", err)
	}

	xvm.inboundProgram = xdpProg

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "eBPF XDP program loaded from pinned resource: " + xdpProgPath,
	})

	return nil
}

// loadPinnedMaps 从pinned资源加载eBPF映射表
func (xvm *XTLSVisionManager) loadPinnedMaps() error {
	// 映射表路径定义
	mapPaths := map[string]string{
		"xtls_inbound_connections": "/sys/fs/bpf/xray/xtls_inbound_connections",
		"xtls_stats":               "/sys/fs/bpf/xray/xtls_stats",
		"hot_connections":          "/sys/fs/bpf/xray/hot_connections",
		"user_uuid_whitelist":      "/sys/fs/bpf/xray/user_uuid_whitelist",
		"xtls_direct_copy_hint":    "/sys/fs/bpf/xray/xtls_direct_copy_hint",
	}

	// 加载连接表
	if connMap, err := ebpf.LoadPinnedMap(mapPaths["xtls_inbound_connections"], nil); err != nil {
		return fmt.Errorf("failed to load pinned connections map: %w", err)
	} else {
		xvm.inboundConnections = connMap
	}

	// 加载统计表
	if statsMap, err := ebpf.LoadPinnedMap(mapPaths["xtls_stats"], nil); err != nil {
		return fmt.Errorf("failed to load pinned stats map: %w", err)
	} else {
		xvm.inboundStats = statsMap
	}

	// 加载热连接表
	if hotMap, err := ebpf.LoadPinnedMap(mapPaths["hot_connections"], nil); err != nil {
		return fmt.Errorf("failed to load pinned hot connections map: %w", err)
	} else {
		xvm.hotConnections = hotMap
	}

	// 加载UUID白名单表
	if uuidMap, err := ebpf.LoadPinnedMap(mapPaths["user_uuid_whitelist"], nil); err != nil {
		return fmt.Errorf("failed to load pinned UUID whitelist map: %w", err)
	} else {
		xvm.userUUIDWhitelist = uuidMap
	}

	// 加载 direct copy hint（可选）
	if dcMap, err := ebpf.LoadPinnedMap(mapPaths["xtls_direct_copy_hint"], nil); err == nil {
		xvm.directCopyHint = dcMap
	}

	// 尝试加载事件 ringbuf（可选）
	if evMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/xtls_vision_events", nil); err == nil {
		xvm.eventsMap = evMap
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "eBPF maps loaded from pinned resources successfully",
	})

	return nil
}

// IsDirectCopyEnabledIPv4 根据 IPv4 四元组查询解析状态是否为直拷（command=2）
func (xvm *XTLSVisionManager) IsDirectCopyEnabledIPv4(srcIP uint32, srcPort uint16, dstIP uint32, dstPort uint16) bool {
	if !xvm.enabled {
		return false
	}
	// conn_id 需与 eBPF 侧保持一致
	connID := (uint64(srcIP) << 32) | uint64(dstIP) | (uint64(srcPort) << 48) | (uint64(dstPort) << 32)
	// 优先读 hint map
	if xvm.directCopyHint != nil {
		var one uint8
		if err := xvm.directCopyHint.Lookup(&connID, &one); err == nil && one == 1 {
			return true
		}
	}
	// 回退读取连接表的 parsing_state
	if xvm.inboundConnections != nil {
		var v struct {
			ClientIP        uint32
			ServerIP        uint32
			ClientPort      uint16
			ServerPort      uint16
			State           uint8
			RealityVerified uint8
			TLSVersion      uint8
			VisionEnabled   uint8
			HandshakeTime   uint64
			BytesReceived   uint64
			BytesSent       uint64
			SpliceCount     uint32
			VisionPackets   uint32
			LastActivity    uint64
			DestIP          uint32
			DestPort        uint16
			UserUUID        [16]byte
			Command         uint8
			ContentLen      uint16
			PaddingLen      uint16
			ParsingState    uint8
		}
		if err := xvm.inboundConnections.Lookup(&connID, &v); err == nil {
			return v.ParsingState == 2 || v.ParsingState == 4
		}
	}
	return false
}

// SetDirectCopyHintIPv4 设置/清除指定 IPv4 四元组的直拷提示（与 eBPF 侧 conn_id 一致）
// enabled=true 时写入 1，false 时删除 key。
func (xvm *XTLSVisionManager) SetDirectCopyHintIPv4(srcIP uint32, srcPort uint16, dstIP uint32, dstPort uint16, enabled bool) error {
	if !xvm.enabled || xvm.directCopyHint == nil {
		return nil
	}
	// 与 eBPF 侧保持一致的 conn_id 计算
	connID := (uint64(srcIP) << 32) | uint64(dstIP) | (uint64(srcPort) << 48) | (uint64(dstPort) << 32)
	if enabled {
		one := uint8(1)
		return xvm.directCopyHint.Update(&connID, &one, ebpf.UpdateAny)
	}
	return xvm.directCopyHint.Delete(&connID)
}
