//go:build linux && amd64

package ebpf

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy"
)

// ConnectionState eBPF连接状态结构
type ConnectionState struct {
	UserUUIDHigh      uint64 `json:"user_uuid_high"`
	UserUUIDLow       uint64 `json:"user_uuid_low"`
	ConnectionID      uint32 `json:"connection_id"`
	Protocol          uint32 `json:"protocol"`
	UplinkBytes       uint64 `json:"uplink_bytes"`
	DownlinkBytes     uint64 `json:"downlink_bytes"`
	UplinkPackets     uint64 `json:"uplink_packets"`
	DownlinkPackets   uint64 `json:"downlink_packets"`
	StartTime         uint64 `json:"start_time"`
	LastActive        uint64 `json:"last_active"`
	LocalIP           uint32 `json:"local_ip"`
	RemoteIP          uint32 `json:"remote_ip"`
	LocalPort         uint16 `json:"local_port"`
	RemotePort        uint16 `json:"remote_port"`
	State             uint8  `json:"state"`
	IsTLS             uint8  `json:"is_tls"`
	EnableXTLS        uint8  `json:"enable_xtls"`
	Direction         uint8  `json:"direction"`
}

// TrafficState eBPF流量状态结构
type TrafficState struct {
	NumberOfPacketToFilter    uint32 `json:"number_of_packet_to_filter"`
	Cipher                    uint16 `json:"cipher"`
	IsTLS12OrAbove           uint8  `json:"is_tls12_or_above"`
	IsTLS                    uint8  `json:"is_tls"`
	RemainingServerHello     int32  `json:"remaining_server_hello"`
	WithinPaddingBuffersIn   uint8  `json:"within_padding_buffers_in"`
	UplinkReaderDirectCopy   uint8  `json:"uplink_reader_direct_copy"`
	RemainingCommandIn       int32  `json:"remaining_command_in"`
	RemainingContentIn       int32  `json:"remaining_content_in"`
	RemainingPaddingIn       int32  `json:"remaining_padding_in"`
	CurrentCommandIn         uint32 `json:"current_command_in"`
	IsPaddingIn              uint8  `json:"is_padding_in"`
	DownlinkWriterDirectCopy uint8  `json:"downlink_writer_direct_copy"`
	WithinPaddingBuffersOut  uint8  `json:"within_padding_buffers_out"`
	DownlinkReaderDirectCopy uint8  `json:"downlink_reader_direct_copy"`
	RemainingCommandOut      int32  `json:"remaining_command_out"`
	RemainingContentOut      int32  `json:"remaining_content_out"`
	RemainingPaddingOut      int32  `json:"remaining_padding_out"`
	CurrentCommandOut        uint32 `json:"current_command_out"`
	IsPaddingOut             uint8  `json:"is_padding_out"`
	UplinkWriterDirectCopy   uint8  `json:"uplink_writer_direct_copy"`
}

// UserStats eBPF用户统计结构
type UserStats struct {
	UserUUIDHigh          uint64 `json:"user_uuid_high"`
	UserUUIDLow           uint64 `json:"user_uuid_low"`
	TotalUplinkBytes      uint64 `json:"total_uplink_bytes"`
	TotalDownlinkBytes    uint64 `json:"total_downlink_bytes"`
	TotalUplinkPackets    uint64 `json:"total_uplink_packets"`
	TotalDownlinkPackets  uint64 `json:"total_downlink_packets"`
	ActiveConnections     uint32 `json:"active_connections"`
	TotalConnections      uint32 `json:"total_connections"`
	FirstSeen             uint64 `json:"first_seen"`
	LastSeen              uint64 `json:"last_seen"`
}

// ConnectionKey 连接键结构
type ConnectionKey struct {
	ConnectionID uint32
}

// UserKey 用户键结构
type UserKey struct {
	UserUUIDHigh uint64
	UserUUIDLow  uint64
}

// EBpfConnectionTracker eBPF连接跟踪器
type EBpfConnectionTracker struct {
	sync.RWMutex
	enabled              bool
	programFd            int
	connectionStatesMap  int
	trafficStatesMap     int
	userStatisticsMap    int
	globalStatsMap       int
	connections          map[uint32]*ConnectionState
	nextConnectionID     uint32
	cleanupInterval      time.Duration
	cleanupTicker        *time.Ticker
	stopCleanup          chan struct{}
}

// NewEBpfConnectionTracker 创建新的eBPF连接跟踪器
func NewEBpfConnectionTracker() (*EBpfConnectionTracker, error) {
	tracker := &EBpfConnectionTracker{
		enabled:         false,
		connections:     make(map[uint32]*ConnectionState),
		nextConnectionID: 1,
		cleanupInterval: 60 * time.Second,
		stopCleanup:     make(chan struct{}),
	}

	// 检查eBPF支持
	if err := tracker.checkEBpfSupport(); err != nil {
		errors.LogInfo(context.Background(), "eBPF not supported: ", err)
		return tracker, nil
	}

	// 尝试加载eBPF程序
	if err := tracker.loadEBpfPrograms(); err != nil {
		errors.LogInfo(context.Background(), "Failed to load eBPF programs: ", err)
		return tracker, nil
	}

	tracker.enabled = true
	
	// 启动清理协程
	tracker.startCleanupRoutine()
	
	errors.LogInfo(context.Background(), "eBPF connection tracker initialized successfully")
	return tracker, nil
}

// checkEBpfSupport 检查eBPF支持
func (t *EBpfConnectionTracker) checkEBpfSupport() error {
	// 检查内核版本和权限
	return checkEBpfKernelSupport()
}

// loadEBpfPrograms 加载eBPF程序
func (t *EBpfConnectionTracker) loadEBpfPrograms() error {
	// 这里实现加载eBPF程序的逻辑
	// 实际实现需要使用cilium/ebpf或其他eBPF加载库
	
	// 占位符实现
	t.programFd = -1
	t.connectionStatesMap = -1
	t.trafficStatesMap = -1
	t.userStatisticsMap = -1
	t.globalStatsMap = -1
	
	return nil
}

// TrackConnection 跟踪新连接
func (t *EBpfConnectionTracker) TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32 {
	if !t.enabled {
		return 0
	}

	t.Lock()
	defer t.Unlock()

	connID := t.nextConnectionID
	t.nextConnectionID++

	// 解析UUID
	var uuidHigh, uuidLow uint64
	if len(userUUID) >= 16 {
		uuidHigh = *(*uint64)(unsafe.Pointer(&userUUID[0]))
		uuidLow = *(*uint64)(unsafe.Pointer(&userUUID[8]))
	}

	// 解析地址
	var localIP, remoteIP uint32
	var localPort, remotePort uint16

	if tcpAddr, ok := localAddr.(*net.TCPAddr); ok {
		if ipv4 := tcpAddr.IP.To4(); ipv4 != nil {
			localIP = *(*uint32)(unsafe.Pointer(&ipv4[0]))
		}
		localPort = uint16(tcpAddr.Port)
	} else if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
		if ipv4 := udpAddr.IP.To4(); ipv4 != nil {
			localIP = *(*uint32)(unsafe.Pointer(&ipv4[0]))
		}
		localPort = uint16(udpAddr.Port)
	}

	if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok {
		if ipv4 := tcpAddr.IP.To4(); ipv4 != nil {
			remoteIP = *(*uint32)(unsafe.Pointer(&ipv4[0]))
		}
		remotePort = uint16(tcpAddr.Port)
	} else if udpAddr, ok := remoteAddr.(*net.UDPAddr); ok {
		if ipv4 := udpAddr.IP.To4(); ipv4 != nil {
			remoteIP = *(*uint32)(unsafe.Pointer(&ipv4[0]))
		}
		remotePort = uint16(udpAddr.Port)
	}

	now := uint64(time.Now().UnixNano())
	connState := &ConnectionState{
		UserUUIDHigh:    uuidHigh,
		UserUUIDLow:     uuidLow,
		ConnectionID:    connID,
		Protocol:        protocol,
		UplinkBytes:     0,
		DownlinkBytes:   0,
		UplinkPackets:   0,
		DownlinkPackets: 0,
		StartTime:       now,
		LastActive:      now,
		LocalIP:         localIP,
		RemoteIP:        remoteIP,
		LocalPort:       localPort,
		RemotePort:      remotePort,
		State:           0, // CONN_STATE_ACTIVE
		IsTLS:           0,
		EnableXTLS:      0,
		Direction:       0,
	}

	t.connections[connID] = connState

	// 更新eBPF map
	if t.enabled {
		t.updateConnectionInMap(connID, connState)
	}

	// 更新用户统计
	t.updateUserConnection(uuidHigh, uuidLow, 1)

	return connID
}

// UpdateTraffic 更新流量统计
func (t *EBpfConnectionTracker) UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error {
	if !t.enabled {
		return errors.New("eBPF connection tracker not enabled")
	}

	t.Lock()
	defer t.Unlock()

	connState, exists := t.connections[connID]
	if !exists {
		return errors.New("connection not found")
	}

	// 更新流量统计
	connState.UplinkBytes += uplinkBytes
	connState.DownlinkBytes += downlinkBytes
	connState.LastActive = uint64(time.Now().UnixNano())

	if uplinkBytes > 0 {
		connState.UplinkPackets++
	}
	if downlinkBytes > 0 {
		connState.DownlinkPackets++
	}

	// 更新eBPF map
	t.updateConnectionInMap(connID, connState)

	// 更新用户统计
	t.updateUserTraffic(connState.UserUUIDHigh, connState.UserUUIDLow, uplinkBytes, downlinkBytes)

	return nil
}

// UpdateTrafficState 更新流量状态
func (t *EBpfConnectionTracker) UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error {
	if !t.enabled {
		return errors.New("eBPF connection tracker not enabled")
	}

	// 转换TrafficState到eBPF格式
	ebpfState := &TrafficState{
		NumberOfPacketToFilter:    uint32(trafficState.NumberOfPacketToFilter),
		Cipher:                    trafficState.Cipher,
		IsTLS12OrAbove:           boolToUint8(trafficState.IsTLS12orAbove),
		IsTLS:                    boolToUint8(trafficState.IsTLS),
		RemainingServerHello:     trafficState.RemainingServerHello,
		WithinPaddingBuffersIn:   boolToUint8(trafficState.Inbound.WithinPaddingBuffers),
		UplinkReaderDirectCopy:   boolToUint8(trafficState.Inbound.UplinkReaderDirectCopy),
		RemainingCommandIn:       trafficState.Inbound.RemainingCommand,
		RemainingContentIn:       trafficState.Inbound.RemainingContent,
		RemainingPaddingIn:       trafficState.Inbound.RemainingPadding,
		CurrentCommandIn:         uint32(trafficState.Inbound.CurrentCommand),
		IsPaddingIn:              boolToUint8(trafficState.Inbound.IsPadding),
		DownlinkWriterDirectCopy: boolToUint8(trafficState.Inbound.DownlinkWriterDirectCopy),
		WithinPaddingBuffersOut:  boolToUint8(trafficState.Outbound.WithinPaddingBuffers),
		DownlinkReaderDirectCopy: boolToUint8(trafficState.Outbound.DownlinkReaderDirectCopy),
		RemainingCommandOut:      trafficState.Outbound.RemainingCommand,
		RemainingContentOut:      trafficState.Outbound.RemainingContent,
		RemainingPaddingOut:      trafficState.Outbound.RemainingPadding,
		CurrentCommandOut:        uint32(trafficState.Outbound.CurrentCommand),
		IsPaddingOut:             boolToUint8(trafficState.Outbound.IsPadding),
		UplinkWriterDirectCopy:   boolToUint8(trafficState.Outbound.UplinkWriterDirectCopy),
	}

	// 更新eBPF map
	return t.updateTrafficStateInMap(connID, ebpfState)
}

// CloseConnection 关闭连接跟踪
func (t *EBpfConnectionTracker) CloseConnection(connID uint32) error {
	if !t.enabled {
		return errors.New("eBPF connection tracker not enabled")
	}

	t.Lock()
	defer t.Unlock()

	connState, exists := t.connections[connID]
	if !exists {
		return errors.New("connection not found")
	}

	// 更新连接状态
	connState.State = 4 // CONN_STATE_TERMINATED

	// 更新eBPF map
	t.updateConnectionInMap(connID, connState)

	// 更新用户统计
	t.updateUserConnection(connState.UserUUIDHigh, connState.UserUUIDLow, -1)

	// 从本地缓存中删除
	delete(t.connections, connID)

	return nil
}

// GetConnectionStats 获取连接统计
func (t *EBpfConnectionTracker) GetConnectionStats(connID uint32) (*ConnectionState, error) {
	if !t.enabled {
		return nil, errors.New("eBPF connection tracker not enabled")
	}

	t.RLock()
	defer t.RUnlock()

	connState, exists := t.connections[connID]
	if !exists {
		return nil, errors.New("connection not found")
	}

	// 创建副本返回
	result := *connState
	return &result, nil
}

// GetUserStats 获取用户统计
func (t *EBpfConnectionTracker) GetUserStats(userUUID []byte) (*UserStats, error) {
	if !t.enabled {
		return nil, errors.New("eBPF connection tracker not enabled")
	}

	if len(userUUID) < 16 {
		return nil, errors.New("invalid user UUID")
	}

	uuidHigh := *(*uint64)(unsafe.Pointer(&userUUID[0]))
	uuidLow := *(*uint64)(unsafe.Pointer(&userUUID[8]))

	return t.getUserStatsFromMap(uuidHigh, uuidLow)
}

// GetGlobalStats 获取全局统计
func (t *EBpfConnectionTracker) GetGlobalStats() (map[string]interface{}, error) {
	if !t.enabled {
		return nil, errors.New("eBPF connection tracker not enabled")
	}

	stats := make(map[string]interface{})
	
	t.RLock()
	activeConnections := len(t.connections)
	t.RUnlock()

	stats["active_connections"] = activeConnections
	stats["enabled"] = t.enabled
	stats["cleanup_interval"] = t.cleanupInterval.String()

	// 从eBPF map获取全局统计
	if globalStats, err := t.getGlobalStatsFromMap(); err == nil {
		for k, v := range globalStats {
			stats[k] = v
		}
	}

	return stats, nil
}

// IsEnabled 检查是否启用
func (t *EBpfConnectionTracker) IsEnabled() bool {
	return t.enabled
}

// Close 关闭连接跟踪器
func (t *EBpfConnectionTracker) Close() error {
	if t.cleanupTicker != nil {
		t.cleanupTicker.Stop()
		close(t.stopCleanup)
	}

	// 关闭eBPF程序和maps
	// 实际实现需要调用相应的清理函数

	return nil
}

// 辅助函数

func boolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func (t *EBpfConnectionTracker) updateConnectionInMap(connID uint32, connState *ConnectionState) error {
	// 实际实现需要调用eBPF map更新操作
	return nil
}

func (t *EBpfConnectionTracker) updateTrafficStateInMap(connID uint32, trafficState *TrafficState) error {
	// 实际实现需要调用eBPF map更新操作
	return nil
}

func (t *EBpfConnectionTracker) updateUserConnection(uuidHigh, uuidLow uint64, delta int32) error {
	// 实际实现需要调用eBPF map更新操作
	return nil
}

func (t *EBpfConnectionTracker) updateUserTraffic(uuidHigh, uuidLow, uplinkBytes, downlinkBytes uint64) error {
	// 实际实现需要调用eBPF map更新操作
	return nil
}

func (t *EBpfConnectionTracker) getUserStatsFromMap(uuidHigh, uuidLow uint64) (*UserStats, error) {
	// 实际实现需要从eBPF map读取数据
	return &UserStats{
		UserUUIDHigh: uuidHigh,
		UserUUIDLow:  uuidLow,
	}, nil
}

func (t *EBpfConnectionTracker) getGlobalStatsFromMap() (map[string]interface{}, error) {
	// 实际实现需要从eBPF map读取数据
	return make(map[string]interface{}), nil
}

func (t *EBpfConnectionTracker) startCleanupRoutine() {
	t.cleanupTicker = time.NewTicker(t.cleanupInterval)
	go func() {
		for {
			select {
			case <-t.cleanupTicker.C:
				t.cleanupExpiredConnections()
			case <-t.stopCleanup:
				return
			}
		}
	}()
}

func (t *EBpfConnectionTracker) cleanupExpiredConnections() {
	t.Lock()
	defer t.Unlock()

	now := uint64(time.Now().UnixNano())
	timeout := uint64(5 * time.Minute.Nanoseconds()) // 5分钟超时

	for connID, connState := range t.connections {
		if now-connState.LastActive > timeout {
			// 连接已过期，清理
			delete(t.connections, connID)
			t.updateUserConnection(connState.UserUUIDHigh, connState.UserUUIDLow, -1)
		}
	}
}

// checkEBpfKernelSupport 检查内核eBPF支持
func checkEBpfKernelSupport() error {
	// 实际实现需要检查内核版本、权限等
	return fmt.Errorf("eBPF kernel support check not implemented")
}