//go:build !linux || !amd64

package ebpf

import (
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy"
)

// EBpfConnectionTracker fallback实现，用于非Linux平台
type EBpfConnectionTracker struct {
	sync.RWMutex
	enabled          bool
	connections      map[uint32]*ConnectionState
	nextConnectionID uint32
}

// NewEBpfConnectionTracker 创建新的eBPF连接跟踪器（fallback实现）
func NewEBpfConnectionTracker() (*EBpfConnectionTracker, error) {
	// 在非Linux平台上，eBPF不可用，直接返回禁用状态
	return &EBpfConnectionTracker{
		enabled:          false,
		connections:      make(map[uint32]*ConnectionState),
		nextConnectionID: 1,
	}, errors.New("eBPF not supported on this platform")
}

// TrackConnection 跟踪新连接（fallback实现）
func (t *EBpfConnectionTracker) TrackConnection(userUUID []byte, protocol uint32, localAddr, remoteAddr net.Addr) uint32 {
	return 0 // 返回无效的连接ID
}

// UpdateTraffic 更新流量统计（fallback实现）
func (t *EBpfConnectionTracker) UpdateTraffic(connID uint32, uplinkBytes, downlinkBytes uint64) error {
	return errors.New("eBPF connection tracker not available on this platform")
}

// UpdateTrafficState 更新流量状态（fallback实现）
func (t *EBpfConnectionTracker) UpdateTrafficState(connID uint32, trafficState *proxy.TrafficState) error {
	return errors.New("eBPF connection tracker not available on this platform")
}

// CloseConnection 关闭连接跟踪（fallback实现）
func (t *EBpfConnectionTracker) CloseConnection(connID uint32) error {
	return errors.New("eBPF connection tracker not available on this platform")
}

// GetConnectionStats 获取连接统计（fallback实现）
func (t *EBpfConnectionTracker) GetConnectionStats(connID uint32) (*ConnectionState, error) {
	return nil, errors.New("eBPF connection tracker not available on this platform")
}

// GetUserStats 获取用户统计（fallback实现）
func (t *EBpfConnectionTracker) GetUserStats(userUUID []byte) (*UserStats, error) {
	return nil, errors.New("eBPF connection tracker not available on this platform")
}

// GetGlobalStats 获取全局统计（fallback实现）
func (t *EBpfConnectionTracker) GetGlobalStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})
	stats["active_connections"] = 0
	stats["enabled"] = false
	stats["platform"] = "unsupported"
	stats["total_connections"] = 0
	stats["total_uplink_bytes"] = uint64(0)
	stats["total_downlink_bytes"] = uint64(0)
	stats["total_uplink_packets"] = uint64(0)
	stats["total_downlink_packets"] = uint64(0)

	return stats, nil
}

// IsEnabled 检查是否启用（fallback实现）
func (t *EBpfConnectionTracker) IsEnabled() bool {
	return false
}

// Close 关闭连接跟踪器（fallback实现）
func (t *EBpfConnectionTracker) Close() error {
	return nil
}

// ConnectionState fallback连接状态结构
type ConnectionState struct {
	UserUUIDHigh    uint64 `json:"user_uuid_high"`
	UserUUIDLow     uint64 `json:"user_uuid_low"`
	ConnectionID    uint32 `json:"connection_id"`
	Protocol        uint32 `json:"protocol"`
	UplinkBytes     uint64 `json:"uplink_bytes"`
	DownlinkBytes   uint64 `json:"downlink_bytes"`
	UplinkPackets   uint64 `json:"uplink_packets"`
	DownlinkPackets uint64 `json:"downlink_packets"`
	StartTime       uint64 `json:"start_time"`
	LastActive      uint64 `json:"last_active"`
	LocalIP         uint32 `json:"local_ip"`
	RemoteIP        uint32 `json:"remote_ip"`
	LocalPort       uint16 `json:"local_port"`
	RemotePort      uint16 `json:"remote_port"`
	State           uint8  `json:"state"`
	IsTLS           uint8  `json:"is_tls"`
	EnableXTLS      uint8  `json:"enable_xtls"`
	Direction       uint8  `json:"direction"`
}

// TrafficState fallback流量状态结构
type TrafficState struct {
	NumberOfPacketToFilter   uint32 `json:"number_of_packet_to_filter"`
	Cipher                   uint16 `json:"cipher"`
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

// UserStats fallback用户统计结构
type UserStats struct {
	UserUUIDHigh         uint64 `json:"user_uuid_high"`
	UserUUIDLow          uint64 `json:"user_uuid_low"`
	TotalUplinkBytes     uint64 `json:"total_uplink_bytes"`
	TotalDownlinkBytes   uint64 `json:"total_downlink_bytes"`
	TotalUplinkPackets   uint64 `json:"total_uplink_packets"`
	TotalDownlinkPackets uint64 `json:"total_downlink_packets"`
	ActiveConnections    uint32 `json:"active_connections"`
	TotalConnections     uint32 `json:"total_connections"`
	FirstSeen            uint64 `json:"first_seen"`
	LastSeen             uint64 `json:"last_seen"`
}
