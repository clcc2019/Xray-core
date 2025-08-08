//go:build !linux
// +build !linux

package ebpf

import (
	"context"
	"net"
	"time"
)

// XTLSVisionManager XTLS Vision eBPF管理器（非Linux平台fallback）
type XTLSVisionManager struct {
	enabled bool
}

// XTLSVisionStats 统计信息（非Linux平台fallback）
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

// VisionConnection Vision连接（非Linux平台fallback）
type VisionConnection struct {
	ID            string
	UserUUID      []byte
	ClientIP      string
	ServerIP      string
	ClientPort    uint16
	ServerPort    uint16
	State         uint8
	VisionEnabled bool
	HandshakeTime time.Time
	BytesSent     uint64
	BytesReceived uint64
	LastActivity  time.Time
}

// XTLSVisionIntegration XTLS Vision集成接口（非Linux平台fallback）
type XTLSVisionIntegration struct {
	enabled     bool
	manager     *XTLSVisionManager
	connections map[string]*VisionConnection
}

// GetXTLSVisionManager 获取全局XTLS Vision管理器（非Linux平台fallback）
func GetXTLSVisionManager() *XTLSVisionManager {
	return &XTLSVisionManager{
		enabled: false, // 非Linux平台默认禁用
	}
}

// GetVisionIntegration 获取Vision集成实例（非Linux平台fallback）
func GetVisionIntegration() *XTLSVisionIntegration {
	return &XTLSVisionIntegration{
		enabled:     false, // 非Linux平台默认禁用
		manager:     GetXTLSVisionManager(),
		connections: make(map[string]*VisionConnection),
	}
}

// IsEnabled 检查是否启用（非Linux平台fallback）
func (xvm *XTLSVisionManager) IsEnabled() bool {
	return false // 非Linux平台始终返回false
}

// SetDirectCopyHintIPv4 设置/清除直拷提示（非Linux平台fallback：no-op）
func (xvm *XTLSVisionManager) SetDirectCopyHintIPv4(srcIP uint32, srcPort uint16, dstIP uint32, dstPort uint16, enabled bool) error {
	return nil
}

// IsDirectCopyEnabledIPv4 查询直拷提示（非Linux平台fallback：恒为false）
func (xvm *XTLSVisionManager) IsDirectCopyEnabledIPv4(srcIP uint32, srcPort uint16, dstIP uint32, dstPort uint16) bool {
	return false
}

// AddUserUUID 添加用户UUID（非Linux平台fallback）
func (xvm *XTLSVisionManager) AddUserUUID(uuid []byte) error {
	return nil // 非Linux平台不做任何操作
}

// RemoveUserUUID 移除用户UUID（非Linux平台fallback）
func (xvm *XTLSVisionManager) RemoveUserUUID(uuid []byte) error {
	return nil // 非Linux平台不做任何操作
}

// GetStats 获取统计信息（非Linux平台fallback）
func (xvm *XTLSVisionManager) GetStats() *XTLSVisionStats {
	return &XTLSVisionStats{} // 返回空统计信息
}

// Close 关闭管理器（非Linux平台fallback）
func (xvm *XTLSVisionManager) Close() error {
	return nil // 非Linux平台不做任何操作
}

// IsEnabled 检查集成是否启用（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) IsEnabled() bool {
	return false // 非Linux平台始终返回false
}

// RegisterConnection 注册连接（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) RegisterConnection(conn *VisionConnection) error {
	return nil // 非Linux平台不做任何操作
}

// UnregisterConnection 注销连接（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) UnregisterConnection(connID string) error {
	return nil // 非Linux平台不做任何操作
}

// GetConnection 获取连接（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) GetConnection(connID string) (*VisionConnection, bool) {
	return nil, false // 非Linux平台返回空
}

// UpdateConnectionStats 更新连接统计（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) UpdateConnectionStats(connID string, bytesSent, bytesReceived uint64) {
	// 非Linux平台不做任何操作
}

// GetStats 获取统计信息（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) GetStats() *XTLSVisionStats {
	return &XTLSVisionStats{} // 返回空统计信息
}

// EnableVision 启用Vision优化（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) EnableVision(connID string) error {
	return nil // 非Linux平台不做任何操作
}

// DisableVision 禁用Vision优化（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) DisableVision(connID string) error {
	return nil // 非Linux平台不做任何操作
}

// Close 关闭集成（非Linux平台fallback）
func (xvi *XTLSVisionIntegration) Close() error {
	return nil // 非Linux平台不做任何操作
}

// GenerateConnectionID 生成连接ID（非Linux平台fallback）
func GenerateConnectionID(clientIP, serverIP string, clientPort, serverPort uint16) string {
	return "" // 非Linux平台返回空字符串
}

// EnableXTLSVisionInboundEBPFAcceleration 启用XTLS Vision入站eBPF加速的便捷函数（非Linux平台）
func EnableXTLSVisionInboundEBPFAcceleration(ctx context.Context, clientAddr net.Addr, serverAddr net.Addr) error {
	// 非Linux平台，返回nil表示不启用
	return nil
}
