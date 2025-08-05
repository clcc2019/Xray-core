//go:build linux
// +build linux

package ebpf

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
)

// XTLSVisionIntegration XTLS Vision集成接口
type XTLSVisionIntegration struct {
	mu          sync.RWMutex
	enabled     bool
	manager     *XTLSVisionManager
	connections map[string]*VisionConnection
	ctx         context.Context
	cancel      context.CancelFunc
}

// VisionConnection Vision连接信息
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
	LastActivity  time.Time
	BytesSent     uint64
	BytesReceived uint64
	SpliceCount   uint32
	VisionPackets uint32
}

var (
	globalVisionIntegration   *XTLSVisionIntegration
	initVisionIntegrationOnce sync.Once
)

// GetVisionIntegration 获取全局Vision集成实例
func GetVisionIntegration() *XTLSVisionIntegration {
	initVisionIntegrationOnce.Do(func() {
		globalVisionIntegration = &XTLSVisionIntegration{
			connections: make(map[string]*VisionConnection),
		}
		if err := globalVisionIntegration.init(); err != nil {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Warning,
				Content:  "Failed to initialize Vision integration: " + err.Error(),
			})
		}
	})
	return globalVisionIntegration
}

// init 初始化Vision集成
func (xvi *XTLSVisionIntegration) init() error {
	xvi.ctx, xvi.cancel = context.WithCancel(context.Background())

	// 获取Vision管理器
	xvi.manager = GetXTLSVisionManager()
	xvi.enabled = xvi.manager.IsEnabled()

	if xvi.enabled {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "XTLS Vision integration initialized",
		})
	}

	return nil
}

// RegisterConnection 注册Vision连接
func (xvi *XTLSVisionIntegration) RegisterConnection(conn *VisionConnection) error {
	if !xvi.enabled {
		return fmt.Errorf("Vision integration not enabled")
	}

	xvi.mu.Lock()
	defer xvi.mu.Unlock()

	// 添加到用户空间连接表
	xvi.connections[conn.ID] = conn

	// 添加用户UUID到eBPF白名单
	if err := xvi.manager.AddUserUUID(conn.UserUUID); err != nil {
		return fmt.Errorf("failed to add user UUID to whitelist: %w", err)
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  fmt.Sprintf("Vision connection registered: %s", conn.ID),
	})

	return nil
}

// UnregisterConnection 注销Vision连接
func (xvi *XTLSVisionIntegration) UnregisterConnection(connID string) error {
	if !xvi.enabled {
		return nil
	}

	xvi.mu.Lock()
	defer xvi.mu.Unlock()

	conn, exists := xvi.connections[connID]
	if !exists {
		return fmt.Errorf("connection not found: %s", connID)
	}

	// 从用户空间连接表移除
	delete(xvi.connections, connID)

	// 从eBPF白名单移除用户UUID
	if err := xvi.manager.RemoveUserUUID(conn.UserUUID); err != nil {
		return fmt.Errorf("failed to remove user UUID from whitelist: %w", err)
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Debug,
		Content:  fmt.Sprintf("Vision connection unregistered: %s", connID),
	})

	return nil
}

// GetConnection 获取连接信息
func (xvi *XTLSVisionIntegration) GetConnection(connID string) (*VisionConnection, bool) {
	xvi.mu.RLock()
	defer xvi.mu.RUnlock()

	conn, exists := xvi.connections[connID]
	return conn, exists
}

// UpdateConnectionStats 更新连接统计
func (xvi *XTLSVisionIntegration) UpdateConnectionStats(connID string, bytesSent, bytesReceived uint64) {
	if !xvi.enabled {
		return
	}

	xvi.mu.Lock()
	defer xvi.mu.Unlock()

	if conn, exists := xvi.connections[connID]; exists {
		conn.BytesSent += bytesSent
		conn.BytesReceived += bytesReceived
		conn.LastActivity = time.Now()
	}
}

// GetStats 获取统计信息
func (xvi *XTLSVisionIntegration) GetStats() *XTLSVisionStats {
	if !xvi.enabled {
		return &XTLSVisionStats{}
	}

	return xvi.manager.GetStats()
}

// EnableVision 启用Vision优化
func (xvi *XTLSVisionIntegration) EnableVision(connID string) error {
	if !xvi.enabled {
		return fmt.Errorf("Vision integration not enabled")
	}

	xvi.mu.Lock()
	defer xvi.mu.Unlock()

	if conn, exists := xvi.connections[connID]; exists {
		conn.VisionEnabled = true
		conn.HandshakeTime = time.Now()

		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("Vision enabled for connection: %s", connID),
		})

		return nil
	}

	return fmt.Errorf("connection not found: %s", connID)
}

// DisableVision 禁用Vision优化
func (xvi *XTLSVisionIntegration) DisableVision(connID string) error {
	if !xvi.enabled {
		return nil
	}

	xvi.mu.Lock()
	defer xvi.mu.Unlock()

	if conn, exists := xvi.connections[connID]; exists {
		conn.VisionEnabled = false

		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  fmt.Sprintf("Vision disabled for connection: %s", connID),
		})

		return nil
	}

	return fmt.Errorf("connection not found: %s", connID)
}

// IsEnabled 检查是否启用
func (xvi *XTLSVisionIntegration) IsEnabled() bool {
	return xvi.enabled
}

// Close 关闭Vision集成
func (xvi *XTLSVisionIntegration) Close() error {
	xvi.mu.Lock()
	defer xvi.mu.Unlock()

	if xvi.cancel != nil {
		xvi.cancel()
	}

	// 清理所有连接
	for connID := range xvi.connections {
		if err := xvi.UnregisterConnection(connID); err != nil {
			errors.LogWarning(context.Background(), "Failed to unregister connection during cleanup: ", err)
		}
	}

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "XTLS Vision integration closed",
	})

	return nil
}

// GenerateConnectionID 生成连接ID
func GenerateConnectionID(clientIP, serverIP string, clientPort, serverPort uint16) string {
	return fmt.Sprintf("%s:%d-%s:%d", clientIP, clientPort, serverIP, serverPort)
}

// EnableXTLSVisionInboundEBPFAcceleration 启用XTLS Vision入站eBPF加速
func EnableXTLSVisionInboundEBPFAcceleration(ctx context.Context, clientAddr net.Addr, serverAddr net.Addr) error {
	integration := GetVisionIntegration()
	if !integration.IsEnabled() {
		return nil
	}

	// 解析地址
	clientTCPAddr, ok := clientAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("client address is not TCP address")
	}

	serverTCPAddr, ok := serverAddr.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("server address is not TCP address")
	}

	// 生成连接ID
	connID := GenerateConnectionID(
		clientTCPAddr.IP.String(),
		serverTCPAddr.IP.String(),
		uint16(clientTCPAddr.Port),
		uint16(serverTCPAddr.Port),
	)

	// 创建Vision连接
	conn := &VisionConnection{
		ID:           connID,
		ClientIP:     clientTCPAddr.IP.String(),
		ServerIP:     serverTCPAddr.IP.String(),
		ClientPort:   uint16(clientTCPAddr.Port),
		ServerPort:   uint16(serverTCPAddr.Port),
		State:        0, // init
		LastActivity: time.Now(),
	}

	// 注册连接
	if err := integration.RegisterConnection(conn); err != nil {
		return fmt.Errorf("failed to register Vision connection: %w", err)
	}

	errors.LogInfo(ctx, "XTLS Vision inbound eBPF acceleration enabled for connection: ", connID)
	return nil
}
