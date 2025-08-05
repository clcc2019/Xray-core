//go:build linux

package ebpf

import (
	"context"
	"fmt"
	"net"
	"time"
)

// ExampleUsage XTLS Vision eBPF功能使用示例
func ExampleUsage() {
	// 1. 获取Vision集成实例
	integration := GetVisionIntegration()
	if !integration.IsEnabled() {
		fmt.Println("XTLS Vision eBPF integration is not enabled")
		return
	}

	// 2. 创建测试连接
	conn := &VisionConnection{
		ID:           "example-connection-1",
		UserUUID:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ClientIP:     "192.168.1.100",
		ServerIP:     "10.0.0.1",
		ClientPort:   12345,
		ServerPort:   443,
		State:        0,
		LastActivity: time.Now(),
	}

	// 3. 注册连接
	err := integration.RegisterConnection(conn)
	if err != nil {
		fmt.Printf("Failed to register connection: %v\n", err)
		return
	}
	fmt.Println("Connection registered successfully")

	// 4. 启用Vision优化
	err = integration.EnableVision(conn.ID)
	if err != nil {
		fmt.Printf("Failed to enable Vision: %v\n", err)
		return
	}
	fmt.Println("Vision optimization enabled")

	// 5. 模拟数据传输
	for i := 0; i < 5; i++ {
		// 更新连接统计
		integration.UpdateConnectionStats(conn.ID, 1024, 2048)
		time.Sleep(100 * time.Millisecond)
	}

	// 6. 获取统计信息
	stats := integration.GetStats()
	fmt.Printf("Vision Connections: %d\n", stats.VisionConnections)
	fmt.Printf("Handshake Count: %d\n", stats.HandshakeCount)
	fmt.Printf("Splice Count: %d\n", stats.SpliceCount)
	fmt.Printf("Zero Copy Packets: %d\n", stats.ZeroCopyPackets)

	// 7. 注销连接
	err = integration.UnregisterConnection(conn.ID)
	if err != nil {
		fmt.Printf("Failed to unregister connection: %v\n", err)
		return
	}
	fmt.Println("Connection unregistered successfully")
}

// ExampleInboundAcceleration 入站加速示例
func ExampleInboundAcceleration() {
	// 模拟VLESS入站连接
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	serverAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	ctx := context.Background()

	// 启用XTLS Vision入站eBPF加速
	err := EnableXTLSVisionInboundEBPFAcceleration(ctx, clientAddr, serverAddr)
	if err != nil {
		fmt.Printf("Failed to enable inbound acceleration: %v\n", err)
		return
	}

	fmt.Println("Inbound acceleration enabled successfully")
}

// ExampleManagerUsage 管理器使用示例
func ExampleManagerUsage() {
	// 获取Vision管理器
	manager := GetXTLSVisionManager()
	if !manager.IsEnabled() {
		fmt.Println("XTLS Vision manager is not enabled")
		return
	}

	// 添加用户UUID到白名单
	testUUID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	err := manager.AddUserUUID(testUUID)
	if err != nil {
		fmt.Printf("Failed to add user UUID: %v\n", err)
		return
	}
	fmt.Println("User UUID added to whitelist")

	// 获取统计信息
	stats := manager.GetStats()
	fmt.Printf("Total Inbound Connections: %d\n", stats.TotalInboundConnections)
	fmt.Printf("Vision Connections: %d\n", stats.VisionConnections)
	fmt.Printf("Total Bytes Received: %d\n", stats.TotalBytesReceived)

	// 移除用户UUID
	err = manager.RemoveUserUUID(testUUID)
	if err != nil {
		fmt.Printf("Failed to remove user UUID: %v\n", err)
		return
	}
	fmt.Println("User UUID removed from whitelist")
}

// ExampleConnectionTracking 连接跟踪示例
func ExampleConnectionTracking() {
	integration := GetVisionIntegration()
	if !integration.IsEnabled() {
		fmt.Println("Vision integration is not enabled")
		return
	}

	// 创建多个连接进行跟踪
	connections := []*VisionConnection{
		{
			ID:           "conn-1",
			UserUUID:     []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			ClientIP:     "192.168.1.100",
			ServerIP:     "10.0.0.1",
			ClientPort:   12345,
			ServerPort:   443,
			State:        0,
			LastActivity: time.Now(),
		},
		{
			ID:           "conn-2",
			UserUUID:     []byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
			ClientIP:     "192.168.1.101",
			ServerIP:     "10.0.0.1",
			ClientPort:   12346,
			ServerPort:   443,
			State:        0,
			LastActivity: time.Now(),
		},
	}

	// 注册所有连接
	for _, conn := range connections {
		err := integration.RegisterConnection(conn)
		if err != nil {
			fmt.Printf("Failed to register connection %s: %v\n", conn.ID, err)
			continue
		}
		fmt.Printf("Connection %s registered\n", conn.ID)
	}

	// 模拟连接活动
	for i := 0; i < 3; i++ {
		for _, conn := range connections {
			integration.UpdateConnectionStats(conn.ID, 512, 1024)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 查询连接状态
	for _, conn := range connections {
		foundConn, exists := integration.GetConnection(conn.ID)
		if exists && foundConn != nil {
			fmt.Printf("Connection %s: BytesSent=%d, BytesReceived=%d\n",
				conn.ID, foundConn.BytesSent, foundConn.BytesReceived)
		}
	}

	// 清理所有连接
	for _, conn := range connections {
		err := integration.UnregisterConnection(conn.ID)
		if err != nil {
			fmt.Printf("Failed to unregister connection %s: %v\n", conn.ID, err)
		} else {
			fmt.Printf("Connection %s unregistered\n", conn.ID)
		}
	}
}

// ExamplePerformanceMonitoring 性能监控示例
func ExamplePerformanceMonitoring() {
	manager := GetXTLSVisionManager()
	if !manager.IsEnabled() {
		fmt.Println("Vision manager is not enabled")
		return
	}

	// 定期监控性能指标
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	fmt.Println("Starting performance monitoring...")
	fmt.Println("Press Ctrl+C to stop")

	for i := 0; i < 5; i++ {
		select {
		case <-ticker.C:
			stats := manager.GetStats()
			fmt.Printf("=== Performance Report %d ===\n", i+1)
			fmt.Printf("Vision Connections: %d\n", stats.VisionConnections)
			fmt.Printf("Handshake Count: %d\n", stats.HandshakeCount)
			fmt.Printf("Splice Count: %d\n", stats.SpliceCount)
			fmt.Printf("Zero Copy Packets: %d\n", stats.ZeroCopyPackets)
			fmt.Printf("Padding Optimized: %d\n", stats.PaddingOptimized)
			fmt.Printf("Command Parsed: %d\n", stats.CommandParsed)
			fmt.Printf("Total Bytes Received: %d\n", stats.TotalBytesReceived)
			fmt.Printf("Total Bytes Sent: %d\n", stats.TotalBytesSent)
			fmt.Printf("Average Handshake Time: %d ms\n", stats.AvgHandshakeTime)
			fmt.Println()
		}
	}

	fmt.Println("Performance monitoring completed")
}
