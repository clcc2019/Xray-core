package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/transport/internet/tcp/ebpf"
)

func main() {
	fmt.Println("=== XTLS Vision eBPF 加速功能演示 ===")

	// 1. 检查eBPF功能是否可用
	fmt.Println("\n1. 检查eBPF功能状态:")
	manager := ebpf.GetXTLSVisionManager()
	if manager.IsEnabled() {
		fmt.Println("   ✓ eBPF加速功能已启用")
	} else {
		fmt.Println("   ✗ eBPF加速功能未启用（可能是非Linux平台或未设置XRAY_EBPF=1）")
	}

	// 2. 演示Vision集成功能
	fmt.Println("\n2. 演示Vision集成功能:")
	integration := ebpf.GetVisionIntegration()
	if integration.IsEnabled() {
		fmt.Println("   ✓ Vision集成功能已启用")
		demoVisionIntegration(integration)
	} else {
		fmt.Println("   ✗ Vision集成功能未启用")
	}

	// 3. 演示入站加速功能
	fmt.Println("\n3. 演示入站加速功能:")
	demoInboundAcceleration()

	// 4. 演示管理器功能
	fmt.Println("\n4. 演示管理器功能:")
	demoManagerFunctions(manager)

	// 5. 演示性能监控
	fmt.Println("\n5. 演示性能监控:")
	demoPerformanceMonitoring(manager)

	fmt.Println("\n=== 演示完成 ===")
}

func demoVisionIntegration(integration *ebpf.XTLSVisionIntegration) {
	// 创建测试连接
	conn := &ebpf.VisionConnection{
		ID:           "demo-connection-1",
		UserUUID:     []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		ClientIP:     "192.168.1.100",
		ServerIP:     "10.0.0.1",
		ClientPort:   12345,
		ServerPort:   443,
		State:        0,
		LastActivity: time.Now(),
	}

	// 注册连接
	err := integration.RegisterConnection(conn)
	if err != nil {
		fmt.Printf("   ✗ 连接注册失败: %v\n", err)
		return
	}
	fmt.Println("   ✓ 连接注册成功")

	// 启用Vision优化
	err = integration.EnableVision(conn.ID)
	if err != nil {
		fmt.Printf("   ✗ Vision优化启用失败: %v\n", err)
	} else {
		fmt.Println("   ✓ Vision优化启用成功")
	}

	// 模拟数据传输
	for i := 0; i < 3; i++ {
		integration.UpdateConnectionStats(conn.ID, 1024, 2048)
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("   ✓ 数据传输统计更新完成")

	// 获取连接信息
	foundConn, exists := integration.GetConnection(conn.ID)
	if exists && foundConn != nil {
		fmt.Printf("   ✓ 连接信息: BytesSent=%d, BytesReceived=%d\n",
			foundConn.BytesSent, foundConn.BytesReceived)
	}

	// 注销连接
	err = integration.UnregisterConnection(conn.ID)
	if err != nil {
		fmt.Printf("   ✗ 连接注销失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 连接注销成功")
	}
}

func demoInboundAcceleration() {
	// 创建测试地址
	clientAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	serverAddr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}

	ctx := context.Background()

	// 启用入站加速
	err := ebpf.EnableXTLSVisionInboundEBPFAcceleration(ctx, clientAddr, serverAddr)
	if err != nil {
		fmt.Printf("   ✗ 入站加速启用失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 入站加速启用成功")
	}
}

func demoManagerFunctions(manager *ebpf.XTLSVisionManager) {
	// 添加用户UUID
	testUUID := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	err := manager.AddUserUUID(testUUID)
	if err != nil {
		fmt.Printf("   ✗ 用户UUID添加失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 用户UUID添加成功")
	}

	// 获取统计信息
	stats := manager.GetStats()
	fmt.Printf("   ✓ 统计信息: Vision连接=%d, 握手次数=%d, 零拷贝包=%d\n",
		stats.VisionConnections, stats.HandshakeCount, stats.ZeroCopyPackets)

	// 移除用户UUID
	err = manager.RemoveUserUUID(testUUID)
	if err != nil {
		fmt.Printf("   ✗ 用户UUID移除失败: %v\n", err)
	} else {
		fmt.Println("   ✓ 用户UUID移除成功")
	}
}

func demoPerformanceMonitoring(manager *ebpf.XTLSVisionManager) {
	fmt.Println("   📊 开始性能监控（5秒）...")

	// 模拟性能监控
	for i := 0; i < 5; i++ {
		stats := manager.GetStats()
		fmt.Printf("   [%d] Vision连接: %d, 总字节数: %d, 平均握手时间: %dms\n",
			i+1, stats.VisionConnections, stats.TotalBytesReceived+stats.TotalBytesSent, stats.AvgHandshakeTime)
		time.Sleep(1 * time.Second)
	}

	fmt.Println("   ✓ 性能监控完成")
}
