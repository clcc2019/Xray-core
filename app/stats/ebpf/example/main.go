package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/app/stats/ebpf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy"
)

func main() {
	fmt.Println("eBPF连接状态跟踪示例")
	fmt.Println("=====================")

	// 创建统计管理器
	statsManager, err := stats.NewManager(context.Background(), &stats.Config{})
	if err != nil {
		fmt.Printf("创建统计管理器失败: %v\n", err)
		return
	}

	// 创建eBPF状态管理器
	config := ebpf.DefaultStateManagerConfig()
	stateManager, err := ebpf.NewEBpfStateManager(context.Background(), config, statsManager)
	if err != nil {
		fmt.Printf("创建eBPF状态管理器失败: %v\n", err)
		return
	}

	// 启动状态管理器
	if err := stateManager.Start(); err != nil {
		fmt.Printf("启动状态管理器失败: %v\n", err)
		return
	}
	defer stateManager.Close()

	fmt.Printf("eBPF状态管理器已启动，启用状态: %v\n", stateManager.IsEnabled())

	// 模拟用户UUID
	userUUID := []byte{
		0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	}

	// 示例1: 跟踪TCP连接
	fmt.Println("\n示例1: 跟踪TCP连接")
	tcpLocalAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	tcpRemoteAddr, _ := net.ResolveTCPAddr("tcp", "93.184.216.34:443") // example.com

	connID1 := stateManager.TrackConnection(userUUID, 6, tcpLocalAddr, tcpRemoteAddr) // TCP = 6
	fmt.Printf("TCP连接ID: %d\n", connID1)

	// 示例2: 跟踪UDP连接
	fmt.Println("\n示例2: 跟踪UDP连接")
	udpLocalAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:5353")
	udpRemoteAddr, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53") // Google DNS

	connID2 := stateManager.TrackConnection(userUUID, 17, udpLocalAddr, udpRemoteAddr) // UDP = 17
	fmt.Printf("UDP连接ID: %d\n", connID2)

	// 示例3: 更新流量统计
	fmt.Println("\n示例3: 更新流量统计")

	// 模拟流量数据
	trafficUpdates := []struct {
		connID        uint32
		uplinkBytes   uint64
		downlinkBytes uint64
		description   string
	}{
		{connID1, 1024, 2048, "TCP初始数据"},
		{connID2, 512, 256, "UDP DNS查询"},
		{connID1, 2048, 4096, "TCP持续传输"},
		{connID2, 128, 64, "UDP响应"},
	}

	for _, update := range trafficUpdates {
		err := stateManager.UpdateTraffic(update.connID, update.uplinkBytes, update.downlinkBytes)
		if err != nil {
			fmt.Printf("更新流量失败 (连接%d): %v\n", update.connID, err)
		} else {
			fmt.Printf("已更新流量 (连接%d): 上行%d字节, 下行%d字节 - %s\n",
				update.connID, update.uplinkBytes, update.downlinkBytes, update.description)
		}
		time.Sleep(100 * time.Millisecond) // 模拟时间间隔
	}

	// 示例4: 更新流量状态
	fmt.Println("\n示例4: 更新流量状态")

	trafficState := proxy.NewTrafficState(userUUID)
	trafficState.EnableXtls = true
	trafficState.IsTLS = true
	trafficState.IsTLS12orAbove = true
	trafficState.Cipher = 0x1301 // TLS 1.3 AES_128_GCM_SHA256

	err = stateManager.UpdateTrafficState(connID1, trafficState)
	if err != nil {
		fmt.Printf("更新流量状态失败: %v\n", err)
	} else {
		fmt.Printf("已更新连接%d的流量状态 (XTLS: %v, TLS: %v)\n",
			connID1, trafficState.EnableXtls, trafficState.IsTLS)
	}

	// 示例5: 查询连接统计
	fmt.Println("\n示例5: 查询连接统计")

	for _, connID := range []uint32{connID1, connID2} {
		stats, err := stateManager.GetConnectionStats(connID)
		if err != nil {
			fmt.Printf("获取连接%d统计失败: %v\n", connID, err)
		} else if stats != nil {
			protocol := "TCP"
			if stats.Protocol == 17 {
				protocol = "UDP"
			}
			fmt.Printf("连接%d统计 (%s):\n", connID, protocol)
			fmt.Printf("  上行: %d字节, %d包\n", stats.UplinkBytes, stats.UplinkPackets)
			fmt.Printf("  下行: %d字节, %d包\n", stats.DownlinkBytes, stats.DownlinkPackets)
			fmt.Printf("  状态: %d, TLS: %v, XTLS: %v\n",
				stats.State, stats.IsTLS == 1, stats.EnableXTLS == 1)
		}
	}

	// 示例6: 查询用户统计
	fmt.Println("\n示例6: 查询用户统计")

	userStats, err := stateManager.GetUserStats(userUUID)
	if err != nil {
		fmt.Printf("获取用户统计失败: %v\n", err)
	} else if userStats != nil {
		fmt.Printf("用户统计:\n")
		fmt.Printf("  总上行: %d字节, %d包\n", userStats.TotalUplinkBytes, userStats.TotalUplinkPackets)
		fmt.Printf("  总下行: %d字节, %d包\n", userStats.TotalDownlinkBytes, userStats.TotalDownlinkPackets)
		fmt.Printf("  活跃连接: %d, 总连接: %d\n", userStats.ActiveConnections, userStats.TotalConnections)
	}

	// 示例7: 查询全局统计
	fmt.Println("\n示例7: 查询全局统计")

	globalStats, err := stateManager.GetGlobalStats()
	if err != nil {
		fmt.Printf("获取全局统计失败: %v\n", err)
	} else {
		fmt.Println("全局统计:")
		for key, value := range globalStats {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	// 示例8: 查询管理器统计
	fmt.Println("\n示例8: 查询管理器统计")

	managerStats := stateManager.GetManagerStats()
	fmt.Println("管理器统计:")
	for key, value := range managerStats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// 等待一段时间以观察清理过程
	fmt.Println("\n等待5秒钟...")
	time.Sleep(5 * time.Second)

	// 示例9: 关闭连接
	fmt.Println("\n示例9: 关闭连接")

	err = stateManager.CloseConnection(connID1)
	if err != nil {
		fmt.Printf("关闭连接%d失败: %v\n", connID1, err)
	} else {
		fmt.Printf("已关闭连接%d\n", connID1)
	}

	err = stateManager.CloseConnection(connID2)
	if err != nil {
		fmt.Printf("关闭连接%d失败: %v\n", connID2, err)
	} else {
		fmt.Printf("已关闭连接%d\n", connID2)
	}

	// 最终统计
	fmt.Println("\n最终全局统计:")
	finalStats, _ := stateManager.GetGlobalStats()
	for key, value := range finalStats {
		fmt.Printf("  %s: %v\n", key, value)
	}

	fmt.Println("\n示例程序完成!")
}

// 辅助函数：记录错误日志
func logError(err error) {
	if err != nil {
		errors.LogError(context.Background(), err)
	}
}
