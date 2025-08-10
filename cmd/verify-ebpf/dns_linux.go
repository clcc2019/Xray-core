//go:build linux

package main

import (
	"fmt"

	dns_ebpf "github.com/xtls/xray-core/app/dns/ebpf"
)

func testDNSBridge() {
	cache, err := dns_ebpf.NewEBpfDNSCache()
	if err != nil {
		fmt.Printf("❌ DNS eBPF缓存初始化失败: %v\n", err)
		return
	}
	defer cache.Close()

	if !cache.IsEnabled() {
		fmt.Println("❌ DNS eBPF缓存未启用")
		return
	}
	fmt.Println("✅ DNS eBPF缓存初始化成功")
	stats := cache.GetStats()
	if *verbose {
		fmt.Println("   DNS eBPF统计信息:")
		for key, value := range stats {
			fmt.Printf("     %s: %v\n", key, value)
		}
	}
	fmt.Printf("   平台: %v\n", stats["platform"])
	fmt.Printf("   启用状态: %v\n", stats["enabled"])
}
