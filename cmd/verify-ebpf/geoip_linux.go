//go:build linux

package main

import (
	"fmt"

	router_ebpf "github.com/xtls/xray-core/app/router/ebpf"
)

func testGeoIPBridge() {
	matcher, err := router_ebpf.NewEBpfGeoIPMatcher("CN", false)
	if err != nil {
		fmt.Printf("❌ GeoIP eBPF匹配器初始化失败: %v\n", err)
		return
	}
	defer matcher.Close()

	if !matcher.IsEnabled() {
		fmt.Println("❌ GeoIP eBPF匹配器未启用")
		return
	}

	fmt.Println("✅ GeoIP eBPF匹配器初始化成功")
	stats := matcher.GetStats()
	if *verbose {
		fmt.Println("   GeoIP eBPF统计信息:")
		for key, value := range stats {
			fmt.Printf("     %s: %v\n", key, value)
		}
	}
	fmt.Printf("   平台: %v\n", stats["platform"])
	fmt.Printf("   启用状态: %v\n", stats["enabled"])
	fmt.Printf("   国家代码: %v\n", stats["country_code"])
}
