package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/xtls/xray-core/app/dns"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func main() {
	fmt.Println("=== eBPF DNS缓存示例 ===")

	// 1. 基本eBPF缓存使用
	fmt.Println("\n1. 测试基本eBPF缓存功能")
	testBasicCache()

	// 2. 缓存控制器使用
	fmt.Println("\n2. 测试缓存控制器功能")
	testCacheController()

	// 3. 性能测试
	fmt.Println("\n3. 性能测试")
	testPerformance()

	fmt.Println("\n=== 示例完成 ===")
}

func testBasicCache() {
	// 创建eBPF DNS缓存
	cache, err := dns.NewEBpfDNSCache()
	if err != nil {
		log.Printf("警告: 无法创建eBPF缓存，使用模拟模式: %v", err)
		return
	}
	defer cache.Close()

	// 添加测试数据
	testDomains := []string{
		"google.com",
		"github.com",
		"stackoverflow.com",
		"reddit.com",
		"youtube.com",
	}

	for i, domain := range testDomains {
		ips := []net.IP{net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1))}
		err := cache.AddRecord(domain, ips, 300, 0)
		if err != nil {
			log.Printf("添加记录失败 %s: %v", domain, err)
			continue
		}
		fmt.Printf("✓ 添加记录: %s -> %s\n", domain, ips[0])
	}

	// 测试查找
	for _, domain := range testDomains {
		ips, ttl, err := cache.LookupRecord(domain)
		if err != nil {
			fmt.Printf("✗ 查找失败 %s: %v\n", domain, err)
			continue
		}
		fmt.Printf("✓ 查找成功 %s -> %s (TTL: %d)\n", domain, ips[0], ttl)
	}

	// 显示统计信息
	stats := cache.GetStats()
	fmt.Printf("缓存统计: 命中率=%.2f%%, 大小=%d\n",
		stats["hit_rate"].(float64)*100, cache.Size())
}

func testCacheController() {
	// 创建eBPF缓存控制器
	controller, err := dns.NewEBpfCacheController("test-controller", false)
	if err != nil {
		log.Printf("警告: 无法创建eBPF缓存控制器: %v", err)
		return
	}
	defer controller.Close()

	// 测试DNS查询
	testQueries := []string{
		"example.com",
		"test.org",
		"demo.net",
	}

	for _, domain := range testQueries {
		ips, ttl, err := controller.findIPsForDomain(domain, dns_feature.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
		})
		if err != nil {
			fmt.Printf("✗ 查询失败 %s: %v\n", domain, err)
			continue
		}
		fmt.Printf("✓ 查询成功 %s -> %s (TTL: %d)\n", domain, ips[0], ttl)
	}

	// 显示统计信息
	stats := controller.GetStats()
	fmt.Printf("控制器统计: eBPF启用=%v, 命中率=%.2f%%\n",
		stats["ebpf_enabled"], stats["ebpf_hit_rate"].(float64)*100)
}

func testPerformance() {
	// 创建eBPF DNS缓存
	cache, err := dns.NewEBpfDNSCache()
	if err != nil {
		log.Printf("警告: 无法创建eBPF缓存进行性能测试: %v", err)
		return
	}
	defer cache.Close()

	// 性能测试参数
	numRecords := 1000
	numLookups := 10000

	// 预热：添加测试记录
	fmt.Printf("预热: 添加 %d 条记录...\n", numRecords)
	start := time.Now()
	for i := 0; i < numRecords; i++ {
		domain := fmt.Sprintf("test%d.example.com", i)
		ips := []net.IP{net.ParseIP(fmt.Sprintf("192.168.1.%d", i%255))}
		err := cache.AddRecord(domain, ips, 3600, 0)
		if err != nil {
			log.Printf("添加记录失败: %v", err)
		}
	}
	addTime := time.Since(start)
	fmt.Printf("✓ 添加完成，耗时: %v\n", addTime)

	// 查找性能测试
	fmt.Printf("性能测试: 执行 %d 次查找...\n", numLookups)
	start = time.Now()
	hitCount := 0
	for i := 0; i < numLookups; i++ {
		domain := fmt.Sprintf("test%d.example.com", i%numRecords)
		_, _, err := cache.LookupRecord(domain)
		if err == nil {
			hitCount++
		}
	}
	lookupTime := time.Since(start)

	// 显示性能结果
	fmt.Printf("✓ 查找完成，耗时: %v\n", lookupTime)
	fmt.Printf("✓ 命中次数: %d/%d (%.2f%%)\n", hitCount, numLookups, float64(hitCount)/float64(numLookups)*100)
	fmt.Printf("✓ 平均查找时间: %v\n", lookupTime/time.Duration(numLookups))

	// 显示最终统计
	stats := cache.GetStats()
	fmt.Printf("✓ 最终统计: 命中率=%.2f%%, 缓存大小=%d\n",
		stats["hit_rate"].(float64)*100, cache.Size())
}

// 模拟DNS服务器响应
func simulateDNSResponse(domain string) ([]net.IP, uint32) {
	// 模拟DNS解析延迟
	time.Sleep(10 * time.Millisecond)

	// 返回模拟的IP地址
	ips := []net.IP{
		net.ParseIP("192.168.1.100"),
		net.ParseIP("192.168.1.101"),
	}
	return ips, 300
}
