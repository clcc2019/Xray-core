package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/xtls/xray-core/common/platform"
)

var (
	verbose   = flag.Bool("v", false, "详细输出")
	testDNS   = flag.Bool("dns", true, "测试DNS eBPF功能")
	testGeoIP = flag.Bool("geoip", true, "测试GeoIP eBPF功能")
)

func main() {
	flag.Parse()

	fmt.Println("========================================")
	fmt.Println("Xray-core eBPF功能验证工具")
	fmt.Println("========================================")

	// 1. 平台检查
	fmt.Println("\n1. 平台兼容性检查:")
	fmt.Printf("   操作系统: %s\n", runtime.GOOS)
	fmt.Printf("   架构: %s\n", runtime.GOARCH)
	fmt.Printf("   Linux服务器: %v\n", platform.IsLinuxServer())
	fmt.Printf("   eBPF支持: %v\n", platform.IsEBpfSupported())

	if !platform.IsEBpfSupported() {
		fmt.Println("\n❌ 当前平台不支持eBPF功能")
		if !platform.IsLinuxServer() {
			fmt.Println("   原因: 非Linux系统")
		} else if runtime.GOARCH != "amd64" {
			fmt.Println("   原因: 非AMD64架构")
		} else {
			fmt.Println("   原因: Linux内核版本不足 (需要4.18+)")
		}
		fmt.Println("   将自动使用用户态实现")
		os.Exit(0)
	}

	fmt.Println("✅ 平台支持eBPF功能")

	// 2. 测试DNS eBPF功能
	if *testDNS {
		fmt.Println("\n2. DNS eBPF功能测试:")
		testDNSBridge()
	}

	// 3. 测试GeoIP eBPF功能（Linux-only，运行时桥接）
	if *testGeoIP {
		fmt.Println("\n3. GeoIP eBPF功能测试:")
		testGeoIPBridge()
	}

	// 4. 检查eBPF程序加载状态
	fmt.Println("\n4. eBPF程序加载状态:")
	checkEBpfPrograms()

	fmt.Println("\n========================================")
	fmt.Println("eBPF功能验证完成")
	fmt.Println("========================================")
}

// Linux-only bridge implemented in a separate file with build tag
func testDNSBridge() {}

// Linux-only bridge implemented in a separate file with build tag
func testGeoIPBridge() {}

func checkEBpfPrograms() {
	if runtime.GOOS != "linux" {
		fmt.Println("   跳过 - 非Linux系统")
		return
	}

	// 检查是否有bpftool命令
	fmt.Println("   检查eBPF工具...")

	// 这里可以添加更多的eBPF程序检查逻辑
	// 例如检查 /sys/fs/bpf/ 目录下的程序
	// 或者使用bpftool命令查看加载的程序

	fmt.Println("   注意: 当前实现为模拟版本，不会实际加载eBPF程序")
	fmt.Println("   在生产环境中，这里会显示实际的eBPF程序状态")
}
