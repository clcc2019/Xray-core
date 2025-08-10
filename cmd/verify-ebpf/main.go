package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/platform"
)

var (
	verbose    = flag.Bool("v", false, "详细输出")
	testDNS    = flag.Bool("dns", true, "测试DNS eBPF功能")
	testGeoIP  = flag.Bool("geoip", true, "测试GeoIP eBPF功能")
	outputJSON = flag.Bool("json", false, "以 JSON 输出结果，便于机器解析")
	strictExit = flag.Bool("strict", false, "严格模式：若 eBPF 不可用或任一测试失败，使用非零退出码")

	geoipCountry = flag.String("geoip-country", "CN", "GeoIP 测试国家代码（例如 CN/US/...）")
	geoipReverse = flag.Bool("geoip-reverse", false, "GeoIP 反向匹配（非该国家为真）")

	syscheckTimeout = flag.Duration("syscheck-timeout", time.Second, "系统检查超时时间，例如 500ms/1s/2s")
)

type (
	platformInfo struct {
		OS            string `json:"os"`
		Arch          string `json:"arch"`
		IsLinuxServer bool   `json:"is_linux_server"`
		EBpfSupported bool   `json:"ebpf_supported"`
	}

	ebpfProgramsStatus struct {
		IsLinux           bool     `json:"is_linux"`
		BPFToolPresent    bool     `json:"bpftool_present"`
		BPFToolError      string   `json:"bpftool_error,omitempty"`
		PinnedDir         string   `json:"pinned_dir,omitempty"`
		PinnedDirExists   bool     `json:"pinned_dir_exists"`
		PinnedXrayDir     string   `json:"pinned_xray_dir,omitempty"`
		PinnedXrayExists  bool     `json:"pinned_xray_exists"`
		XrayPinnedMaps    []string `json:"xray_pinned_maps,omitempty"`
		SampleProgramSumm []string `json:"sample_program_summ,omitempty"`
	}

	testResult struct {
		OK    bool                   `json:"ok"`
		Stats map[string]interface{} `json:"stats,omitempty"`
		Error string                 `json:"error,omitempty"`
	}

	verifyReport struct {
		Platform platformInfo       `json:"platform"`
		DNS      *testResult        `json:"dns,omitempty"`
		GeoIP    *testResult        `json:"geoip,omitempty"`
		System   ebpfProgramsStatus `json:"system"`
	}
)

// 由 main 注入到平台实现（stub 在非 Linux 平台定义；Linux 平台在 geoip_linux.go 定义）

func main() {
	// 自定义 Usage（当用户传 -h 时更友好）
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n", filepath.Base(os.Args[0]))
		fmt.Fprintln(os.Stderr, "\n选项：")
		flag.PrintDefaults()
	}

	flag.Parse()

	if !*outputJSON {
		fmt.Println("========================================")
		fmt.Println("Xray-core eBPF功能验证工具")
		fmt.Println("========================================")
	}

	// 1. 平台检查
	info := platformInfo{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		IsLinuxServer: platform.IsLinuxServer(),
		EBpfSupported: platform.IsEBpfSupported(),
	}

	if !*outputJSON {
		fmt.Println("\n1. 平台兼容性检查:")
		fmt.Printf("   操作系统: %s\n", info.OS)
		fmt.Printf("   架构: %s\n", info.Arch)
		fmt.Printf("   Linux服务器: %v\n", info.IsLinuxServer)
		fmt.Printf("   eBPF支持: %v\n", info.EBpfSupported)
	}

	if !info.EBpfSupported {
		if !*outputJSON {
			fmt.Println("\n❌ 当前平台不支持eBPF功能")
			if !info.IsLinuxServer {
				fmt.Println("   原因: 非Linux系统")
			} else if runtime.GOARCH != "amd64" {
				fmt.Println("   原因: 非AMD64架构")
			} else {
				fmt.Println("   原因: Linux内核版本不足 (需要4.18+)")
			}
			fmt.Println("   将自动使用用户态实现")
		}
		if *strictExit {
			outputAndExit(verifyReport{Platform: info, System: collectEBpfSystemStatus(*syscheckTimeout, *verbose)}, 1, *outputJSON)
			return
		}
		outputAndExit(verifyReport{Platform: info, System: collectEBpfSystemStatus(*syscheckTimeout, *verbose)}, 0, *outputJSON)
		return
	}

	if !*outputJSON {
		fmt.Println("✅ 平台支持eBPF功能")
	}

	// 2. 测试DNS eBPF功能
	var dnsRes *testResult
	if *testDNS {
		if !*outputJSON {
			fmt.Println("\n2. DNS eBPF功能测试:")
		}
		ok, stats, err := testDNSBridge()
		dnsRes = &testResult{OK: ok, Stats: stats}
		if err != nil {
			dnsRes.Error = err.Error()
		}
	}

	// 3. 测试GeoIP eBPF功能（Linux-only，运行时桥接）
	var geoRes *testResult
	if *testGeoIP {
		if !*outputJSON {
			fmt.Println("\n3. GeoIP eBPF功能测试:")
		}
		// 通过包级变量传递给 Linux 平台实现（stub 在非 Linux 下定义同名变量）
		setGeoIPFlags(*geoipCountry, *geoipReverse)
		ok, stats, err := testGeoIPBridge()
		geoRes = &testResult{OK: ok, Stats: stats}
		if err != nil {
			geoRes.Error = err.Error()
		}
	}

	// 4. 检查eBPF程序加载状态
	systemStatus := collectEBpfSystemStatus(*syscheckTimeout, *verbose)
	if !*outputJSON {
		fmt.Println("\n4. eBPF程序加载状态:")
		prettyPrintSystemStatus(systemStatus)
		fmt.Println("\n========================================")
		fmt.Println("eBPF功能验证完成")
		fmt.Println("========================================")
	}

	// 退出码策略
	exitCode := 0
	if *strictExit {
		if (dnsRes != nil && !dnsRes.OK) || (geoRes != nil && !geoRes.OK) || !info.EBpfSupported {
			exitCode = 1
		}
	}
	outputAndExit(verifyReport{Platform: info, DNS: dnsRes, GeoIP: geoRes, System: systemStatus}, exitCode, *outputJSON)
}

// Linux-only bridge在对应平台文件实现，这里不提供实现

func collectEBpfSystemStatus(timeout time.Duration, verbose bool) ebpfProgramsStatus {
	status := ebpfProgramsStatus{IsLinux: runtime.GOOS == "linux"}
	if !status.IsLinux {
		return status
	}

	// 检查常见 bpffs 挂载点
	for _, d := range []string{"/sys/fs/bpf", "/run/bpffs"} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			status.PinnedDir = d
			status.PinnedDirExists = true
			break
		}
	}
	if status.PinnedDirExists {
		xdir := filepath.Join(status.PinnedDir, "xray")
		if fi, err := os.Stat(xdir); err == nil && fi.IsDir() {
			status.PinnedXrayDir = xdir
			status.PinnedXrayExists = true
			if verbose {
				if ents, err := os.ReadDir(xdir); err == nil {
					for _, e := range ents {
						status.XrayPinnedMaps = append(status.XrayPinnedMaps, e.Name())
					}
				}
			}
		}
	}

	// 检查 bpftool 是否可用
	if p, err := exec.LookPath("bpftool"); err == nil {
		status.BPFToolPresent = true
		if verbose {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, p, "prog", "show")
			out, err := cmd.Output()
			if ctx.Err() == context.DeadlineExceeded {
				status.BPFToolError = "bpftool 超时"
			} else if err == nil {
				status.SampleProgramSumm = firstNonEmptyLines(string(out), 10)
			} else {
				status.BPFToolError = err.Error()
			}
		}
	} else {
		status.BPFToolError = "bpftool 不存在"
	}

	return status
}

func prettyPrintSystemStatus(s ebpfProgramsStatus) {
	if !s.IsLinux {
		fmt.Println("   跳过 - 非Linux系统")
		return
	}
	fmt.Printf("   固定挂载目录: %s 存在=%v\n", defaultIfEmpty(s.PinnedDir, "/sys/fs/bpf"), s.PinnedDirExists)
	fmt.Printf("   bpftool: 存在=%v\n", s.BPFToolPresent)
	if s.BPFToolError != "" {
		fmt.Printf("   bpftool 错误: %s\n", s.BPFToolError)
	}
	if len(s.SampleProgramSumm) > 0 {
		fmt.Println("   已加载程序（示例，最多10行）：")
		for _, l := range s.SampleProgramSumm {
			fmt.Printf("     %s\n", l)
		}
	}
}

func outputAndExit(r verifyReport, code int, asJSON bool) {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	}
	os.Exit(code)
}

func firstNonEmptyLines(s string, limit int) []string {
	scanner := bufio.NewScanner(strings.NewReader(s))
	lines := make([]string, 0, limit)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		lines = append(lines, text)
		if len(lines) >= limit {
			break
		}
	}
	return lines
}

func defaultIfEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
