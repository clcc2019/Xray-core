//go:build linux

package main

import (
	"os"

	routerebpf "github.com/xtls/xray-core/app/router/ebpf"
	inetebpf "github.com/xtls/xray-core/transport/internet/ebpf"
	transportebpf "github.com/xtls/xray-core/transport/internet/tcp/ebpf"
)

func initEBPFAtRun() {
	// Initialize TCP CC eBPF policy (best-effort)
	_ = transportebpf.InitDefaultTCPCCPolicy()
	if os.Getenv("XRAY_EBPF") == "1" {
		// Apply default marks/policies if available
		routerebpf.NewPolicyManager().ApplyDefaultsFromEnv()
		// 启动透明加速器（best-effort）
		_ = inetebpf.GetGlobalAccelerator().Start()
		// 尝试打开 cgroup/connect 资源（attach 由部署脚本负责）
		_ = inetebpf.StartCgroupConnect()
	}
}
