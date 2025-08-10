//go:build linux

package main

import (
	"os"

	routerebpf "github.com/xtls/xray-core/app/router/ebpf"
	transportebpf "github.com/xtls/xray-core/transport/internet/tcp/ebpf"
)

func initEBPFAtRun() {
	// Initialize TCP CC eBPF policy (best-effort)
	_ = transportebpf.InitDefaultTCPCCPolicy()
	if os.Getenv("XRAY_EBPF") == "1" {
		// Apply default marks/policies if available
		routerebpf.NewPolicyManager().ApplyDefaultsFromEnv()
	}
}
