//go:build linux

package main

import (
	"errors"

	dns_ebpf "github.com/xtls/xray-core/app/dns/ebpf"
)

func testDNSBridge() (bool, map[string]interface{}, error) {
	cache, err := dns_ebpf.NewEBpfDNSCache()
	if err != nil {
		return false, nil, err
	}
	defer cache.Close()

	stats := cache.GetStats()
	if !cache.IsEnabled() {
		return false, stats, errors.New("DNS eBPF 未启用")
	}
	return true, stats, nil
}
