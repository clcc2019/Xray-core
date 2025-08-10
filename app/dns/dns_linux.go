//go:build linux

package dns

import (
	"net"

	dnsebpf "github.com/xtls/xray-core/app/dns/ebpf"
	routerebpf "github.com/xtls/xray-core/app/router/ebpf"
)

// 覆盖非 Linux 的默认实现：查询 geosite 策略 mark
func dnsLookupSitePolicyMark() uint32 {
	if v, ok := routerebpf.GetGeoSitePolicyMark(1); ok {
		return v
	}
	return 0
}

// newEbpfDNSCache 返回 eBPF DNS 缓存实例
func newEbpfDNSCache() (ebpfDNSCache, bool) {
	if cache, err := dnsebpf.NewEBpfDNSCache(); err == nil && cache != nil && cache.IsEnabled() {
		return cache, true
	}
	return nil, false
}

// ipFastpathEnable -> router/ebpf
func ipFastpathEnable(enable bool) { routerebpf.EnableIPFastpath(enable) }

// setIPv4Mark/setIPv6Mark -> router/ebpf
func setIPv4Mark(ip net.IP, mark uint32, ttlSeconds uint32) {
	routerebpf.SetIPv4Mark(ip, mark, ttlSeconds)
}
func setIPv6Mark(ip net.IP, mark uint32, ttlSeconds uint32) {
	routerebpf.SetIPv6Mark(ip, mark, ttlSeconds)
}
