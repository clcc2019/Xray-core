//go:build !linux

package dns

import "net"

// 非 Linux 平台：统一 no-op 实现，避免编译错误
func newEbpfDNSCache() (ebpfDNSCache, bool)                 { return nil, false }
func dnsLookupSitePolicyMark() uint32                       { return 0 }
func ipFastpathEnable(enable bool)                          {}
func setIPv4Mark(ip net.IP, mark uint32, ttlSeconds uint32) {}
func setIPv6Mark(ip net.IP, mark uint32, ttlSeconds uint32) {}
