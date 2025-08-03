//go:build !linux || !amd64

package ebpf

import (
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

// EBpfGeoIPMatcher fallback实现，用于非Linux平台
type EBpfGeoIPMatcher struct {
	sync.RWMutex
	
	// 配置
	countryCode  string
	reverseMatch bool
	enabled      bool
	
	// 统计信息
	matchCount   uint64
	missCount    uint64
	totalQueries uint64
}

// NewEBpfGeoIPMatcher 创建新的eBPF GeoIP匹配器（fallback实现）
func NewEBpfGeoIPMatcher(countryCode string, reverseMatch bool) (*EBpfGeoIPMatcher, error) {
	// 在非Linux平台上，eBPF不可用
	return &EBpfGeoIPMatcher{
		countryCode:  countryCode,
		reverseMatch: reverseMatch,
		enabled:      false,
	}, errors.New("eBPF GeoIP matcher not supported on this platform")
}

// AddIPv4CIDR 添加IPv4 CIDR范围（fallback实现）
func (m *EBpfGeoIPMatcher) AddIPv4CIDR(cidr *net.IPNet, countryCode string) error {
	return errors.New("eBPF GeoIP matcher not available on this platform")
}

// AddIPv6CIDR 添加IPv6 CIDR范围（fallback实现）
func (m *EBpfGeoIPMatcher) AddIPv6CIDR(cidr *net.IPNet, countryCode string) error {
	return errors.New("eBPF GeoIP matcher not available on this platform")
}

// MatchIPv4 匹配IPv4地址（fallback实现）
func (m *EBpfGeoIPMatcher) MatchIPv4(ip net.IP) bool {
	return false
}

// MatchIPv6 匹配IPv6地址（fallback实现）
func (m *EBpfGeoIPMatcher) MatchIPv6(ip net.IP) bool {
	return false
}

// Match 匹配IP地址（fallback实现）
func (m *EBpfGeoIPMatcher) Match(ip net.IP) bool {
	return false
}

// GetStats 获取统计信息（fallback实现）
func (m *EBpfGeoIPMatcher) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["match_count"] = uint64(0)
	stats["miss_count"] = uint64(0)
	stats["total_queries"] = uint64(0)
	stats["match_rate"] = 0.0
	stats["enabled"] = false
	stats["country_code"] = m.countryCode
	stats["reverse_match"] = m.reverseMatch
	stats["platform"] = "unsupported"
	
	return stats
}

// Close 关闭eBPF GeoIP匹配器（fallback实现）
func (m *EBpfGeoIPMatcher) Close() error {
	return nil
}

// IsEnabled 检查是否启用（fallback实现）
func (m *EBpfGeoIPMatcher) IsEnabled() bool {
	return false
}

// GetCountryCode 获取国家代码（fallback实现）
func (m *EBpfGeoIPMatcher) GetCountryCode() string {
	return m.countryCode
} 