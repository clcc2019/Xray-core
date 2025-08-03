//go:build !linux || !amd64

package ebpf

import (
	"net"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

// EBpfDNSCache fallback实现，用于非Linux平台
type EBpfDNSCache struct {
	sync.RWMutex

	// 配置
	maxEntries uint32
	enabled    bool

	// 统计信息
	hitCount     uint64
	missCount    uint64
	totalQueries uint64
}

// NewEBpfDNSCache 创建新的eBPF DNS缓存（fallback实现）
func NewEBpfDNSCache() (*EBpfDNSCache, error) {
	// 在非Linux平台上，eBPF不可用，直接返回禁用状态
	return &EBpfDNSCache{
		maxEntries: 0,
		enabled:    false,
	}, errors.New("eBPF not supported on this platform")
}

// AddRecord 添加DNS记录到缓存（fallback实现）
func (c *EBpfDNSCache) AddRecord(domain string, ips []net.IP, ttl uint32, rcode uint16) error {
	return errors.New("eBPF DNS cache not available on this platform")
}

// LookupRecord 从缓存中查找DNS记录（fallback实现）
func (c *EBpfDNSCache) LookupRecord(domain string) ([]net.IP, uint32, error) {
	return nil, 0, errors.New("eBPF DNS cache not available on this platform")
}

// DeleteRecord 删除DNS记录（fallback实现）
func (c *EBpfDNSCache) DeleteRecord(domain string) error {
	return errors.New("eBPF DNS cache not available on this platform")
}

// CleanupExpired 清理过期记录（fallback实现）
func (c *EBpfDNSCache) CleanupExpired() error {
	return errors.New("eBPF DNS cache not available on this platform")
}

// GetStats 获取统计信息（fallback实现）
func (c *EBpfDNSCache) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["hit_count"] = uint64(0)
	stats["miss_count"] = uint64(0)
	stats["total_queries"] = uint64(0)
	stats["hit_rate"] = 0.0
	stats["enabled"] = false
	stats["platform"] = "unsupported"

	return stats
}

// Close 关闭eBPF DNS缓存（fallback实现）
func (c *EBpfDNSCache) Close() error {
	return nil
}

// IsEnabled 检查是否启用（fallback实现）
func (c *EBpfDNSCache) IsEnabled() bool {
	return false
}

// Size 获取缓存大小（fallback实现）
func (c *EBpfDNSCache) Size() int {
	return 0
}
