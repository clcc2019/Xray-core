// +build ignore
//go:build !linux || !amd64
// +build !linux !amd64

package ebpf

import (
	"context"
	"net"
	"sync"
)

// DynamicGeoIPMatcher fallback implementation
type DynamicGeoIPMatcher struct {
	enabled bool
	mu      sync.RWMutex
}

// DynamicGeoSiteMatcher fallback implementation
type DynamicGeoSiteMatcher struct {
	enabled bool
	mu      sync.RWMutex
}

// GeoIP动态统计
type GeoIPDynamicStats struct {
	TotalQueries    uint64 `json:"total_queries"`
	CacheHits       uint64 `json:"cache_hits"`
	CacheMisses     uint64 `json:"cache_misses"`
	DynamicAdds     uint64 `json:"dynamic_adds"`
	HotIPPromotions uint64 `json:"hot_ip_promotions"`
}

// GeoSite动态统计
type GeoSiteDynamicStats struct {
	TotalQueries        uint64 `json:"total_queries"`
	CacheHits           uint64 `json:"cache_hits"`
	CacheMisses         uint64 `json:"cache_misses"`
	DynamicAdds         uint64 `json:"dynamic_adds"`
	HotDomainPromotions uint64 `json:"hot_domain_promotions"`
	DNSPackets          uint64 `json:"dns_packets"`
}

// GeoIP动态配置
type GeoIPDynamicConfig struct {
	CacheEnabled   uint32 `json:"cache_enabled"`
	MinAccessCount uint32 `json:"min_access_count"`
	MaxCacheSize   uint32 `json:"max_cache_size"`
	TTLSeconds     uint32 `json:"ttl_seconds"`
}

// GeoSite动态配置
type GeoSiteDynamicConfig struct {
	CacheEnabled   uint32 `json:"cache_enabled"`
	MinAccessCount uint32 `json:"min_access_count"`
	MaxCacheSize   uint32 `json:"max_cache_size"`
	TTLSeconds     uint32 `json:"ttl_seconds"`
}

// NewDynamicGeoIPMatcher 创建动态GeoIP匹配器 (fallback)
func NewDynamicGeoIPMatcher() *DynamicGeoIPMatcher {
	return &DynamicGeoIPMatcher{
		enabled: false, // fallback implementation is disabled
	}
}

// NewDynamicGeoSiteMatcher 创建动态GeoSite匹配器 (fallback)
func NewDynamicGeoSiteMatcher() *DynamicGeoSiteMatcher {
	return &DynamicGeoSiteMatcher{
		enabled: false, // fallback implementation is disabled
	}
}

// LookupIP fallback implementation
func (m *DynamicGeoIPMatcher) LookupIP(ip net.IP) (string, bool) {
	return "", false
}

// LookupDomain fallback implementation
func (m *DynamicGeoSiteMatcher) LookupDomain(domain string) (string, bool) {
	return "", false
}

// GetGeoIPStats fallback implementation
func (m *DynamicGeoIPMatcher) GetGeoIPStats() (*GeoIPDynamicStats, error) {
	return &GeoIPDynamicStats{}, nil
}

// GetGeoSiteStats fallback implementation
func (m *DynamicGeoSiteMatcher) GetGeoSiteStats() (*GeoSiteDynamicStats, error) {
	return &GeoSiteDynamicStats{}, nil
}

// UpdateGeoIPConfig fallback implementation
func (m *DynamicGeoIPMatcher) UpdateGeoIPConfig(config *GeoIPDynamicConfig) error {
	return nil
}

// UpdateGeoSiteConfig fallback implementation
func (m *DynamicGeoSiteMatcher) UpdateGeoSiteConfig(config *GeoSiteDynamicConfig) error {
	return nil
}

// PerformMaintenance fallback implementation
func (m *DynamicGeoIPMatcher) PerformMaintenance(ctx context.Context) {
	// 空实现
}

// GetCacheSize fallback implementation
func (m *DynamicGeoIPMatcher) GetCacheSize() (int, error) {
	return 0, nil
}

// Close fallback implementation
func (m *DynamicGeoIPMatcher) Close() error {
	return nil
}

// Close fallback implementation
func (m *DynamicGeoSiteMatcher) Close() error {
	return nil
}
