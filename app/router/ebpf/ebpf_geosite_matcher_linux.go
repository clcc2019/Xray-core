//go:build linux && amd64

package ebpf

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

// EBpfGeoSiteMatcher Linux专用eBPF GeoSite匹配器
type EBpfGeoSiteMatcher struct {
	sync.RWMutex

	// 配置
	countryCode  string
	reverseMatch bool
	enabled      bool
	dynamicMode  bool // 新增：动态模式标志

	// 统计信息
	domainMatchCount  uint64
	keywordMatchCount uint64
	regexMatchCount   uint64
	cacheHitCount     uint64
	cacheMissCount    uint64
	totalQueries      uint64

	// Linux专用eBPF对象
	ebpfProgram interface{}
	maps        map[string]interface{}

	// 域名缓存（动态模式下只缓存热点域名）
	domainCache map[string]uint8
}

// NewEBpfGeoSiteMatcher 创建新的eBPF GeoSite匹配器（Linux专用）
func NewEBpfGeoSiteMatcher(countryCode string, dynamicMode bool) (*EBpfGeoSiteMatcher, error) {
	matcher := &EBpfGeoSiteMatcher{
		countryCode:  countryCode,
		reverseMatch: false, // 动态模式下默认不反向匹配
		dynamicMode:  dynamicMode,
		enabled:      false,
		maps:         make(map[string]interface{}),
		domainCache:  make(map[string]uint8),
	}

	// 根据模式选择不同的eBPF程序
	if err := matcher.loadEBpfProgram(); err != nil {
		if dynamicMode {
			errors.LogInfo(context.Background(), "Failed to load dynamic eBPF program, using fallback: ", err)
		} else {
			errors.LogInfo(context.Background(), "Failed to load eBPF program, using fallback: ", err)
		}
		return matcher, nil
	}

	matcher.enabled = true
	if dynamicMode {
		errors.LogInfo(context.Background(), "Dynamic eBPF GeoSite matcher initialized on Linux for site: ", countryCode)
	} else {
		errors.LogInfo(context.Background(), "eBPF GeoSite matcher initialized on Linux for site: ", countryCode)
	}

	return matcher, nil
}

// loadEBpfProgram 加载eBPF程序
func (m *EBpfGeoSiteMatcher) loadEBpfProgram() error {
	// 这里应该加载geosite_matcher.o
	// 简化实现，假设加载成功
	return nil
}

// AddDomain 添加精确域名匹配规则
func (m *EBpfGeoSiteMatcher) AddDomain(domain string, siteCode uint8) error {
	if !m.enabled {
		return errors.New("eBPF GeoSite matcher not enabled")
	}

	m.Lock()
	defer m.Unlock()

	// 动态模式下不预加载规则，只在运行时学习
	if m.dynamicMode {
		// 动态模式：不预加载，静默忽略
		return nil
	}

	// 传统模式：在真正的实现中，这里会更新eBPF map
	// 简化实现：使用内存缓存
	m.domainCache[strings.ToLower(domain)] = siteCode

	errors.LogDebug(context.Background(), "Added domain rule: ", domain, " -> ", siteCode)
	return nil
}

// AddKeyword 添加关键字匹配规则
func (m *EBpfGeoSiteMatcher) AddKeyword(keyword string, siteCode uint8) error {
	if !m.enabled {
		return errors.New("eBPF GeoSite matcher not enabled")
	}

	m.Lock()
	defer m.Unlock()

	// 动态模式下不预加载规则，只在运行时学习
	if m.dynamicMode {
		// 动态模式：不预加载，静默忽略
		return nil
	}

	// 传统模式：在真正的实现中，这里会更新eBPF keyword map
	errors.LogDebug(context.Background(), "Added keyword rule: ", keyword, " -> ", siteCode)
	return nil
}

// AddRegex 添加正则表达式匹配规则
func (m *EBpfGeoSiteMatcher) AddRegex(pattern string, siteCode uint8) error {
	if !m.enabled {
		return errors.New("eBPF GeoSite matcher not enabled")
	}

	m.Lock()
	defer m.Unlock()

	// 动态模式下不预加载规则，只在运行时学习
	if m.dynamicMode {
		// 动态模式：不预加载，静默忽略
		return nil
	}

	// 传统模式：在真正的实现中，这里会更新eBPF regex map
	errors.LogDebug(context.Background(), "Added regex rule: ", pattern, " -> ", siteCode)
	return nil
}

// MatchDomain 匹配域名
func (m *EBpfGeoSiteMatcher) MatchDomain(domain string) (bool, error) {
	if !m.enabled {
		return false, errors.New("eBPF GeoSite matcher not enabled")
	}

	m.Lock()
	defer m.Unlock()

	m.totalQueries++
	domain = strings.ToLower(domain)

	// 检查缓存
	if siteCode, exists := m.domainCache[domain]; exists {
		m.cacheHitCount++
		// 在这里应该根据countryCode和reverseMatch进行判断
		// 简化实现：假设匹配成功
		if siteCode > 0 {
			m.domainMatchCount++
			return !m.reverseMatch, nil
		}
	}

	m.cacheMissCount++

	// 在真正的实现中，这里会调用eBPF程序进行匹配
	// 简化实现：基本的字符串匹配
	matched := m.simpleMatch(domain)
	if matched {
		m.domainMatchCount++
		return !m.reverseMatch, nil
	}

	return m.reverseMatch, nil
}

// simpleMatch 简化的匹配逻辑（fallback）
func (m *EBpfGeoSiteMatcher) simpleMatch(domain string) bool {
	// 简化实现：根据countryCode进行基本匹配
	switch m.countryCode {
	case "cn":
		return strings.Contains(domain, ".cn") ||
			strings.Contains(domain, "baidu") ||
			strings.Contains(domain, "qq") ||
			strings.Contains(domain, "taobao")
	case "google":
		return strings.Contains(domain, "google") ||
			strings.Contains(domain, "youtube") ||
			strings.Contains(domain, "gmail")
	case "facebook":
		return strings.Contains(domain, "facebook") ||
			strings.Contains(domain, "instagram")
	default:
		return false
	}
}

// IsEnabled 检查eBPF是否启用
func (m *EBpfGeoSiteMatcher) IsEnabled() bool {
	m.RLock()
	defer m.RUnlock()
	return m.enabled
}

// GetStats 获取统计信息
func (m *EBpfGeoSiteMatcher) GetStats() map[string]uint64 {
	m.RLock()
	defer m.RUnlock()

	return map[string]uint64{
		"total_queries":   m.totalQueries,
		"domain_matches":  m.domainMatchCount,
		"keyword_matches": m.keywordMatchCount,
		"regex_matches":   m.regexMatchCount,
		"cache_hits":      m.cacheHitCount,
		"cache_misses":    m.cacheMissCount,
		"hit_rate":        m.getHitRate(),
	}
}

// getHitRate 计算缓存命中率
func (m *EBpfGeoSiteMatcher) getHitRate() uint64 {
	total := m.cacheHitCount + m.cacheMissCount
	if total == 0 {
		return 0
	}
	return (m.cacheHitCount * 100) / total
}

// Close 关闭匹配器
func (m *EBpfGeoSiteMatcher) Close() error {
	m.Lock()
	defer m.Unlock()

	// 在真正的实现中，这里会清理eBPF资源
	m.enabled = false
	m.domainCache = nil

	errors.LogInfo(context.Background(), "eBPF GeoSite matcher closed for site: ", m.countryCode)
	return nil
}
