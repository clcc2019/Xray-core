//go:build !linux || !amd64

package ebpf

import (
	"context"
	"strings"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

// EBpfGeoSiteMatcher 非Linux平台的fallback实现
type EBpfGeoSiteMatcher struct {
	sync.RWMutex

	// 配置
	countryCode  string
	reverseMatch bool
	enabled      bool

	// 统计信息
	domainMatchCount  uint64
	keywordMatchCount uint64
	regexMatchCount   uint64
	totalQueries      uint64

	// fallback存储
	domains  map[string]uint8
	keywords map[string]uint8
	regexes  map[string]uint8
}

// NewEBpfGeoSiteMatcher 创建新的GeoSite匹配器（fallback实现）
func NewEBpfGeoSiteMatcher(countryCode string, dynamicMode bool) (*EBpfGeoSiteMatcher, error) {
	matcher := &EBpfGeoSiteMatcher{
		countryCode:  countryCode,
		reverseMatch: false, // fallback不支持反向匹配
		enabled:      true,  // fallback总是启用
		domains:      make(map[string]uint8),
		keywords:     make(map[string]uint8),
		regexes:      make(map[string]uint8),
	}

	if dynamicMode {
		errors.LogInfo(context.Background(), "Dynamic GeoSite matcher initialized with fallback implementation for site: ", countryCode)
	} else {
		errors.LogInfo(context.Background(), "GeoSite matcher initialized with fallback implementation for site: ", countryCode)
	}

	return matcher, nil
}

// AddDomain 添加精确域名匹配规则
func (m *EBpfGeoSiteMatcher) AddDomain(domain string, siteCode uint8) error {
	m.Lock()
	defer m.Unlock()

	m.domains[strings.ToLower(domain)] = siteCode

	errors.LogDebug(context.Background(), "Added domain rule (fallback): ", domain, " -> ", siteCode)
	return nil
}

// AddKeyword 添加关键字匹配规则
func (m *EBpfGeoSiteMatcher) AddKeyword(keyword string, siteCode uint8) error {
	m.Lock()
	defer m.Unlock()

	m.keywords[strings.ToLower(keyword)] = siteCode

	errors.LogDebug(context.Background(), "Added keyword rule (fallback): ", keyword, " -> ", siteCode)
	return nil
}

// AddRegex 添加正则表达式匹配规则
func (m *EBpfGeoSiteMatcher) AddRegex(pattern string, siteCode uint8) error {
	m.Lock()
	defer m.Unlock()

	m.regexes[pattern] = siteCode

	errors.LogDebug(context.Background(), "Added regex rule (fallback): ", pattern, " -> ", siteCode)
	return nil
}

// MatchDomain 匹配域名（fallback实现）
func (m *EBpfGeoSiteMatcher) MatchDomain(domain string) (bool, error) {
	m.Lock()
	defer m.Unlock()

	m.totalQueries++
	domain = strings.ToLower(domain)

	// 精确域名匹配
	if _, exists := m.domains[domain]; exists {
		m.domainMatchCount++
		return !m.reverseMatch, nil
	}

	// 关键字匹配
	for keyword := range m.keywords {
		if strings.Contains(domain, keyword) {
			m.keywordMatchCount++
			return !m.reverseMatch, nil
		}
	}

	// 简化的正则匹配
	for pattern := range m.regexes {
		if strings.Contains(domain, pattern) {
			m.regexMatchCount++
			return !m.reverseMatch, nil
		}
	}

	// 基本匹配逻辑
	if m.basicMatch(domain) {
		m.domainMatchCount++
		return !m.reverseMatch, nil
	}

	return m.reverseMatch, nil
}

// basicMatch 基本匹配逻辑
func (m *EBpfGeoSiteMatcher) basicMatch(domain string) bool {
	// 基于countryCode的基本匹配
	switch m.countryCode {
	case "cn":
		return strings.Contains(domain, ".cn") ||
			strings.Contains(domain, "baidu") ||
			strings.Contains(domain, "qq") ||
			strings.Contains(domain, "taobao") ||
			strings.Contains(domain, "weibo") ||
			strings.Contains(domain, "sina")
	case "google":
		return strings.Contains(domain, "google") ||
			strings.Contains(domain, "youtube") ||
			strings.Contains(domain, "gmail") ||
			strings.Contains(domain, "gstatic")
	case "facebook":
		return strings.Contains(domain, "facebook") ||
			strings.Contains(domain, "instagram") ||
			strings.Contains(domain, "whatsapp")
	case "twitter":
		return strings.Contains(domain, "twitter") ||
			strings.Contains(domain, "twimg")
	case "apple":
		return strings.Contains(domain, "apple") ||
			strings.Contains(domain, "icloud")
	case "microsoft":
		return strings.Contains(domain, "microsoft") ||
			strings.Contains(domain, "outlook") ||
			strings.Contains(domain, "office")
	default:
		return false
	}
}

// IsEnabled 检查是否启用
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
		"implementation":  0, // 0 = fallback, 1 = eBPF
	}
}

// Close 关闭匹配器
func (m *EBpfGeoSiteMatcher) Close() error {
	m.Lock()
	defer m.Unlock()

	m.enabled = false
	m.domains = nil
	m.keywords = nil
	m.regexes = nil

	errors.LogInfo(context.Background(), "GeoSite matcher closed (fallback) for site: ", m.countryCode)
	return nil
}
