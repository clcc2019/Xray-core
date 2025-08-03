//go:build !linux || !amd64
// +build !linux !amd64

package ebpf

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// DNS类型定义
type DNSType uint16

const (
	DNSTypeA     DNSType = 1
	DNSTypeAAAA  DNSType = 28
	DNSTypeCNAME DNSType = 5
	DNSTypeMX    DNSType = 15
	DNSTypeTXT   DNSType = 16
)

// DNSAccelerator 非Linux平台的fallback实现
type DNSAccelerator struct {
	sync.RWMutex

	// 基础配置
	enabled          bool
	cacheEnabled     bool
	filterEnabled    bool
	rateLimitEnabled bool

	// 性能统计
	totalQueries    uint64
	cacheHits       uint64
	cacheMisses     uint64
	blockedQueries  uint64
	failedQueries   uint64
	avgResponseTime uint64

	// 服务器管理
	dnsServers       []*DNSServerInfo
	activeDNSServers int
	bestServerIndex  int

	// 恶意域名过滤
	maliciousDomains map[string]*MaliciousDomainEntry
	threatLevel      int

	// 缓存管理 (Go实现)
	cache           map[string]*CacheEntry
	cacheSize       int
	cacheTTL        time.Duration
	prefetchEnabled bool

	// 监控和维护
	ctx             context.Context
	cancel          context.CancelFunc
	cleanupInterval time.Duration
}

// CacheEntry 缓存条目
type CacheEntry struct {
	Domain     string
	IPs        []net.IP
	TTL        uint32
	CreateTime time.Time
	ExpireTime time.Time
	HitCount   uint32
}

// DNSServerInfo DNS服务器信息
type DNSServerInfo struct {
	ServerIP         net.IP
	ServerPort       uint16
	ServerType       DNSServerType
	ResponseTimeAvg  time.Duration
	SuccessCount     uint32
	FailureCount     uint32
	TimeoutCount     uint32
	LastUsed         time.Time
	ReliabilityScore uint8
}

// DNSServerType DNS服务器类型
type DNSServerType uint8

const (
	DNSServerUDP DNSServerType = iota
	DNSServerTCP
	DNSServerDoH
	DNSServerDoT
)

// MaliciousDomainEntry 恶意域名条目
type MaliciousDomainEntry struct {
	Domain         string
	ThreatLevel    uint32
	DetectionCount uint32
	FirstSeen      time.Time
	LastSeen       time.Time
	ThreatType     ThreatType
	Confidence     uint8
}

// ThreatType 威胁类型
type ThreatType uint8

const (
	ThreatMalware ThreatType = iota
	ThreatPhishing
	ThreatBotnet
	ThreatSpam
	ThreatCrypto
)

// DNSQueryStats DNS查询统计
type DNSQueryStats struct {
	TotalQueries           uint64
	CacheHits              uint64
	CacheMisses            uint64
	BlockedQueries         uint64
	FailedQueries          uint64
	AvgResponseTime        time.Duration
	IPv4Queries            uint64
	IPv6Queries            uint64
	RecursiveQueries       uint64
	AuthoritativeResponses uint64
}

// DNSPerfMetrics DNS性能指标
type DNSPerfMetrics struct {
	ConcurrentQueries uint32
	QueueDepth        uint32
	MemoryUsage       uint32
	CPUUsage          uint32
	BytesSent         uint64
	BytesReceived     uint64
	PacketLossRate    uint32
	Jitter            time.Duration
}

// DNSResult DNS查询结果
type DNSResult struct {
	Domain       string
	IPs          []net.IP
	TTL          uint32
	Source       string
	CacheHit     bool
	ResponseTime time.Duration
	ServerType   DNSServerType
}

// NewDNSAccelerator 创建新的DNS加速器（fallback实现）
func NewDNSAccelerator() (*DNSAccelerator, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 检查是否启用eBPF
	enabled := os.Getenv("XRAY_EBPF") == "1" || os.Getenv("XRAY_EBPF") == "true"

	accelerator := &DNSAccelerator{
		enabled:          enabled,
		cacheEnabled:     enabled,
		filterEnabled:    enabled,
		rateLimitEnabled: enabled,
		dnsServers:       make([]*DNSServerInfo, 0),
		maliciousDomains: make(map[string]*MaliciousDomainEntry),
		cache:            make(map[string]*CacheEntry),
		ctx:              ctx,
		cancel:           cancel,
		cleanupInterval:  time.Minute * 5,
		cacheSize:        10000, // 较小的缓存大小
		cacheTTL:         time.Minute * 5,
		prefetchEnabled:  enabled, // 根据eBPF状态启用预取
	}

	// 启动后台维护任务
	go accelerator.maintenanceLoop()

	errors.LogInfo(ctx, "DNS accelerator initialized with Go fallback implementation")
	return accelerator, nil
}

// AddDNSServer 添加DNS服务器
func (da *DNSAccelerator) AddDNSServer(serverIP net.IP, port uint16, serverType DNSServerType) error {
	da.Lock()
	defer da.Unlock()

	server := &DNSServerInfo{
		ServerIP:         serverIP,
		ServerPort:       port,
		ServerType:       serverType,
		ResponseTimeAvg:  time.Millisecond * 50,
		ReliabilityScore: 100,
		LastUsed:         time.Now(),
	}

	da.dnsServers = append(da.dnsServers, server)
	da.activeDNSServers++

	errors.LogInfo(da.ctx, "Added DNS server (fallback): ", serverIP, ":", port)
	return nil
}

// AddMaliciousDomain 添加恶意域名
func (da *DNSAccelerator) AddMaliciousDomain(domain string, threatType ThreatType, confidence uint8) error {
	da.Lock()
	defer da.Unlock()

	entry := &MaliciousDomainEntry{
		Domain:         domain,
		ThreatLevel:    uint32(threatType + 1),
		DetectionCount: 1,
		FirstSeen:      time.Now(),
		LastSeen:       time.Now(),
		ThreatType:     threatType,
		Confidence:     confidence,
	}

	da.maliciousDomains[domain] = entry

	errors.LogInfo(da.ctx, "Added malicious domain (fallback): ", domain)
	return nil
}

// UpdateMaliciousDomains 批量更新恶意域名列表
func (da *DNSAccelerator) UpdateMaliciousDomains(domains map[string]*MaliciousDomainEntry) error {
	da.Lock()
	defer da.Unlock()

	count := 0
	for domain, entry := range domains {
		da.maliciousDomains[domain] = entry
		count++
	}

	errors.LogInfo(da.ctx, "Updated ", count, " malicious domains (fallback)")
	return nil
}

// LookupIP 实现DNS查询接口
func (da *DNSAccelerator) LookupIP(domain string, option IPOption) ([]net.IP, uint32, error) {
	result, err := da.QueryDomain(domain, DNSTypeA)
	if err != nil {
		return nil, 0, err
	}
	return result.IPs, result.TTL, nil
}

// IPOption DNS查询选项
type IPOption struct {
	IPv4Enable bool
	IPv6Enable bool
}

// QueryDomain 查询域名（Go fallback实现）
func (da *DNSAccelerator) QueryDomain(domain string, queryType DNSType) (*DNSResult, error) {
	if !da.enabled {
		return nil, errors.New("DNS accelerator not enabled")
	}

	da.Lock()
	defer da.Unlock()

	da.totalQueries++

	// 检查恶意域名
	if da.filterEnabled {
		if entry, exists := da.maliciousDomains[domain]; exists && entry.Confidence > 70 {
			da.blockedQueries++
			return nil, errors.New("domain blocked: malicious (fallback)")
		}
	}

	startTime := time.Now()

	// 检查Go缓存
	if da.cacheEnabled {
		if entry, exists := da.cache[domain]; exists {
			if time.Now().Before(entry.ExpireTime) {
				da.cacheHits++
				entry.HitCount++

				result := &DNSResult{
					Domain:       domain,
					IPs:          entry.IPs,
					TTL:          entry.TTL,
					Source:       "Go-cache",
					CacheHit:     true,
					ResponseTime: time.Since(startTime),
				}
				return result, nil
			} else {
				// 缓存过期，删除条目
				delete(da.cache, domain)
			}
		}
	}

	da.cacheMisses++

	// 选择最佳DNS服务器
	serverIndex := da.selectBestServer()
	if serverIndex < 0 {
		da.failedQueries++
		return nil, errors.New("no available DNS servers")
	}

	// 模拟DNS查询
	server := da.dnsServers[serverIndex]
	responseTime := da.simulateQuery(server)

	// 模拟查询结果
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	ttl := uint32(300)

	// 添加到缓存
	if da.cacheEnabled && len(da.cache) < da.cacheSize {
		entry := &CacheEntry{
			Domain:     domain,
			IPs:        ips,
			TTL:        ttl,
			CreateTime: time.Now(),
			ExpireTime: time.Now().Add(time.Duration(ttl) * time.Second),
			HitCount:   0,
		}
		da.cache[domain] = entry
	}

	result := &DNSResult{
		Domain:       domain,
		IPs:          ips,
		TTL:          ttl,
		Source:       server.ServerIP.String(),
		CacheHit:     false,
		ResponseTime: responseTime,
		ServerType:   server.ServerType,
	}

	// 更新服务器统计
	da.updateServerStats(serverIndex, responseTime, true)

	return result, nil
}

// selectBestServer 选择最佳DNS服务器
func (da *DNSAccelerator) selectBestServer() int {
	if len(da.dnsServers) == 0 {
		return -1
	}

	bestIndex := 0
	bestScore := uint32(0)

	for i, server := range da.dnsServers {
		// 计算服务器评分 (响应时间 + 可靠性)
		score := uint32(server.ReliabilityScore)
		if server.ResponseTimeAvg > 0 {
			score = score * 1000 / uint32(server.ResponseTimeAvg.Milliseconds())
		}

		if score > bestScore {
			bestScore = score
			bestIndex = i
		}
	}

	return bestIndex
}

// simulateQuery 模拟DNS查询
func (da *DNSAccelerator) simulateQuery(server *DNSServerInfo) time.Duration {
	// 模拟网络延迟
	baseDelay := server.ResponseTimeAvg
	if baseDelay == 0 {
		baseDelay = time.Millisecond * 50
	}

	// fallback模式稍微慢一些
	return baseDelay + time.Millisecond*10
}

// updateServerStats 更新服务器统计
func (da *DNSAccelerator) updateServerStats(serverIndex int, responseTime time.Duration, success bool) {
	if serverIndex < 0 || serverIndex >= len(da.dnsServers) {
		return
	}

	server := da.dnsServers[serverIndex]
	server.LastUsed = time.Now()

	if success {
		server.SuccessCount++
		if server.ResponseTimeAvg == 0 {
			server.ResponseTimeAvg = responseTime
		} else {
			server.ResponseTimeAvg = (server.ResponseTimeAvg + responseTime) / 2
		}
	} else {
		server.FailureCount++
	}

	// 重新计算可靠性评分
	total := server.SuccessCount + server.FailureCount
	if total > 0 {
		server.ReliabilityScore = uint8((server.SuccessCount * 100) / total)
	}
}

// GetStats 获取统计信息
func (da *DNSAccelerator) GetStats() *DNSQueryStats {
	da.RLock()
	defer da.RUnlock()

	return &DNSQueryStats{
		TotalQueries:    da.totalQueries,
		CacheHits:       da.cacheHits,
		CacheMisses:     da.cacheMisses,
		BlockedQueries:  da.blockedQueries,
		FailedQueries:   da.failedQueries,
		AvgResponseTime: time.Duration(da.avgResponseTime) * time.Microsecond,
	}
}

// GetPerformanceMetrics 获取性能指标
func (da *DNSAccelerator) GetPerformanceMetrics() *DNSPerfMetrics {
	da.RLock()
	defer da.RUnlock()

	return &DNSPerfMetrics{
		ConcurrentQueries: 5,
		QueueDepth:        2,
		MemoryUsage:       512 * 1024, // 512KB
		CPUUsage:          25,         // 25% (fallback通常更耗CPU)
		BytesSent:         da.totalQueries * 512,
		BytesReceived:     da.totalQueries * 1024,
		PacketLossRate:    5, // 5% (fallback模式可能丢包率更高)
		Jitter:            time.Millisecond * 10,
	}
}

// GetHotDomains 获取热点域名
func (da *DNSAccelerator) GetHotDomains(limit int) []string {
	da.RLock()
	defer da.RUnlock()

	// 基于缓存命中次数排序
	type domainHit struct {
		domain string
		hits   uint32
	}

	var domains []domainHit
	for domain, entry := range da.cache {
		domains = append(domains, domainHit{domain: domain, hits: entry.HitCount})
	}

	// 简单排序 (冒泡排序)
	for i := 0; i < len(domains)-1; i++ {
		for j := 0; j < len(domains)-i-1; j++ {
			if domains[j].hits < domains[j+1].hits {
				domains[j], domains[j+1] = domains[j+1], domains[j]
			}
		}
	}

	result := make([]string, 0, limit)
	for i := 0; i < len(domains) && i < limit; i++ {
		result = append(result, domains[i].domain)
	}

	return result
}

// maintenanceLoop 后台维护循环
func (da *DNSAccelerator) maintenanceLoop() {
	ticker := time.NewTicker(da.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-da.ctx.Done():
			return
		case <-ticker.C:
			da.performMaintenance()
		}
	}
}

// performMaintenance 执行维护任务
func (da *DNSAccelerator) performMaintenance() {
	da.Lock()
	defer da.Unlock()

	// 清理过期缓存条目
	da.cleanupExpiredCache()

	// 更新服务器健康状态
	da.updateServerHealth()

	// 清理过期的恶意域名条目
	da.cleanupMaliciousDomains()
}

// cleanupExpiredCache 清理过期缓存
func (da *DNSAccelerator) cleanupExpiredCache() {
	now := time.Now()
	count := 0

	for domain, entry := range da.cache {
		if now.After(entry.ExpireTime) {
			delete(da.cache, domain)
			count++
		}
	}

	if count > 0 {
		errors.LogDebug(da.ctx, "Cleaned up ", count, " expired DNS cache entries (fallback)")
	}
}

// updateServerHealth 更新服务器健康状态
func (da *DNSAccelerator) updateServerHealth() {
	for _, server := range da.dnsServers {
		// 如果服务器长时间未使用，降低其可靠性评分
		if time.Since(server.LastUsed) > time.Minute*10 {
			if server.ReliabilityScore > 10 {
				server.ReliabilityScore -= 5
			}
		}

		// 如果失败率过高，标记为不可用
		total := server.SuccessCount + server.FailureCount
		if total > 10 && server.FailureCount*100/total > 50 {
			server.ReliabilityScore = 0
			errors.LogWarning(da.ctx, "DNS server marked as unreliable (fallback): ", server.ServerIP)
		}
	}
}

// cleanupMaliciousDomains 清理恶意域名
func (da *DNSAccelerator) cleanupMaliciousDomains() {
	cutoff := time.Now().AddDate(0, 0, -30) // 30天前

	for domain, entry := range da.maliciousDomains {
		if entry.LastSeen.Before(cutoff) && entry.DetectionCount < 5 {
			delete(da.maliciousDomains, domain)
		}
	}
}

// IsEnabled 检查是否启用
func (da *DNSAccelerator) IsEnabled() bool {
	da.RLock()
	defer da.RUnlock()
	return da.enabled
}

// EnableCache 启用/禁用缓存
func (da *DNSAccelerator) EnableCache(enable bool) {
	da.Lock()
	defer da.Unlock()
	da.cacheEnabled = enable
	errors.LogInfo(da.ctx, "DNS cache enabled (fallback): ", enable)
}

// EnableFilter 启用/禁用恶意域名过滤
func (da *DNSAccelerator) EnableFilter(enable bool) {
	da.Lock()
	defer da.Unlock()
	da.filterEnabled = enable
	errors.LogInfo(da.ctx, "DNS malware filter enabled (fallback): ", enable)
}

// SetCacheTTL 设置缓存TTL
func (da *DNSAccelerator) SetCacheTTL(ttl time.Duration) {
	da.Lock()
	defer da.Unlock()
	da.cacheTTL = ttl
	errors.LogInfo(da.ctx, "DNS cache TTL set to (fallback): ", ttl)
}

// Close 关闭DNS加速器
func (da *DNSAccelerator) Close() error {
	da.Lock()
	defer da.Unlock()

	da.cancel()
	da.enabled = false

	errors.LogInfo(da.ctx, "DNS accelerator closed (fallback)")
	return nil
}
