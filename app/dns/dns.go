// Package dns is an implementation of core.DNS feature.
package dns

import (
	"context"
	go_errors "errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	ebpf "github.com/xtls/xray-core/app/dns/ebpf"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/features/dns"
	"golang.org/x/sync/singleflight"
)

// DNS is a DNS rely server.
type DNS struct {
	sync.Mutex
	disableFallback        bool
	disableFallbackIfMatch bool
	ipOption               *dns.IPOption
	hosts                  *StaticHosts
	clients                []*Client
	ctx                    context.Context
	domainMatcher          strmatcher.IndexMatcher
	matcherInfos           []*DomainMatcherInfo
	checkSystem            bool

	// singleflight to deduplicate concurrent lookups for same key
	sf singleflight.Group

	// lightweight negative cache: domainKey -> expireAt
	negMu    sync.RWMutex
	negCache map[string]time.Time

	// prefetch scheduling to avoid duplicate refresh tasks
	pfMu        sync.Mutex
	pfScheduled map[string]struct{}
}

// -------- 双层缓存融合：全局 eBPF 加速器与 eBPF 缓存（懒加载） --------

// ebpfDNSCache 提供最小接口以避免在非 Linux 平台直接依赖具体实现
type ebpfDNSCache interface {
	AddRecord(domain string, ips []net.IP, ttl uint32, rcode uint16) error
	AddRecordV6(domain string, ips []net.IP, ttl uint32, rcode uint16) error
	IsEnabled() bool
}

var (
	ebpfInitOnce    sync.Once
	ebpfAccelGlobal *ebpf.DNSAccelerator
	ebpfCacheGlobal ebpfDNSCache
)

// getNegativeCacheTTL returns duration for negative cache from env XRAY_DNS_NEG_TTL seconds (default 8s, max 60s).
func getNegativeCacheTTL() time.Duration {
	// 仅受 XRAY_EBPF 控制：开启则使用默认 8s，关闭则禁用负缓存
	if os.Getenv("XRAY_EBPF") != "1" {
		return 0
	}
	return 8 * time.Second
}

// getNegativeCacheMaxSize returns max entries allowed in negative cache.
// Controlled by XRAY_DNS_NEG_MAX (default 8192, min 256, max 262144).
func getNegativeCacheMaxSize() int {
	// 仅受 XRAY_EBPF 控制：开启则使用默认容量 8192，关闭则容量为 0（禁用）
	if os.Getenv("XRAY_EBPF") != "1" {
		return 0
	}
	return 8192
}

// pruneNegativeCache reduces negative cache size by removing expired entries and
// then trimming oldest-by-expire entries if still too large.
func (s *DNS) pruneNegativeCacheLocked(maxSize int) {
	now := time.Now()
	// Remove expired first
	for k, exp := range s.negCache {
		if now.After(exp) {
			delete(s.negCache, k)
		}
	}
	// Trim if still too large
	if len(s.negCache) <= maxSize {
		return
	}
	type kv struct {
		k   string
		exp time.Time
	}
	list := make([]kv, 0, len(s.negCache))
	for k, exp := range s.negCache {
		list = append(list, kv{k: k, exp: exp})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].exp.Before(list[j].exp) })
	// keep newest ~75%, drop oldest 25%
	target := maxSize * 3 / 4
	if target < 256 {
		target = 256
	}
	for i := 0; i < len(list)-target; i++ {
		delete(s.negCache, list[i].k)
	}
}

func ensureEBPFDNS() {
	ebpfInitOnce.Do(func() {
		if accel, err := ebpf.NewDNSAccelerator(); err == nil && accel != nil && accel.IsEnabled() {
			ebpfAccelGlobal = accel
		}
		if cache, ok := newEbpfDNSCache(); ok {
			ebpfCacheGlobal = cache
		}
	})
}

// shouldEnableKernelFastpath returns true if XRAY_EBPF is set
func shouldEnableKernelFastpath() bool {
	return strings.TrimSpace(os.Getenv("XRAY_EBPF")) != ""
}

// 下列函数在 Linux 由桥接文件提供实现；非 Linux 为 no-op
//   - newEbpfDNSCache() (ebpfDNSCache, bool)
//   - dnsLookupSitePolicyMark() uint32
//   - ipFastpathEnable(enable bool)
//   - setIPv4Mark(ip net.IP, mark uint32, ttlSeconds uint32)
//   - setIPv6Mark(ip net.IP, mark uint32, ttlSeconds uint32)

// DomainMatcherInfo contains information attached to index returned by Server.domainMatcher
type DomainMatcherInfo struct {
	clientIdx     uint16
	domainRuleIdx uint16
}

// New creates a new DNS server with given configuration.
func New(ctx context.Context, config *Config) (*DNS, error) {
	var clientIP net.IP
	switch len(config.ClientIp) {
	case 0, net.IPv4len, net.IPv6len:
		clientIP = net.IP(config.ClientIp)
	default:
		return nil, errors.New("unexpected client IP length ", len(config.ClientIp))
	}

	var ipOption dns.IPOption
	checkSystem := false
	switch config.QueryStrategy {
	case QueryStrategy_USE_IP:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
	case QueryStrategy_USE_SYS:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: true,
			FakeEnable: false,
		}
		checkSystem = true
	case QueryStrategy_USE_IP4:
		ipOption = dns.IPOption{
			IPv4Enable: true,
			IPv6Enable: false,
			FakeEnable: false,
		}
	case QueryStrategy_USE_IP6:
		ipOption = dns.IPOption{
			IPv4Enable: false,
			IPv6Enable: true,
			FakeEnable: false,
		}
	default:
		return nil, errors.New("unexpected query strategy ", config.QueryStrategy)
	}

	hosts, err := NewStaticHosts(config.StaticHosts)
	if err != nil {
		return nil, errors.New("failed to create hosts").Base(err)
	}

	var clients []*Client
	domainRuleCount := 0

	var defaultTag = config.Tag
	if len(config.Tag) == 0 {
		defaultTag = generateRandomTag()
	}

	for _, ns := range config.NameServer {
		domainRuleCount += len(ns.PrioritizedDomain)
	}

	// MatcherInfos is ensured to cover the maximum index domainMatcher could return, where matcher's index starts from 1
	matcherInfos := make([]*DomainMatcherInfo, domainRuleCount+1)
	domainMatcher := &strmatcher.MatcherGroup{}

	for _, ns := range config.NameServer {
		clientIdx := len(clients)
		updateDomain := func(domainRule strmatcher.Matcher, originalRuleIdx int, matcherInfos []*DomainMatcherInfo) error {
			midx := domainMatcher.Add(domainRule)
			matcherInfos[midx] = &DomainMatcherInfo{
				clientIdx:     uint16(clientIdx),
				domainRuleIdx: uint16(originalRuleIdx),
			}
			return nil
		}

		myClientIP := clientIP
		switch len(ns.ClientIp) {
		case net.IPv4len, net.IPv6len:
			myClientIP = net.IP(ns.ClientIp)
		}

		disableCache := config.DisableCache || ns.DisableCache

		var tag = defaultTag
		if len(ns.Tag) > 0 {
			tag = ns.Tag
		}
		clientIPOption := ResolveIpOptionOverride(ns.QueryStrategy, ipOption)
		if !clientIPOption.IPv4Enable && !clientIPOption.IPv6Enable {
			return nil, errors.New("no QueryStrategy available for ", ns.Address)
		}

		client, err := NewClient(ctx, ns, myClientIP, disableCache, tag, clientIPOption, &matcherInfos, updateDomain)
		if err != nil {
			return nil, errors.New("failed to create client").Base(err)
		}
		clients = append(clients, client)
	}

	// If there is no DNS client in config, add a `localhost` DNS client
	if len(clients) == 0 {
		clients = append(clients, NewLocalDNSClient(ipOption))
	}

	return &DNS{
		hosts:                  hosts,
		ipOption:               &ipOption,
		clients:                clients,
		ctx:                    ctx,
		domainMatcher:          domainMatcher,
		matcherInfos:           matcherInfos,
		disableFallback:        config.DisableFallback,
		disableFallbackIfMatch: config.DisableFallbackIfMatch,
		checkSystem:            checkSystem,
		negCache:               make(map[string]time.Time),
	}, nil
}

// Type implements common.HasType.
func (*DNS) Type() interface{} {
	return dns.ClientType()
}

// Start implements common.Runnable.
func (s *DNS) Start() error {
	// 启动时尝试初始化 eBPF 加速与缓存，并执行可选预取
	ensureEBPFDNS()
	// 可选预取：如需关闭监控/指标，这里保留功能但静默执行
	prefetchList := strings.TrimSpace(os.Getenv("XRAY_DNS_PREFETCH"))
	if prefetchList != "" {
		for _, d := range strings.Split(prefetchList, ",") {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			go func(domain string) { _, _, _ = s.LookupIP(domain, *s.ipOption) }(d)
		}
	}
	return nil
}

// Close implements common.Closable.
func (s *DNS) Close() error {
	return nil
}

// IsOwnLink implements proxy.dns.ownLinkVerifier
func (s *DNS) IsOwnLink(ctx context.Context) bool {
	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		return false
	}
	for _, client := range s.clients {
		if client.tag == inbound.Tag {
			return true
		}
	}
	return false
}

// LookupIP implements dns.Client.
func (s *DNS) LookupIP(domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	// Normalize the FQDN form query
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return nil, 0, errors.New("empty domain name")
	}

	// Negative cache: quick drop of recent NODATA/NXDOMAIN for small TTL
	if !s.checkSystem { // keep behavior conservative under system mode
		negKey := domain + ":" + keyOfOption(option)
		s.negMu.RLock()
		if exp, ok := s.negCache[negKey]; ok && time.Now().Before(exp) {
			s.negMu.RUnlock()
			return nil, 0, dns.ErrEmptyResponse
		}
		s.negMu.RUnlock()
	}

	// 🚀 DNS eBPF加速查询（仅在启用时快速路径）
	ensureEBPFDNS()
	if ebpfAccelGlobal != nil && ebpfAccelGlobal.IsEnabled() {
		if option.IPv4Enable {
			if result, err := ebpfAccelGlobal.QueryDomain(domain, ebpf.DNSTypeA); err == nil && result.CacheHit {
				return result.IPs, result.TTL, nil
			}
		}
		if option.IPv6Enable {
			if result, err := ebpfAccelGlobal.QueryDomain(domain, ebpf.DNSTypeAAAA); err == nil && result.CacheHit {
				return result.IPs, result.TTL, nil
			}
		}
	}

	if s.checkSystem {
		supportIPv4, supportIPv6 := checkSystemNetwork()
		option.IPv4Enable = option.IPv4Enable && supportIPv4
		option.IPv6Enable = option.IPv6Enable && supportIPv6
	} else {
		option.IPv4Enable = option.IPv4Enable && s.ipOption.IPv4Enable
		option.IPv6Enable = option.IPv6Enable && s.ipOption.IPv6Enable
	}

	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, 0, dns.ErrEmptyResponse
	}

	// Static host lookup
	switch addrs, err := s.hosts.Lookup(domain, option); {
	case err != nil:
		if go_errors.Is(err, dns.ErrEmptyResponse) {
			return nil, 0, dns.ErrEmptyResponse
		}
		return nil, 0, errors.New("returning nil for domain ", domain).Base(err)
	case addrs == nil: // Domain not recorded in static host
		break
	case len(addrs) == 0: // Domain recorded, but no valid IP returned (e.g. IPv4 address with only IPv6 enabled)
		return nil, 0, dns.ErrEmptyResponse
	case len(addrs) == 1 && addrs[0].Family().IsDomain(): // Domain replacement
		errors.LogInfo(s.ctx, "domain replaced: ", domain, " -> ", addrs[0].Domain())
		domain = addrs[0].Domain()
	default: // Successfully found ip records in static host
		errors.LogInfo(s.ctx, "returning ", len(addrs), " IP(s) for domain ", domain, " -> ", addrs)
		ips, err := toNetIP(addrs)
		if err != nil {
			return nil, 0, err
		}
		// 写回 eBPF 缓存（若可用），分别处理 A/AAAA；并按策略回写 fastpath mark
		if ebpfCacheGlobal != nil && len(ips) > 0 {
			var v4s, v6s []net.IP
			for _, ip := range ips {
				if ip.To4() != nil {
					v4s = append(v4s, ip)
				} else if ip.To16() != nil {
					v6s = append(v6s, ip)
				}
			}
			if len(v4s) > 0 {
				_ = ebpfCacheGlobal.AddRecord(domain, v4s, 10, 0)
				if shouldEnableKernelFastpath() {
					ipFastpathEnable(true)
					if mark := dnsLookupSitePolicyMark(); mark != 0 {
						for _, ip4 := range v4s {
							setIPv4Mark(ip4, mark, 10)
						}
					}
				}
			}
			if len(v6s) > 0 {
				_ = ebpfCacheGlobal.AddRecordV6(domain, v6s, 10, 0)
				if shouldEnableKernelFastpath() {
					ipFastpathEnable(true)
					if mark := dnsLookupSitePolicyMark(); mark != 0 {
						for _, ip6 := range v6s {
							setIPv6Mark(ip6, mark, 10)
						}
					}
				}
			}
		}
		return ips, 10, nil // Hosts ttl is 10
	}

	// Name servers lookup with singleflight (deduplicate concurrent same-domain lookups)
	v, errSF, _ := s.sf.Do("dns:"+domain+":"+keyOfOption(option), func() (interface{}, error) {
		var errs []error
		for _, client := range s.sortClients(domain) {
			if !option.FakeEnable && strings.EqualFold(client.Name(), "FakeDNS") {
				errors.LogDebug(s.ctx, "skip DNS resolution for domain ", domain, " at server ", client.Name())
				continue
			}

			ips, ttl, err := client.QueryIP(s.ctx, domain, option)

			if len(ips) > 0 {
				if ttl == 0 {
					ttl = 1
				}
				// 🚀 将结果写回 eBPF 缓存（仅 A/AAAA 正常响应）
				if ebpfCacheGlobal != nil {
					// 限制 TTL 范围，避免过大
					if ttl > 1800 {
						ttl = 1800
					}
					if ttl == 0 {
						ttl = 1
					}
					if len(ips) > 0 {
						var v4s, v6s []net.IP
						for _, ip := range ips {
							if ip.To4() != nil {
								v4s = append(v4s, ip)
							} else if ip.To16() != nil {
								v6s = append(v6s, ip)
							}
						}
						if len(v4s) > 0 {
							_ = ebpfCacheGlobal.AddRecord(domain, v4s, ttl, 0)
							// 同步写入 IP fastpath（仅在启用 eBPF 时，且有可用策略 mark 时），不修改服务端配置
							if shouldEnableKernelFastpath() {
								ipFastpathEnable(true)
								if mark := dnsLookupSitePolicyMark(); mark != 0 {
									for _, ip4 := range v4s {
										setIPv4Mark(ip4, mark, ttl)
									}
								}
							}
						}
						if len(v6s) > 0 {
							_ = ebpfCacheGlobal.AddRecordV6(domain, v6s, ttl, 0)
							if shouldEnableKernelFastpath() {
								ipFastpathEnable(true)
								if mark := dnsLookupSitePolicyMark(); mark != 0 {
									for _, ip6 := range v6s {
										setIPv6Mark(ip6, mark, ttl)
									}
								}
							}
						}
					}
				}
				return struct {
					ips []net.IP
					ttl uint32
				}{ips, ttl}, nil
			}

			errors.LogInfoInner(s.ctx, err, "failed to lookup ip for domain ", domain, " at server ", client.Name())
			if err == nil {
				err = dns.ErrEmptyResponse
			}
			errs = append(errs, err)

			if client.IsFinalQuery() {
				break
			}
		}

		if len(errs) > 0 {
			allErrs := errors.Combine(errs...)
			err0 := errs[0]
			if errors.AllEqual(err0, allErrs) {
				if go_errors.Is(err0, dns.ErrEmptyResponse) {
					return struct {
						ips []net.IP
						ttl uint32
					}{nil, 0}, dns.ErrEmptyResponse
				}
				return struct {
					ips []net.IP
					ttl uint32
				}{nil, 0}, errors.New("returning nil for domain ", domain).Base(err0)
			}
			return struct {
				ips []net.IP
				ttl uint32
			}{nil, 0}, errors.New("returning nil for domain ", domain).Base(allErrs)
		}
		return struct {
			ips []net.IP
			ttl uint32
		}{nil, 0}, dns.ErrEmptyResponse
	})

	if errSF != nil {
		if errSF == dns.ErrEmptyResponse {
			// 更新负缓存：短 TTL
			if !s.checkSystem {
				negKey := domain + ":" + keyOfOption(option)
				ttl := getNegativeCacheTTL()
				if ttl > 0 {
					s.negMu.Lock()
					if s.negCache == nil {
						s.negCache = make(map[string]time.Time)
					}
					// 容量管控，防止内存增长
					maxSize := getNegativeCacheMaxSize()
					if len(s.negCache) >= maxSize {
						s.pruneNegativeCacheLocked(maxSize)
					}
					s.negCache[negKey] = time.Now().Add(ttl)
					s.negMu.Unlock()
				}
			}
		}
		return nil, 0, errSF
	}
	res := v.(struct {
		ips []net.IP
		ttl uint32
	})
	// schedule prefetch if TTL is short
	s.maybeSchedulePrefetch(domain, option, res.ttl)
	return res.ips, res.ttl, nil
}

// maybeSchedulePrefetch schedules a background refresh when TTL is short.
// XRAY_DNS_PREFETCH_TTL controls threshold seconds (default 30, max 300). XRAY_DNS_PREFETCH_JITTER adds random jitter up to N seconds (default 5).
func (s *DNS) maybeSchedulePrefetch(domain string, option dns.IPOption, ttl uint32) {
	if ttl == 0 {
		return
	}
	// 仅受 XRAY_EBPF 控制：开启时，默认阈值 30，否则不预取
	thr := 0
	if os.Getenv("XRAY_EBPF") == "1" {
		thr = 30
	}
	if thr == 0 || int(ttl) > thr {
		return
	}
	key := domain + ":" + keyOfOption(option)
	s.pfMu.Lock()
	if s.pfScheduled == nil {
		s.pfScheduled = make(map[string]struct{})
	}
	if _, ok := s.pfScheduled[key]; ok {
		s.pfMu.Unlock()
		return
	}
	s.pfScheduled[key] = struct{}{}
	s.pfMu.Unlock()

	// jitter seconds
	// 仅受 XRAY_EBPF 控制：开启时，默认抖动 5s
	jitter := 0
	if os.Getenv("XRAY_EBPF") == "1" {
		jitter = 5
	}
	go func() {
		// small delay to reduce contention, but keep within TTL window
		if jitter > 0 {
			time.Sleep(time.Duration(jitter) * time.Second)
		}
		// Use background context to avoid request cancellation
		// Singleflight in LookupIP will deduplicate concurrent refreshes
		_, _, _ = s.LookupIP(domain, option)
		s.pfMu.Lock()
		delete(s.pfScheduled, key)
		s.pfMu.Unlock()
	}()
}

// keyOfOption 生成 singleflight key 的 option 部分
func keyOfOption(o dns.IPOption) string {
	b := strings.Builder{}
	if o.IPv4Enable {
		b.WriteByte('4')
	} else {
		b.WriteByte('-')
	}
	if o.IPv6Enable {
		b.WriteByte('6')
	} else {
		b.WriteByte('-')
	}
	if o.FakeEnable {
		b.WriteByte('F')
	} else {
		b.WriteByte('-')
	}
	return b.String()
}

func (s *DNS) sortClients(domain string) []*Client {
	clients := make([]*Client, 0, len(s.clients))
	clientUsed := make([]bool, len(s.clients))
	clientNames := make([]string, 0, len(s.clients))
	domainRules := []string{}

	// Priority domain matching
	hasMatch := false
	MatchSlice := s.domainMatcher.Match(domain)
	sort.Slice(MatchSlice, func(i, j int) bool {
		return MatchSlice[i] < MatchSlice[j]
	})
	for _, match := range MatchSlice {
		info := s.matcherInfos[match]
		client := s.clients[info.clientIdx]
		domainRule := client.domains[info.domainRuleIdx]
		domainRules = append(domainRules, fmt.Sprintf("%s(DNS idx:%d)", domainRule, info.clientIdx))
		if clientUsed[info.clientIdx] {
			continue
		}
		clientUsed[info.clientIdx] = true
		clients = append(clients, client)
		clientNames = append(clientNames, client.Name())
		hasMatch = true
	}

	if !(s.disableFallback || s.disableFallbackIfMatch && hasMatch) {
		// Default round-robin query
		for idx, client := range s.clients {
			if clientUsed[idx] || client.skipFallback {
				continue
			}
			clientUsed[idx] = true
			clients = append(clients, client)
			clientNames = append(clientNames, client.Name())
		}
	}

	if len(domainRules) > 0 {
		errors.LogDebug(s.ctx, "domain ", domain, " matches following rules: ", domainRules)
	}
	if len(clientNames) > 0 {
		errors.LogDebug(s.ctx, "domain ", domain, " will use DNS in order: ", clientNames)
	}

	if len(clients) == 0 {
		clients = append(clients, s.clients[0])
		clientNames = append(clientNames, s.clients[0].Name())
		errors.LogDebug(s.ctx, "domain ", domain, " will use the first DNS: ", clientNames)
	}

	return clients
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

func checkSystemNetwork() (supportIPv4 bool, supportIPv6 bool) {
	conn4, err4 := net.Dial("udp4", "8.8.8.8:53")
	if err4 != nil {
		supportIPv4 = false
	} else {
		supportIPv4 = true
		conn4.Close()
	}

	conn6, err6 := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err6 != nil {
		supportIPv6 = false
	} else {
		supportIPv6 = true
		conn6.Close()
	}
	return
}
