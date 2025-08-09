//go:build linux && amd64

package ebpf

import (
	"context"
	"encoding/binary"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/xtls/xray-core/common/errors"
)

// Kernel-side learning cache manager for GeoSite
// Relies on pinned maps created by loading app/router/ebpf/geosite_matcher_dynamic.o

type geoSiteLearningCache struct {
	enabled bool
	cache   *ebpf.Map // geosite_dynamic_cache
	hotlist *ebpf.Map // hot_domain_list
	enable  *ebpf.Map // geosite_enable
}

var globalGeoSiteLearning = &geoSiteLearningCache{}

type geoIPLearningCache struct {
	enabled   bool
	cache     *ebpf.Map // geoip_dynamic_cache
	hotlist   *ebpf.Map // hot_ip_list
	routeHint *ebpf.Map // route_geoip_v4_hint
	policy    *ebpf.Map // geoip_policy (country_code -> policy_id)
}

var globalGeoIPLearning = &geoIPLearningCache{}

func getGeoSiteLearning() *geoSiteLearningCache {
	if globalGeoSiteLearning.cache != nil || globalGeoSiteLearning.hotlist != nil {
		return globalGeoSiteLearning
	}
	cache, err1 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geosite_dynamic_cache", nil)
	hot, err2 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/hot_domain_list", nil)
	en, err3 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geosite_enable", nil)
	if err1 != nil || err2 != nil {
		errors.LogDebug(context.Background(), "GeoSite learning cache maps not available: ", err1, ", ", err2, ", en:", err3)
		return globalGeoSiteLearning
	}
	globalGeoSiteLearning.cache = cache
	globalGeoSiteLearning.hotlist = hot
	if err3 == nil {
		globalGeoSiteLearning.enable = en
	}
	globalGeoSiteLearning.enabled = true
	return globalGeoSiteLearning
}

func getGeoIPLearning() *geoIPLearningCache {
	if globalGeoIPLearning.cache != nil || globalGeoIPLearning.hotlist != nil || globalGeoIPLearning.routeHint != nil {
		return globalGeoIPLearning
	}
	cache, err1 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geoip_dynamic_cache", nil)
	hot, err2 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/hot_ip_list", nil)
	hint, err3 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/route_geoip_v4_hint", nil)
	policy, err4 := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geoip_policy", nil)
	if err1 != nil || err2 != nil || err3 != nil {
		errors.LogDebug(context.Background(), "GeoIP learning cache maps not available: ", err1, ", ", err2, ", ", err3, ", policy:", err4)
		return globalGeoIPLearning
	}
	globalGeoIPLearning.cache = cache
	globalGeoIPLearning.hotlist = hot
	globalGeoIPLearning.routeHint = hint
	if err4 == nil {
		globalGeoIPLearning.policy = policy
	}
	globalGeoIPLearning.enabled = true
	return globalGeoIPLearning
}

// hashDomain64 computes 64-bit hash of domain; keep name distinct to avoid clashes.
// Must match the hashing used by geosite_matcher_dynamic.c integrations.
func hashDomain64(domain string) uint64 {
	// duplicate logic kept minimal: delegate to package-level hashDomain if available
	// but to avoid cyclic import or mismatch, use a simple FNV-1a inline implementation
	var hash uint64 = 1469598103934665603 // FNV-1a offset
	const prime uint64 = 1099511628211
	for i := 0; i < len(domain); i++ {
		hash ^= uint64(domain[i])
		hash *= prime
	}
	return hash
}

// PromoteDomain writes a hot flag and cache entry into kernel maps.
// siteCode must be > 0 to represent a positive match.
func PromoteDomain(domain string, siteCode uint8, ttlSeconds uint32) {
	lc := getGeoSiteLearning()
	if !lc.enabled || siteCode == 0 {
		return
	}
	key := hashDomain64(domain)

	// Mark as hot domain
	one := uint8(1)
	if err := lc.hotlist.Update(&key, &one, ebpf.UpdateAny); err != nil {
		errors.LogDebug(context.Background(), "hot_domain_list update failed: ", err)
	}

	// Build geosite_cache_entry (C layout, 32 bytes total):
	// struct geosite_cache_entry {
	//   __u64 domain_hash;   // 0..7
	//   __u8  site_code;     // 8
	//   // 3 bytes padding   // 9..11
	//   __u32 access_count;  // 12..15
	//   __u64 last_access;   // 16..23
	//   __u32 ttl;           // 24..27
	//   // 4 bytes padding   // 28..31
	// };
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint64(buf[0:8], key)
	buf[8] = byte(siteCode)
	// padding 9..11 zeros
	binary.LittleEndian.PutUint32(buf[12:16], 1)
	nowSec := uint64(time.Now().Unix())
	binary.LittleEndian.PutUint64(buf[16:24], nowSec)
	binary.LittleEndian.PutUint32(buf[24:28], ttlSeconds)
	// padding 28..31 zeros

	if err := lc.cache.Update(&key, buf, ebpf.UpdateAny); err != nil {
		errors.LogDebug(context.Background(), "geosite_dynamic_cache update failed: ", err)
	}

	// Also auto-enable kernel geosite mark apply if switch map exists
	if lc.enable != nil {
		var k uint32 = 0
		var on uint32 = 1
		if err := lc.enable.Update(&k, &on, ebpf.UpdateAny); err != nil {
			errors.LogDebug(context.Background(), "geosite_enable update failed: ", err)
		}
	}

	// 同步将域名解析结果对应的已知 IP（若存在）写入 IP FastPath hint：
	// 轻量策略：仅当 site_code=1 且存在 geosite_policy[1] mark 时执行。
	if siteCode == 1 {
		if mark, ok := GetGeoSitePolicyMark(1); ok && mark != 0 {
			// 无法直接从此处取到域名 IP 列表；留给 DNS 写回路径完成（已实现）。
			// 这里仅确保 fastpath 开关开启。
			EnableIPFastpath(true)
		}
	}
}

// PromoteIPv4 writes IPv4 country-code to dynamic cache and to route hint map for fast path.
// countryCode: ASCII code mapped to uint8, e.g. 156 -> CN (caller should map), here use 1..255 custom.
func PromoteIPv4(ip uint32, countryCode uint8, ttlSeconds uint32) {
	lc := getGeoIPLearning()
	if !lc.enabled || countryCode == 0 || ip == 0 {
		return
	}
	// mark hot ip
	one := uint8(1)
	if err := lc.hotlist.Update(&ip, &one, ebpf.UpdateAny); err != nil {
		errors.LogDebug(context.Background(), "hot_ip_list update failed: ", err)
	}
	// compose geoip_cache_entry (C layout, 24 bytes):
	// struct geoip_cache_entry { __u32 ip; __u8 cc; __u32 access; __u64 last; __u32 ttl; } with padding
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf[0:4], ip)
	buf[4] = byte(countryCode)
	// 3 bytes padding 5..7
	binary.LittleEndian.PutUint32(buf[8:12], 1)
	nowSec := uint64(time.Now().Unix())
	binary.LittleEndian.PutUint64(buf[12:20], nowSec)
	binary.LittleEndian.PutUint32(buf[20:24], ttlSeconds)
	if err := lc.cache.Update(&ip, buf, ebpf.UpdateAny); err != nil {
		errors.LogDebug(context.Background(), "geoip_dynamic_cache update failed: ", err)
	}
}

// CountryCode8FromString maps 2-letter ISO code to a compact uint8 id.
func CountryCode8FromString(code string) uint8 {
	if len(code) == 0 {
		return 0
	}
	c := strings.ToUpper(code)
	switch c {
	case "CN":
		return 1
	case "US":
		return 2
	case "HK":
		return 3
	case "TW":
		return 4
	case "JP":
		return 5
	case "SG":
		return 6
	case "KR":
		return 7
	case "RU":
		return 8
	case "DE":
		return 9
	case "GB":
		return 10
	case "FR":
		return 11
	case "NL":
		return 12
	case "CA":
		return 13
	case "AU":
		return 14
	case "IN":
		return 15
	case "BR":
		return 16
	case "TR":
		return 17
	case "VN":
		return 18
	case "ID":
		return 19
	case "MY":
		return 20
	case "PH":
		return 21
	case "TH":
		return 22
	case "IR":
		return 23
	case "AE":
		return 24
	case "ES":
		return 25
	case "IT":
		return 26
	case "SE":
		return 27
	case "NO":
		return 28
	case "FI":
		return 29
	case "PL":
		return 30
	default:
		// fallback: compact hash in 1..254 (avoid 0)
		var h uint32
		for i := 0; i < len(c); i++ {
			h = h*131 + uint32(c[i])
		}
		v := uint8(1 + (h % 254))
		return v
	}
}

// PromoteIPv4WithCountry uses country string, updates dynamic cache, and, if policy exists, writes route hint with policy id.
func PromoteIPv4WithCountry(ip uint32, country string, ttlSeconds uint32) {
	code := CountryCode8FromString(country)
	if code == 0 {
		return
	}
	PromoteIPv4(ip, code, ttlSeconds)
	lc := getGeoIPLearning()
	if !lc.enabled || lc.routeHint == nil || lc.policy == nil {
		return
	}
	// Lookup policy id by country code and populate route hint (value is u32 policy id)
	key := code
	var policyID uint32
	if err := lc.policy.Lookup(&key, &policyID); err == nil && policyID != 0 {
		if err2 := lc.routeHint.Update(&ip, &policyID, ebpf.UpdateAny); err2 != nil {
			errors.LogDebug(context.Background(), "route_geoip_v4_hint update failed: ", err2)
		}
	}
}
