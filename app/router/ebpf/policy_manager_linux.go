//go:build linux && amd64

package ebpf

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/xtls/xray-core/common/errors"
)

// PolicyManager writes geosite/geoip policy mappings to eBPF maps
// geosite_policy:  key=uint8 site_code, value=uint32 fwmark
// geoip_policy:    key=uint8 country_code, value=uint32 fwmark
type PolicyManager struct {
	geosite *ebpf.Map
	geoip   *ebpf.Map
}

func NewPolicyManager() *PolicyManager {
	pm := &PolicyManager{}
	if m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geosite_policy", nil); err == nil {
		pm.geosite = m
	} else {
		errors.LogDebug(context.Background(), "geosite_policy not available: ", err)
	}
	if m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geoip_policy", nil); err == nil {
		pm.geoip = m
	} else {
		errors.LogDebug(context.Background(), "geoip_policy not available: ", err)
	}
	return pm
}

func (pm *PolicyManager) SetGeoSitePolicy(siteCode uint8, mark uint32) error {
	if pm == nil || pm.geosite == nil {
		return nil
	}
	key := siteCode
	val := mark
	return pm.geosite.Update(&key, &val, ebpf.UpdateAny)
}

func (pm *PolicyManager) SetGeoIPPolicy(countryCode uint8, mark uint32) error {
	if pm == nil || pm.geoip == nil {
		return nil
	}
	key := countryCode
	val := mark
	return pm.geoip.Update(&key, &val, ebpf.UpdateAny)
}

// ApplyDefaultsFromEnv parses env and seeds the maps.
// XRAY_GEOSITE_POLICY example: "1=0x1,2=0x2,10=3" (site_code=mark). Marks accept 0xHEX or decimal.
// XRAY_GEOIP_POLICY   example: "1=0x1,2=0x2" (country_code=mark).
func (pm *PolicyManager) ApplyDefaultsFromEnv() {
	parse := func(s string) [][2]uint64 {
		var out [][2]uint64
		if s == "" {
			return out
		}
		items := strings.Split(s, ",")
		for _, it := range items {
			kv := strings.SplitN(strings.TrimSpace(it), "=", 2)
			if len(kv) != 2 {
				continue
			}
			k, err1 := strconv.ParseUint(strings.TrimSpace(kv[0]), 0, 8)
			v, err2 := strconv.ParseUint(strings.TrimSpace(kv[1]), 0, 32)
			if err1 == nil && err2 == nil {
				out = append(out, [2]uint64{k, v})
			}
		}
		return out
	}

	if pm.geosite != nil {
		def := os.Getenv("XRAY_GEOSITE_POLICY")
		// 默认不强制写入，避免误把未匹配流量打上策略；如需启用可在环境变量中显式设置
		if def != "" {
			for _, kv := range parse(def) {
				_ = pm.SetGeoSitePolicy(uint8(kv[0]), uint32(kv[1]))
			}
		}
	}
	if pm.geoip != nil {
		def := os.Getenv("XRAY_GEOIP_POLICY")
		for _, kv := range parse(def) {
			_ = pm.SetGeoIPPolicy(uint8(kv[0]), uint32(kv[1]))
		}
	}
}
