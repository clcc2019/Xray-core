//go:build linux

package ebpf

import (
	"sync"

	"github.com/cilium/ebpf"
)

var (
	geoSitePolicyOnce sync.Once
	geoSitePolicyMap  *ebpf.Map
)

func getGeoSitePolicyMap() *ebpf.Map {
	geoSitePolicyOnce.Do(func() {
		m, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/geosite_policy", nil)
		if err == nil {
			geoSitePolicyMap = m
		}
	})
	return geoSitePolicyMap
}

// GetGeoSitePolicyMark returns policy mark for a site code if available
func GetGeoSitePolicyMark(siteCode uint8) (uint32, bool) {
	m := getGeoSitePolicyMap()
	if m == nil {
		return 0, false
	}
	var val uint32
	if err := m.Lookup(&siteCode, &val); err != nil {
		return 0, false
	}
	return val, val != 0
}
