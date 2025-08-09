//go:build !linux

package ebpf

// GetGeoSitePolicyMark fallback
func GetGeoSitePolicyMark(siteCode uint8) (uint32, bool) { return 0, false }
