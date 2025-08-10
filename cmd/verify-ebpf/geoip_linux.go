//go:build linux

package main

import (
	"errors"

	router_ebpf "github.com/xtls/xray-core/app/router/ebpf"
)

// 由 main 注入（Linux 平台声明变量）
var (
	geoipCountryFlag string
	geoipReverseFlag bool
)

func setGeoIPFlags(country string, reverse bool) {
	geoipCountryFlag = country
	geoipReverseFlag = reverse
}

func testGeoIPBridge() (bool, map[string]interface{}, error) {
	country := geoipCountryFlag
	if country == "" {
		country = "CN"
	}
	matcher, err := router_ebpf.NewEBpfGeoIPMatcher(country, geoipReverseFlag)
	if err != nil {
		return false, nil, err
	}
	defer matcher.Close()

	stats := matcher.GetStats()
	if !matcher.IsEnabled() {
		return false, stats, errors.New("GeoIP eBPF 未启用")
	}
	return true, stats, nil
}
