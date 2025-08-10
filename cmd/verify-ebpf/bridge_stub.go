//go:build !linux

package main

var (
	geoipCountryFlag string
	geoipReverseFlag bool
)

func setGeoIPFlags(country string, reverse bool) {
	geoipCountryFlag = country
	geoipReverseFlag = reverse
}

func testDNSBridge() (bool, map[string]interface{}, error)   { return false, nil, nil }
func testGeoIPBridge() (bool, map[string]interface{}, error) { return false, nil, nil }
