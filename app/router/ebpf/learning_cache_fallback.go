//go:build !linux || !amd64

package ebpf

// Fallback no-op implementations for non-Linux/amd64 platforms

func PromoteDomain(domain string, siteCode uint8, ttlSeconds uint32)      {}
func PromoteIPv4(ip uint32, countryCode uint8, ttlSeconds uint32)         {}
func PromoteIPv4WithCountry(ip uint32, country string, ttlSeconds uint32) {}
