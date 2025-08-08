//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const (
	pinnedDNSRouteMap = "/sys/fs/bpf/xray/dns_route_map"
	pinnedDNSAnomMap  = "/sys/fs/bpf/xray/dns_anomalies"
)

type DNSRouterManager struct {
	route *ebpf.Map
	anom  *ebpf.Map
}

func (m *DNSRouterManager) LoadPinned() error {
	r, err := ebpf.LoadPinnedMap(pinnedDNSRouteMap, nil)
	if err != nil {
		return fmt.Errorf("load route map: %w", err)
	}
	m.route = r
	a, err := ebpf.LoadPinnedMap(pinnedDNSAnomMap, nil)
	if err == nil {
		m.anom = a
	}
	return nil
}

// SetDomainRouteMark sets skb mark for a domain hash to select specific DNS server route in tc.
func (m *DNSRouterManager) SetDomainRouteMark(domainHash uint32, mark uint32) error {
	if m.route == nil {
		if err := m.LoadPinned(); err != nil {
			return err
		}
	}
	return m.route.Update(&domainHash, &mark, ebpf.UpdateAny)
}

// ComputeFNV1a32 lowercases domain and computes FNV-1a 32-bit hash compatible with BPF side.
func ComputeFNV1a32(domain string) uint32 {
	const prime uint32 = 16777619
	var h uint32 = 2166136261
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint32(c)
		h *= prime
	}
	return h
}

// Helper to derive mark per server (example: based on server IP last byte)
func MarkForDNSServer(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[3])
}

func ensureDir(path string) string { return filepath.Dir(path) }

// SetDefaultDotMark sets the skb mark used for DoT (TCP/853) flows detected in BPF.
func (m *DNSRouterManager) SetDefaultDotMark(mark uint32) error {
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/dns_proto_marks", nil)
	if err != nil {
		return err
	}
	var idx uint32 = 1
	return mp.Update(&idx, &mark, ebpf.UpdateAny)
}

// SetDefaultDohMark sets the skb mark used for DoH (HTTPS) destinations present in allowlist maps.
func (m *DNSRouterManager) SetDefaultDohMark(mark uint32) error {
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/dns_proto_marks", nil)
	if err != nil {
		return err
	}
	var idx uint32 = 2
	return mp.Update(&idx, &mark, ebpf.UpdateAny)
}

// AddDohEndpointV4 adds a DoH endpoint to allowlist, associating a mark.
func (m *DNSRouterManager) AddDohEndpointV4(ip net.IP, port uint16, mark uint32) error {
	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("not ipv4")
	}
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/doh_endpoints_v4", nil)
	if err != nil {
		return err
	}
	key := (uint64(v4[0])<<24 | uint64(v4[1])<<16 | uint64(v4[2])<<8 | uint64(v4[3]))
	key = (key << 16) | uint64(port)
	return mp.Update(&key, &mark, ebpf.UpdateAny)
}

// AddDohEndpointV6 adds a DoH endpoint (IPv6) to allowlist, associating a mark.
func (m *DNSRouterManager) AddDohEndpointV6(ip net.IP, port uint16, mark uint32) error {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return fmt.Errorf("not ipv6")
	}
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/doh_endpoints_v6", nil)
	if err != nil {
		return err
	}
	var key struct {
		Hi, Lo uint64
		Port   uint16
	}
	key.Hi = uint64(v6[0])<<56 | uint64(v6[1])<<48 | uint64(v6[2])<<40 | uint64(v6[3])<<32 | uint64(v6[4])<<24 | uint64(v6[5])<<16 | uint64(v6[6])<<8 | uint64(v6[7])
	key.Lo = uint64(v6[8])<<56 | uint64(v6[9])<<48 | uint64(v6[10])<<40 | uint64(v6[11])<<32 | uint64(v6[12])<<24 | uint64(v6[13])<<16 | uint64(v6[14])<<8 | uint64(v6[15])
	key.Port = port
	return mp.Update(&key, &mark, ebpf.UpdateAny)
}
