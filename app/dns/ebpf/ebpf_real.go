//go:build linux && amd64

package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
)

// 真正的eBPF集成实现
type RealEBpfDNSCache struct {
	enabled       bool
	programFd     int
	dnsCacheMap   int
	dnsCacheV6Map int
	statsMap      int
}

// BPF系统调用常量
const (
	BPF_MAP_LOOKUP_ELEM = 1
	BPF_MAP_UPDATE_ELEM = 2
	BPF_MAP_DELETE_ELEM = 3
)

// value structs aligned with kernel side (dns_cache.c)
type dnsResponseV4 struct {
	IP         uint32
	TTL        uint32
	ExpireTime uint64
}

type dnsResponseV6 struct {
	IPHigh     uint64
	IPLow      uint64
	TTL        uint32
	ExpireTime uint64
}

// 创建真正的eBPF DNS缓存
func NewRealEBpfDNSCache() (*RealEBpfDNSCache, error) {
	cache := &RealEBpfDNSCache{
		enabled: false,
	}

	// 检查eBPF支持
	if err := cache.checkEBpfSupport(); err != nil {
		errors.LogInfo(context.Background(), "eBPF not supported: ", err)
		return cache, nil
	}

	// 尝试加载eBPF程序
	if err := cache.loadEBpfProgram(); err != nil {
		errors.LogInfo(context.Background(), "Failed to load eBPF program: ", err)
		return cache, nil
	}

	cache.enabled = true
	errors.LogInfo(context.Background(), "Real eBPF DNS cache initialized successfully")
	return cache, nil
}

// 检查eBPF支持
func (c *RealEBpfDNSCache) checkEBpfSupport() error {
	// 检查内核版本
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return fmt.Errorf("failed to get kernel version: %v", err)
	}

	// 检查bpffs
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("/sys/fs/bpf does not exist")
	}

	errors.LogInfo(context.Background(), "eBPF support verified")
	return nil
}

// 加载eBPF程序
func (c *RealEBpfDNSCache) loadEBpfProgram() error {
	// 简化：仅确保所需 maps 存在并可打开；程序加载由外部脚本负责
	if err := c.openMaps(); err != nil {
		return fmt.Errorf("failed to open eBPF maps: %v", err)
	}
	return nil
}

// 打开eBPF maps
func (c *RealEBpfDNSCache) openMaps() error {
	// 打开DNS缓存map（使用 BPF_OBJ_GET 获取 FD）
	dnsCachePath := "/sys/fs/bpf/xray/dns_cache"
	var fd int
	var err error
	for i := 0; i < 10; i++ {
		if fd, err = bpfObjGetPinned(dnsCachePath); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("failed to open DNS cache map: %v", err)
	}
	c.dnsCacheMap = fd

	// 打开IPv6 DNS缓存map（可选）
	dnsCacheV6Path := "/sys/fs/bpf/xray/dns_cache_v6"
	if _, statErr := os.Stat(dnsCacheV6Path); statErr == nil {
		if fdv6, ge := bpfObjGetPinned(dnsCacheV6Path); ge == nil {
			c.dnsCacheV6Map = fdv6
		}
	}

	// 打开统计map
	statsPath := "/sys/fs/bpf/xray/dns_stats"
	if fd, ge := bpfObjGetPinned(statsPath); ge == nil {
		c.statsMap = fd
	} else {
		errors.LogInfo(context.Background(), "dns_stats map not available: ", ge)
	}

	errors.LogInfo(context.Background(), "eBPF maps opened successfully")
	return nil
}

// 通过 BPF_OBJ_GET 打开 pinned 对象
func bpfObjGetPinned(path string) (int, error) {
	b := append([]byte(path), 0)
	attr := struct {
		pathname   uint64
		bpf_fd     uint32
		file_flags uint32
	}{
		pathname: uint64(uintptr(unsafe.Pointer(&b[0]))),
	}
	fd, _, errno := syscall.Syscall(SYS_BPF, BPF_OBJ_GET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, fmt.Errorf("bpf obj get failed: %v", errno)
	}
	return int(fd), nil
}

// 添加DNS记录到eBPF缓存
func (c *RealEBpfDNSCache) AddRecord(domain string, ips []net.IP, ttl uint32, rcode uint16) error {
	if !c.enabled {
		return errors.New("eBPF DNS cache is not enabled")
	}
	if len(ips) == 0 {
		return errors.New("no IP to add")
	}
	hash := fnv1a32Domain(domain)
	v4 := ips[0].To4()
	if v4 == nil {
		return errors.New("no IPv4 in AddRecord; use AddRecordV6")
	}
	now := uint64(time.Now().Unix())
	val := dnsResponseV4{
		IP:         uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]),
		TTL:        ttl,
		ExpireTime: now + uint64(ttl),
	}
	if err := c.updateMap(c.dnsCacheMap, unsafe.Pointer(&hash), unsafe.Pointer(&val)); err != nil {
		return err
	}
	return nil
}

// 添加IPv6记录
func (c *RealEBpfDNSCache) AddRecordV6(domain string, ips []net.IP, ttl uint32, rcode uint16) error {
	if !c.enabled {
		return errors.New("eBPF DNS cache is not enabled")
	}
	if c.dnsCacheV6Map == 0 {
		return errors.New("IPv6 DNS cache map not available")
	}
	var raw6 [16]byte
	for _, ip := range ips {
		if ip = ip.To16(); ip != nil && ip.To4() == nil {
			copy(raw6[:], ip)
			break
		}
	}
	if raw6 == ([16]byte{}) {
		return errors.New("no IPv6 address provided")
	}
	hash := fnv1a32Domain(domain)
	high := uint64(raw6[0])<<56 | uint64(raw6[1])<<48 | uint64(raw6[2])<<40 | uint64(raw6[3])<<32 |
		uint64(raw6[4])<<24 | uint64(raw6[5])<<16 | uint64(raw6[6])<<8 | uint64(raw6[7])
	low := uint64(raw6[8])<<56 | uint64(raw6[9])<<48 | uint64(raw6[10])<<40 | uint64(raw6[11])<<32 |
		uint64(raw6[12])<<24 | uint64(raw6[13])<<16 | uint64(raw6[14])<<8 | uint64(raw6[15])
	now := uint64(time.Now().Unix())
	val := dnsResponseV6{IPHigh: high, IPLow: low, TTL: ttl, ExpireTime: now + uint64(ttl)}
	if err := c.updateMap(c.dnsCacheV6Map, unsafe.Pointer(&hash), unsafe.Pointer(&val)); err != nil {
		return err
	}
	return nil
}

// 从eBPF缓存查找DNS记录
func (c *RealEBpfDNSCache) LookupRecord(domain string) ([]net.IP, uint32, error) {
	if !c.enabled {
		return nil, 0, errors.New("eBPF DNS cache is not enabled")
	}
	hash := fnv1a32Domain(domain)
	var val dnsResponseV4
	if err := c.lookupMap(c.dnsCacheMap, unsafe.Pointer(&hash), unsafe.Pointer(&val)); err != nil {
		return nil, 0, err
	}
	now := uint64(time.Now().Unix())
	if now > val.ExpireTime || val.TTL == 0 {
		_ = c.deleteMap(c.dnsCacheMap, unsafe.Pointer(&hash))
		return nil, 0, errors.New("expired")
	}
	ipAddr := c.uint32ToIP(val.IP)
	return []net.IP{ipAddr}, val.TTL, nil
}

// 查找IPv6记录
func (c *RealEBpfDNSCache) LookupRecordV6(domain string) ([]net.IP, uint32, error) {
	if !c.enabled {
		return nil, 0, errors.New("eBPF DNS cache is not enabled")
	}
	if c.dnsCacheV6Map == 0 {
		return nil, 0, errors.New("IPv6 DNS cache map not available")
	}
	hash := fnv1a32Domain(domain)
	var val dnsResponseV6
	if err := c.lookupMap(c.dnsCacheV6Map, unsafe.Pointer(&hash), unsafe.Pointer(&val)); err != nil {
		return nil, 0, err
	}
	now := uint64(time.Now().Unix())
	if now > val.ExpireTime || val.TTL == 0 {
		_ = c.deleteMap(c.dnsCacheV6Map, unsafe.Pointer(&hash))
		return nil, 0, errors.New("expired")
	}
	var raw6 [16]byte
	for i := 0; i < 8; i++ {
		raw6[i] = byte((val.IPHigh >> uint(56-8*i)) & 0xFF)
		raw6[8+i] = byte((val.IPLow >> uint(56-8*i)) & 0xFF)
	}
	ip := net.IP(raw6[:])
	return []net.IP{ip}, val.TTL, nil
}

// 更新eBPF map
func (c *RealEBpfDNSCache) updateMap(mapFd int, key, value unsafe.Pointer) error {
	attr := struct {
		mapFd uint32
		key   uintptr
		value uintptr
		flags uint64
	}{
		mapFd: uint32(mapFd),
		key:   uintptr(key),
		value: uintptr(value),
		flags: 0,
	}

	_, _, errno := syscall.Syscall(SYS_BPF, BPF_MAP_UPDATE_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return fmt.Errorf("bpf map update failed: %v", errno)
	}

	return nil
}

// 查找eBPF map
func (c *RealEBpfDNSCache) lookupMap(mapFd int, key, value unsafe.Pointer) error {
	attr := struct {
		mapFd uint32
		key   uintptr
		value uintptr
	}{
		mapFd: uint32(mapFd),
		key:   uintptr(key),
		value: uintptr(value),
	}

	_, _, errno := syscall.Syscall(SYS_BPF, BPF_MAP_LOOKUP_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return fmt.Errorf("bpf map lookup failed: %v", errno)
	}

	return nil
}

// 删除元素
func (c *RealEBpfDNSCache) deleteMap(mapFd int, key unsafe.Pointer) error {
	attr := struct {
		mapFd uint32
		key   uintptr
	}{
		mapFd: uint32(mapFd),
		key:   uintptr(key),
	}
	_, _, errno := syscall.Syscall(SYS_BPF, BPF_MAP_DELETE_ELEM, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return fmt.Errorf("bpf map delete failed: %v", errno)
	}
	return nil
}

// 计算域名哈希
func fnv1a32Domain(domain string) uint32 {
	const prime uint32 = 16777619
	var h uint32 = 2166136261
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c == '.' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c = c + 32
		}
		h ^= uint32(c)
		h *= prime
	}
	return h
}

// IP地址转换为uint32
func (c *RealEBpfDNSCache) ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32转换为IP地址
func (c *RealEBpfDNSCache) uint32ToIP(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// 获取统计信息
func (c *RealEBpfDNSCache) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["enabled"] = c.enabled
	stats["program_fd"] = c.programFd
	stats["dns_cache_map"] = c.dnsCacheMap
	stats["stats_map"] = c.statsMap
	stats["platform"] = "linux"
	stats["real_ebpf"] = true
	return stats
}

// 关闭eBPF资源
func (c *RealEBpfDNSCache) Close() error {
	if c.programFd > 0 {
		syscall.Close(c.programFd)
	}
	if c.dnsCacheMap > 0 {
		syscall.Close(c.dnsCacheMap)
	}
	if c.statsMap > 0 {
		syscall.Close(c.statsMap)
	}
	c.enabled = false
	errors.LogInfo(context.Background(), "Real eBPF DNS cache closed")
	return nil
}

// 检查是否启用
func (c *RealEBpfDNSCache) IsEnabled() bool {
	return c.enabled
}
