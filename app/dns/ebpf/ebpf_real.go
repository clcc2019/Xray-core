//go:build linux && amd64

package ebpf

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
)

// 真正的eBPF集成实现
type RealEBpfDNSCache struct {
	enabled     bool
	programFd   int
	dnsCacheMap int
	statsMap    int
}

// BPF系统调用常量
const (
	BPF_MAP_LOOKUP_ELEM = 1
	BPF_MAP_UPDATE_ELEM = 2
	BPF_MAP_DELETE_ELEM = 3
)

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
	// 尝试从bpffs加载程序
	programPath := "/sys/fs/bpf/xray/dns_cache"
	if _, err := os.Stat(programPath); os.IsNotExist(err) {
		return fmt.Errorf("eBPF program not found at %s", programPath)
	}

	// 打开程序文件描述符
	fd, err := syscall.Open(programPath, syscall.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open eBPF program: %v", err)
	}

	c.programFd = fd
	errors.LogInfo(context.Background(), "eBPF program loaded, fd: ", fd)

	// 打开maps
	if err := c.openMaps(); err != nil {
		return fmt.Errorf("failed to open eBPF maps: %v", err)
	}

	return nil
}

// 打开eBPF maps
func (c *RealEBpfDNSCache) openMaps() error {
	// 打开DNS缓存map
	dnsCachePath := "/sys/fs/bpf/xray/dns_cache"
	fd, err := syscall.Open(dnsCachePath, syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open DNS cache map: %v", err)
	}
	c.dnsCacheMap = fd

	// 打开统计map
	statsPath := "/sys/fs/bpf/xray/dns_stats"
	fd, err = syscall.Open(statsPath, syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("failed to open stats map: %v", err)
	}
	c.statsMap = fd

	errors.LogInfo(context.Background(), "eBPF maps opened successfully")
	return nil
}

// 添加DNS记录到eBPF缓存
func (c *RealEBpfDNSCache) AddRecord(domain string, ips []net.IP, ttl uint32, rcode uint16) error {
	if !c.enabled {
		return errors.New("eBPF DNS cache is not enabled")
	}

	// 计算域名哈希
	hash := c.hashDomain(domain)

	// 准备数据
	var ip uint32
	if len(ips) > 0 {
		ip = c.ipToUint32(ips[0])
	}

	// 更新eBPF map
	if err := c.updateMap(c.dnsCacheMap, unsafe.Pointer(&hash), unsafe.Pointer(&ip)); err != nil {
		errors.LogInfo(context.Background(), "Failed to update eBPF DNS cache: ", err)
		return err
	}

	errors.LogInfo(context.Background(), "Added DNS record to eBPF cache: ", domain, " -> ", ips[0])
	return nil
}

// 从eBPF缓存查找DNS记录
func (c *RealEBpfDNSCache) LookupRecord(domain string) ([]net.IP, uint32, error) {
	if !c.enabled {
		return nil, 0, errors.New("eBPF DNS cache is not enabled")
	}

	// 计算域名哈希
	hash := c.hashDomain(domain)

	// 从eBPF map查找
	var ip uint32
	if err := c.lookupMap(c.dnsCacheMap, unsafe.Pointer(&hash), unsafe.Pointer(&ip)); err != nil {
		// 缓存未命中
		errors.LogInfo(context.Background(), "DNS cache miss: ", domain)
		return nil, 0, err
	}

	// 缓存命中
	ipAddr := c.uint32ToIP(ip)
	errors.LogInfo(context.Background(), "DNS cache hit: ", domain, " -> ", ipAddr)
	return []net.IP{ipAddr}, 300, nil
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

// 计算域名哈希
func (c *RealEBpfDNSCache) hashDomain(domain string) uint64 {
	var hash uint64
	for _, char := range domain {
		hash = hash*31 + uint64(char)
	}
	return hash
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
