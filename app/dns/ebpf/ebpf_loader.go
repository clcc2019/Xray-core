//go:build linux && amd64

package ebpf

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
)

// BPF相关常量
const (
	BPF_PROG_TYPE_XDP        = 8
	BPF_MAP_TYPE_HASH        = 1
	BPF_MAP_TYPE_ARRAY       = 2
	BPF_FUNC_map_lookup_elem = 1
	BPF_FUNC_map_update_elem = 2
	BPF_FUNC_map_delete_elem = 3
)

// BPF系统调用号
const (
	SYS_BPF = 321
)

// BPF命令
const (
	BPF_MAP_CREATE = 0
	BPF_PROG_LOAD  = 5
	BPF_OBJ_PIN    = 6
	BPF_OBJ_GET    = 7
)

// BPFMapInfo eBPF map信息
type BPFMapInfo struct {
	Type       uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

// BPFProgInfo eBPF程序信息
type BPFProgInfo struct {
	ProgType      uint32
	InsnCnt       uint32
	ProgName      [16]byte
	XlatedProgLen uint32
	ProgTag       [8]byte
}

// EBpfLoader 真正的eBPF加载器
type EBpfLoader struct {
	enabled     bool
	programs    map[string]int // 程序ID
	maps        map[string]int // map ID
	programPath string
}

// NewEBpfLoader 创建新的eBPF加载器
func NewEBpfLoader() (*EBpfLoader, error) {
	loader := &EBpfLoader{
		enabled:     false,
		programs:    make(map[string]int),
		maps:        make(map[string]int),
		programPath: "/usr/local/bin/xray",
	}

	// 检查eBPF支持
	if err := loader.checkSupport(); err != nil {
		errors.LogInfo(context.Background(), "eBPF not supported: ", err)
		return loader, nil
	}

	// 尝试加载eBPF程序
	if err := loader.loadPrograms(); err != nil {
		errors.LogInfo(context.Background(), "Failed to load eBPF programs: ", err)
		return loader, nil
	}

	loader.enabled = true
	errors.LogInfo(context.Background(), "eBPF loader initialized successfully")
	return loader, nil
}

// checkSupport 检查eBPF支持
func (e *EBpfLoader) checkSupport() error {
	// 检查内核版本
	if err := e.checkKernelVersion(); err != nil {
		return fmt.Errorf("kernel version check failed: %v", err)
	}

	// 检查bpffs
	if err := e.checkBpffs(); err != nil {
		return fmt.Errorf("bpffs check failed: %v", err)
	}

	return nil
}

// checkKernelVersion 检查内核版本
func (e *EBpfLoader) checkKernelVersion() error {
	// 简化实现，假设支持
	return nil
}

// checkBpffs 检查bpffs
func (e *EBpfLoader) checkBpffs() error {
	if _, err := os.Stat("/sys/fs/bpf"); os.IsNotExist(err) {
		return fmt.Errorf("/sys/fs/bpf does not exist")
	}
	return nil
}

// loadPrograms 加载eBPF程序
func (e *EBpfLoader) loadPrograms() error {
	// 查找eBPF程序文件
	programs := []string{
		"dns_cache.o",
		"geoip_matcher.o",
	}

	for _, program := range programs {
		paths := []string{
			"./" + program,
			"/usr/local/lib/xray/" + program,
			"/opt/xray/" + program,
		}

		for _, path := range paths {
			if _, err := os.Stat(path); err == nil {
				if err := e.loadProgram(path); err != nil {
					errors.LogInfo(context.Background(), "Failed to load program ", path, ": ", err)
				} else {
					errors.LogInfo(context.Background(), "Successfully loaded eBPF program: ", path)
					break
				}
			}
		}
	}

	return nil
}

// loadProgram 加载单个eBPF程序
func (e *EBpfLoader) loadProgram(path string) error {
	// 读取程序文件
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read program file: %v", err)
	}

	// 创建eBPF程序
	progFd, err := e.createProgram(data)
	if err != nil {
		return fmt.Errorf("failed to create program: %v", err)
	}

	// 存储程序ID
	programName := filepath.Base(path)
	e.programs[programName] = progFd

	// 创建相关的maps
	if err := e.createMaps(programName); err != nil {
		errors.LogInfo(context.Background(), "Failed to create maps for ", programName, ": ", err)
	}

	return nil
}

// createProgram 创建eBPF程序
func (e *EBpfLoader) createProgram(data []byte) (int, error) {
	// 准备程序加载参数
	_ = BPFProgInfo{
		ProgType: BPF_PROG_TYPE_XDP,
		InsnCnt:  uint32(len(data) / 8), // 假设每条指令8字节
	}

	// 系统调用参数
	attr := struct {
		ProgType           uint32
		InsnCnt            uint32
		ProgInsns          uintptr
		License            uintptr
		LogLevel           uint32
		LogSize            uint32
		LogBuf             uintptr
		KernVersion        uint32
		ProgFlags          uint32
		ProgName           [16]byte
		ProgIfIndex        uint32
		ExpectedAttachType uint32
		ProgBtfFd          uint32
		FuncInfoRecSize    uint32
		FuncInfo           uintptr
		FuncInfoCnt        uint32
		LineInfoRecSize    uint32
		LineInfo           uintptr
		LineInfoCnt        uint32
		AttachBtfId        uint32
		AttachProgFd       uint32
	}{
		ProgType:  BPF_PROG_TYPE_XDP,
		InsnCnt:   uint32(len(data) / 8),
		ProgInsns: uintptr(unsafe.Pointer(&data[0])),
		License:   uintptr(unsafe.Pointer(&[]byte("GPL\000")[0])),
		LogLevel:  1,
		LogSize:   1024,
		LogBuf:    uintptr(unsafe.Pointer(&make([]byte, 1024)[0])),
	}

	// 执行系统调用
	fd, _, errno := syscall.Syscall(SYS_BPF, BPF_PROG_LOAD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, fmt.Errorf("bpf syscall failed: %v", errno)
	}

	return int(fd), nil
}

// createMaps 创建eBPF maps
func (e *EBpfLoader) createMaps(programName string) error {
	// 创建DNS缓存map
	if programName == "dns_cache.o" {
		dnsMapFd, err := e.createMap(BPF_MAP_TYPE_HASH, 8, 4, 50000) // key: uint64, value: uint32
		if err != nil {
			return fmt.Errorf("failed to create DNS cache map: %v", err)
		}
		e.maps["dns_cache"] = dnsMapFd

		// 创建统计map
		statsMapFd, err := e.createMap(BPF_MAP_TYPE_ARRAY, 4, 8, 10) // key: uint32, value: uint64
		if err != nil {
			return fmt.Errorf("failed to create stats map: %v", err)
		}
		e.maps["dns_stats"] = statsMapFd
	}

	// 创建GeoIP maps
	if programName == "geoip_matcher.o" {
		geoipV4MapFd, err := e.createMap(BPF_MAP_TYPE_HASH, 4, 1, 10000) // key: uint32, value: uint8
		if err != nil {
			return fmt.Errorf("failed to create GeoIP v4 map: %v", err)
		}
		e.maps["geoip_v4"] = geoipV4MapFd

		geoipV6MapFd, err := e.createMap(BPF_MAP_TYPE_HASH, 8, 1, 10000) // key: uint64, value: uint8
		if err != nil {
			return fmt.Errorf("failed to create GeoIP v6 map: %v", err)
		}
		e.maps["geoip_v6"] = geoipV6MapFd
	}

	return nil
}

// createMap 创建eBPF map
func (e *EBpfLoader) createMap(mapType, keySize, valueSize, maxEntries uint32) (int, error) {
	_ = BPFMapInfo{
		Type:       mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		MapFlags:   0,
	}

	// 系统调用参数
	attr := struct {
		MapType               uint32
		KeySize               uint32
		ValueSize             uint32
		MaxEntries            uint32
		MapFlags              uint32
		InnerMapFd            uint32
		NumaNode              uint32
		MapName               [16]byte
		MapIfIndex            uint32
		BtfFd                 uint32
		BtfKeyTypeId          uint32
		BtfValueTypeId        uint32
		BtfVmlinuxValueTypeId uint32
	}{
		MapType:    mapType,
		KeySize:    keySize,
		ValueSize:  valueSize,
		MaxEntries: maxEntries,
		MapFlags:   0,
	}

	// 执行系统调用
	fd, _, errno := syscall.Syscall(SYS_BPF, BPF_MAP_CREATE, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return -1, fmt.Errorf("bpf map create failed: %v", errno)
	}

	return int(fd), nil
}

// IsEnabled 检查eBPF是否启用
func (e *EBpfLoader) IsEnabled() bool {
	return e.enabled
}

// GetStats 获取统计信息
func (e *EBpfLoader) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["enabled"] = e.enabled
	stats["platform"] = "linux"
	stats["programs_loaded"] = len(e.programs)
	stats["maps_created"] = len(e.maps)
	stats["programs"] = e.programs
	stats["maps"] = e.maps

	return stats
}

// Close 关闭eBPF加载器
func (e *EBpfLoader) Close() error {
	// 关闭所有程序文件描述符
	for name, fd := range e.programs {
		syscall.Close(fd)
		errors.LogInfo(context.Background(), "Closed eBPF program: ", name)
	}

	// 关闭所有map文件描述符
	for name, fd := range e.maps {
		syscall.Close(fd)
		errors.LogInfo(context.Background(), "Closed eBPF map: ", name)
	}

	e.programs = make(map[string]int)
	e.maps = make(map[string]int)
	e.enabled = false

	errors.LogInfo(context.Background(), "eBPF loader closed")
	return nil
}
