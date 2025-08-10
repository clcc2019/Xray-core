//go:build linux

package ebpf

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
)

const (
	pinnedSocketDirectProg   = "/sys/fs/bpf/xray/socket_direct_filter"
	pinnedSocketDirectConfig = "/sys/fs/bpf/xray/sockdf_config"
	pinnedListenPorts        = "/sys/fs/bpf/xray/xray_listen_ports"
)

type SocketDirectManager struct {
	cfg   *ebpf.Map
	ports *ebpf.Map
}

func (m *SocketDirectManager) loadPinned() error {
	var err error
	m.cfg, err = ebpf.LoadPinnedMap(pinnedSocketDirectConfig, nil)
	if err != nil {
		return fmt.Errorf("load sockdf_config: %w", err)
	}
	m.ports, err = ebpf.LoadPinnedMap(pinnedListenPorts, nil)
	if err != nil {
		return fmt.Errorf("load xray_listen_ports: %w", err)
	}
	return nil
}

// RegisterPort adds a listening port into xray_listen_ports
func (m *SocketDirectManager) RegisterPort(p int) error {
	if m.cfg == nil || m.ports == nil {
		if err := m.loadPinned(); err != nil {
			return err
		}
	}
	key := uint16(p)
	val := uint8(1)
	return m.ports.Update(&key, &val, ebpf.UpdateAny)
}

// SetDefaultRules enables common drop rules.
func (m *SocketDirectManager) SetDefaultRules() error {
	if m.cfg == nil || m.ports == nil {
		if err := m.loadPinned(); err != nil {
			return err
		}
	}
	// 与 socket_direct_cgroup.c 中 struct sd_config 对齐: 4x u8 + 3x u32 = 16 字节
	type sdConfig struct {
		DropNull     uint8
		DropXmas     uint8
		DropSynFin   uint8
		DropSynRst   uint8
		SynRateLimit uint32
		TLSBadLimit  uint32
		BlockTTLSec  uint32
	}
	var key uint32 = 0
	// 环境变量可调：XRAY_EBPF_SYN_RATE、XRAY_EBPF_TLS_BAD_LIMIT、XRAY_EBPF_BLOCK_TTL
	getUint := func(name string, def uint32) uint32 {
		if s := os.Getenv(name); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n >= 0 {
				return uint32(n)
			}
		}
		return def
	}
	v := sdConfig{
		DropNull:     1,
		DropXmas:     1,
		DropSynFin:   1,
		DropSynRst:   1,
		SynRateLimit: getUint("XRAY_EBPF_SYN_RATE", 0),      // 0 表示禁用
		TLSBadLimit:  getUint("XRAY_EBPF_TLS_BAD_LIMIT", 0), // 0 表示禁用
		BlockTTLSec:  getUint("XRAY_EBPF_BLOCK_TTL", 10),
	}
	return m.cfg.Update(&key, &v, ebpf.UpdateAny)
}

// HookListen should be called when a TCP listener is created, to register the port.
func HookListen(addr net.Addr) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if os.Getenv("XRAY_EBPF") != "1" {
			return
		}
		_ = (&SocketDirectManager{}).RegisterPort(tcp.Port)
		_ = (&SocketDirectManager{}).SetDefaultRules()
		// 初始化该端口的 reuseport 偏置（可由外部动态更新）
		_ = (&ReuseportManager{}).SetBias(tcp.Port, 0, false)
	}
}
