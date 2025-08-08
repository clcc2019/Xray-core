//go:build linux

package ebpf

import (
	"fmt"
	"net"

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
	type sdConfig struct{ DropNull, DropXmas, DropSynFin, DropSynRst uint8 }
	var key uint32 = 0
	v := sdConfig{1, 1, 1, 1}
	return m.cfg.Update(&key, &v, ebpf.UpdateAny)
}

// HookListen should be called when a TCP listener is created, to register the port.
func HookListen(addr net.Addr) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		_ = (&SocketDirectManager{}).RegisterPort(tcp.Port)
		_ = (&SocketDirectManager{}).SetDefaultRules()
	}
}
