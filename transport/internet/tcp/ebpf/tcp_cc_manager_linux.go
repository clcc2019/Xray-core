//go:build linux

package ebpf

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

const (
	pinnedSockopsProg = "/sys/fs/bpf/xray/tcp_cc_sockops"
	pinnedPolicyMap   = "/sys/fs/bpf/xray/tcp_cc_policy"
)

// TCPCCManager configures sockops program and policy map.
type TCPCCManager struct {
	policy *ebpf.Map
}

func (m *TCPCCManager) LoadPinned() error {
	pol, err := ebpf.LoadPinnedMap(pinnedPolicyMap, nil)
	if err != nil {
		return fmt.Errorf("load policy map: %w", err)
	}
	m.policy = pol
	return nil
}

// SetPolicy updates the policy slot 0.
func (m *TCPCCManager) SetPolicy(rttUs uint32, lossPct uint32, preferBBR bool, enableBBR bool, enableCubic bool, initCwndPkts uint8) error {
	if m.policy == nil {
		if err := m.LoadPinned(); err != nil {
			return err
		}
	}
	type ccPolicyConfig struct {
		RttUsThreshold   uint32
		LossPctThreshold uint32
		PreferBBR        uint8
		EnableBBR        uint8
		EnableCubic      uint8
		InitCwndPkts     uint8
	}
	v := ccPolicyConfig{
		RttUsThreshold:   rttUs,
		LossPctThreshold: lossPct,
		PreferBBR:        boolToU8(preferBBR),
		EnableBBR:        boolToU8(enableBBR),
		EnableCubic:      boolToU8(enableCubic),
		InitCwndPkts:     initCwndPkts,
	}
	var key uint32 = 0
	return m.policy.Update(&key, &v, ebpf.UpdateAny)
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// Helper to ensure pinned paths exist.
func ensurePinnedDir(path string) string { return filepath.Dir(path) }

// InitDefaultTCPCCPolicy sets a reasonable default policy on startup (Linux only).
// Safe to call even when maps are not mounted; it will no-op on error.
func InitDefaultTCPCCPolicy() error {
	mgr := &TCPCCManager{}
	// Defaults: RTT>30ms -> prefer BBR; enable both; initcwnd 20
	if err := mgr.SetPolicy(30000, 2, true, true, true, 20); err != nil {
		return err
	}
	return nil
}
