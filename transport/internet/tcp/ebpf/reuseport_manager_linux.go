//go:build linux

package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

const pinnedReuseportFeedback = "/sys/fs/bpf/xray/reuseport_feedback"

type ReuseportManager struct{ feedback *ebpf.Map }

func (m *ReuseportManager) ensure() error {
	if m.feedback != nil {
		return nil
	}
	mp, err := ebpf.LoadPinnedMap(pinnedReuseportFeedback, nil)
	if err != nil {
		return fmt.Errorf("load reuseport_feedback: %w", err)
	}
	m.feedback = mp
	return nil
}

// SetBias 设置端口级偏置（供 sk_reuseport 选择器扰动哈希使用）
// isV6 为 true 时，写入 IPv6 key；否则写入 IPv4 key。
func (m *ReuseportManager) SetBias(port int, bias uint32, isV6 bool) error {
	if os.Getenv("XRAY_EBPF") != "1" {
		return nil
	}
	if err := m.ensure(); err != nil {
		return err
	}
	// key: 高16位端口 + bit0 is_v6
	var key uint32 = (uint32(uint16(port)) << 16)
	if isV6 {
		key |= 1
	}
	val := bias
	return m.feedback.Update(&key, &val, ebpf.UpdateAny)
}
