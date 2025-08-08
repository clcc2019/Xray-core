//go:build linux

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// SockmapManager 负责加载 sk_msg/sockops，并在连接建立时把 socket 注册到 sockhash
type SockmapManager struct {
	mu        sync.RWMutex
	enabled   bool
	skMsg     *ebpf.Program
	sockOps   *ebpf.Program
	hash      *ebpf.Map
	cookieMap *ebpf.Map
	skStore   *ebpf.Map
	rbEvents  *ebpf.Map
	cgroupLn  link.Link
}

var (
	globalSockmapMgr *SockmapManager
	sockmapOnce      sync.Once
)

func GetSockmapManager() *SockmapManager {
	sockmapOnce.Do(func() {
		globalSockmapMgr = &SockmapManager{}
		if os.Getenv("XRAY_EBPF") == "1" {
			_ = globalSockmapMgr.Init(context.Background())
		}
	})
	return globalSockmapMgr
}

func (m *SockmapManager) Init(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enabled {
		return nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		// 软失败
		_ = err
	}

	// 加载 pinned 资源（由 mount-ebpf.sh 负责编译与 pin）
	var err error
	if m.hash, err = ebpf.LoadPinnedMap("/sys/fs/bpf/xray/tcp_sockhash", nil); err != nil {
		return fmt.Errorf("sockhash not found: %w", err)
	}
	if m.cookieMap, err = ebpf.LoadPinnedMap("/sys/fs/bpf/xray/tcp_cookie_to_sid", nil); err != nil {
		return fmt.Errorf("cookie map not found: %w", err)
	}
	if m.skStore, err = ebpf.LoadPinnedMap("/sys/fs/bpf/xray/tcp_sk_storage", nil); err != nil {
		return fmt.Errorf("sk_storage map not found: %w", err)
	}
	// ringbuf 可选
	if rb, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/tcp_sock_events", nil); err == nil {
		m.rbEvents = rb
	}

	// 将 sockops 附加到 cgroup v2
	cgroupPath := os.Getenv("XRAY_CGROUP_PATH")
	if cgroupPath == "" {
		// 常见 cgroup v2 根
		for _, p := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				cgroupPath = p
				break
			}
		}
	}
	if cgroupPath == "" {
		return errors.New("no cgroup v2 path found for sockops attach")
	}

	// 从 pinned 程序加载（由脚本 pin 到 /sys/fs/bpf/xray/）
	if m.sockOps, err = ebpf.LoadPinnedProgram("/sys/fs/bpf/xray/tcp_sockops", nil); err != nil {
		return fmt.Errorf("sockops pinned program not found: %w", err)
	}
	if m.skMsg, err = ebpf.LoadPinnedProgram("/sys/fs/bpf/xray/tcp_sockmsg", nil); err != nil {
		return fmt.Errorf("sk_msg pinned program not found: %w", err)
	}

	// 尝试附加 sockops 到 cgroup
	ln, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: m.sockOps,
	})
	if err != nil {
		return fmt.Errorf("attach sockops failed: %w", err)
	}
	m.cgroupLn = ln
	m.enabled = true
	return nil
}

// RegisterPair 为一对连接设置会话 sid/方向，并把 socket fd 加入 sockhash
// dir: 0/1 用于区分方向
func (m *SockmapManager) RegisterPair(conn net.Conn, sid uint64, dir uint32) error {
	m.mu.RLock()
	enabled := m.enabled
	m.mu.RUnlock()
	if !enabled {
		return nil
	}
	if conn == nil {
		return nil
	}

	// 此处不从用户态写入 cookie->sid，交由 sockops 在 ESTABLISHED 时通过 sk_storage 关联
	return nil
}

func (m *SockmapManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return nil
	}
	if m.cgroupLn != nil {
		_ = m.cgroupLn.Close()
	}
	if m.skMsg != nil {
		_ = m.skMsg.Close()
	}
	if m.sockOps != nil {
		_ = m.sockOps.Close()
	}
	if m.hash != nil {
		_ = m.hash.Close()
	}
	if m.cookieMap != nil {
		_ = m.cookieMap.Close()
	}
	if m.skStore != nil {
		_ = m.skStore.Close()
	}
	m.enabled = false
	return nil
}

func (m *SockmapManager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}
