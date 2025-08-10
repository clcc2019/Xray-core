//go:build linux

package ebpf

import (
	"context"
	"os"

	"github.com/cilium/ebpf"
	"github.com/xtls/xray-core/common/errors"
)

// Minimal cgroup/connect manager: rely on external loader to attach programs.
// Here we just best-effort load pinned maps/programs so user space can interact if needed.

const (
	pinnedCgroupConnect4 = "/sys/fs/bpf/xray/cgroup_connect4"
	pinnedCgroupConnect6 = "/sys/fs/bpf/xray/cgroup_connect6"
	pinnedFwmarkPolicy   = "/sys/fs/bpf/xray/fwmark_policy"
)

type CgroupConnectManager struct {
	prog4  *ebpf.Program
	prog6  *ebpf.Program
	policy *ebpf.Map
	ready  bool
}

var globalCgroupMgr *CgroupConnectManager

func getCgroupMgr() *CgroupConnectManager {
	if globalCgroupMgr == nil {
		globalCgroupMgr = &CgroupConnectManager{}
	}
	return globalCgroupMgr
}

// StartCgroupConnect attempts to open pinned cgroup connect programs/maps.
// It does not attach programs (deployment script is responsible for attach).
func StartCgroupConnect() error {
	if os.Getenv("XRAY_EBPF") != "1" {
		return nil
	}
	mgr := getCgroupMgr()
	// Load pinned resources (ignore errors, best-effort)
	if p, err := ebpf.LoadPinnedProgram(pinnedCgroupConnect4, nil); err == nil {
		mgr.prog4 = p
	} else {
		errors.LogInfo(context.Background(), "cgroup/connect4 not available: ", err)
	}
	if p, err := ebpf.LoadPinnedProgram(pinnedCgroupConnect6, nil); err == nil {
		mgr.prog6 = p
	} else {
		errors.LogInfo(context.Background(), "cgroup/connect6 not available: ", err)
	}
	if m, err := ebpf.LoadPinnedMap(pinnedFwmarkPolicy, nil); err == nil {
		mgr.policy = m
	} else {
		errors.LogInfo(context.Background(), "fwmark_policy map not available: ", err)
	}
	mgr.ready = mgr.policy != nil || mgr.prog4 != nil || mgr.prog6 != nil
	if mgr.ready {
		errors.LogInfo(context.Background(), "cgroup/connect manager ready (pinned resources opened)")
	}
	return nil
}

func StopCgroupConnect() {
	mgr := getCgroupMgr()
	if mgr.prog4 != nil {
		mgr.prog4.Close()
		mgr.prog4 = nil
	}
	if mgr.prog6 != nil {
		mgr.prog6.Close()
		mgr.prog6 = nil
	}
	if mgr.policy != nil {
		mgr.policy.Close()
		mgr.policy = nil
	}
	mgr.ready = false
}

func (m *CgroupConnectManager) IsReady() bool { return m != nil && m.ready }
