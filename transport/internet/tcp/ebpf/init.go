//go:build linux

package ebpf

import (
	"github.com/xtls/xray-core/common/log"
)

func init() {
	// 初始化XTLS Vision eBPF管理器
	manager := GetXTLSVisionManager()
	if manager.IsEnabled() {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Info,
			Content:  "XTLS Vision eBPF package initialized",
		})
	}
}
