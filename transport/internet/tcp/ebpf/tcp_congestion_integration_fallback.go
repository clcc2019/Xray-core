//go:build !linux
// +build !linux

package ebpf

import (
	"context"
	"net"

	xnet "github.com/xtls/xray-core/common/net"
)

// CongestionStats 拥塞控制统计 (跨平台兼容)
type CongestionStats struct {
	TotalConnections         uint64
	SlowStartCount           uint64
	CongestionAvoidanceCount uint64
	RetransmitCount          uint64
	ECNMarks                 uint64
	AverageCWND              uint64
	AverageRTT               uint64
}

// EnableTCPCongestionControl 启用TCP拥塞控制优化 (跨平台兼容)
func EnableTCPCongestionControl(ctx context.Context, conn net.Conn, destination xnet.Destination) {
	// 非Linux平台不执行任何操作
}

// GetTCPCongestionStats 获取TCP拥塞控制统计 (跨平台兼容)
func GetTCPCongestionStats() *CongestionStats {
	// 返回空的统计信息
	return &CongestionStats{}
}
