//go:build linux

package freedom

import (
	"context"
	"net"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/ebpf"
)

// recordConnectionStats 记录连接统计信息 (Cilium版本)
func recordConnectionStats(ctx context.Context, conn *net.TCPConn, accelerator *ebpf.ProxyAcceleratorCilium) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastBytes int64
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 获取连接统计（这里简化，实际可以从系统接口获取更精确的数据）
			if file, err := conn.File(); err == nil {
				// 简化统计：基于时间估算传输量
				elapsed := time.Since(startTime).Seconds()
				estimatedBytes := int64(elapsed * 1024) // 假设每秒1KB传输
				
				if estimatedBytes > lastBytes {
					bytesTransferred := estimatedBytes - lastBytes
					accelerator.RecordBytes(conn, bytesTransferred)
					lastBytes = estimatedBytes
				}
				
				file.Close()
			}

			// 定期清理
			accelerator.Cleanup()

			// 记录统计
			if stats, err := accelerator.GetStats(); err == nil {
				errors.LogDebug(ctx, "Freedom eBPF stats: total=", stats.TotalConnections,
					" active=", stats.ActiveConnections, " bytes_saved=", stats.BytesSaved)
			}
		}
	}
}