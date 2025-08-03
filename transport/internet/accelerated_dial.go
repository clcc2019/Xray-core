package internet

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/ebpf"
)

// DialSystemWithEBPF 带eBPF加速的系统拨号
func DialSystemWithEBPF(ctx context.Context, dest xnet.Destination, sockopt *SocketConfig) (net.Conn, error) {
	// 首先尝试标准拨号
	conn, err := DialSystem(ctx, dest, sockopt)
	if err != nil {
		return nil, err
	}

	// 尝试eBPF加速优化
	accelerator := ebpf.GetGlobalAccelerator()
	if accelerator != nil {
		if optimizedConn, accelerated := accelerator.OptimizeConnection(conn, dest); accelerated {
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Debug,
				Content:  "Connection accelerated with eBPF: " + dest.String(),
			})
			return optimizedConn, nil
		}
	}

	return conn, nil
}

// ListenSystemWithEBPF 带eBPF加速的系统监听
func ListenSystemWithEBPF(ctx context.Context, addr xnet.Addr, sockopt *SocketConfig) (net.Listener, error) {
	// 标准监听
	listener, err := ListenSystem(ctx, addr, sockopt)
	if err != nil {
		return nil, err
	}

	// 如果eBPF启用，返回加速监听器
	accelerator := ebpf.GetGlobalAccelerator()
	if accelerator != nil {
		return &AcceleratedListener{
			Listener:    listener,
			accelerator: accelerator,
		}, nil
	}

	return listener, nil
}

// AcceleratedListener eBPF加速监听器
type AcceleratedListener struct {
	net.Listener
	accelerator *ebpf.XrayAccelerator
}

// Accept 接受连接并尝试eBPF优化
func (al *AcceleratedListener) Accept() (net.Conn, error) {
	conn, err := al.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// 记录连接以供学习
	if al.accelerator != nil {
		// 这里可以记录入站连接模式，但暂时简化处理
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Debug,
			Content:  "Accepted connection from: " + conn.RemoteAddr().String(),
		})
	}

	return conn, nil
}

// InitializeEBPFAccelerator 初始化eBPF加速器
// 在Xray启动时调用
func InitializeEBPFAccelerator() error {
	accelerator := ebpf.GetGlobalAccelerator()
	return accelerator.Start()
}

// ShutdownEBPFAccelerator 关闭eBPF加速器
// 在Xray关闭时调用
func ShutdownEBPFAccelerator() error {
	accelerator := ebpf.GetGlobalAccelerator()
	return accelerator.Stop()
}
