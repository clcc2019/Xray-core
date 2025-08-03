//go:build !linux

package ebpf

import (
	"net"
)

// ProxyAcceleratorCilium Cilium版本的fallback实现
type ProxyAcceleratorCilium struct{}

// GetProxyAccelerator 返回Cilium版本的fallback实现
func GetProxyAccelerator() *ProxyAcceleratorCilium {
	return &ProxyAcceleratorCilium{}
}

// Fallback实现 - 所有方法都是no-op
func (p *ProxyAcceleratorCilium) IsEnabled() bool { return false }
func (p *ProxyAcceleratorCilium) Init() error { return nil }
func (p *ProxyAcceleratorCilium) RegisterConnection(srcIP, dstIP net.IP, srcPort, dstPort uint16, proxyType uint8) error { return nil }
func (p *ProxyAcceleratorCilium) EnableSplice(conn net.Conn) error { return nil }
func (p *ProxyAcceleratorCilium) EnableTLSOptimization(conn net.Conn, sni string) error { return nil }
func (p *ProxyAcceleratorCilium) GetConnectionCount() int { return 0 }
func (p *ProxyAcceleratorCilium) RecordBytes(conn net.Conn, bytes int64) {}
func (p *ProxyAcceleratorCilium) Cleanup() {}
func (p *ProxyAcceleratorCilium) Close() error { return nil }