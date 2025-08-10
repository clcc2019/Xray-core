//go:build !linux

package ebpf

import (
	"net"
	"strconv"
	"strings"
)

// ProxyAcceleratorCilium Cilium版本的fallback实现
type ProxyAcceleratorCilium struct{}

// GetProxyAccelerator 返回Cilium版本的fallback实现
func GetProxyAccelerator() *ProxyAcceleratorCilium {
	return &ProxyAcceleratorCilium{}
}

// Fallback实现 - 所有方法都是no-op
func (p *ProxyAcceleratorCilium) IsEnabled() bool { return false }
func (p *ProxyAcceleratorCilium) Init() error     { return nil }
func (p *ProxyAcceleratorCilium) RegisterConnection(srcIP, dstIP net.IP, srcPort, dstPort uint16, proxyType uint8) error {
	return nil
}
func (p *ProxyAcceleratorCilium) EnableSplice(conn net.Conn) error                      { return nil }
func (p *ProxyAcceleratorCilium) EnableTLSOptimization(conn net.Conn, sni string) error { return nil }
func (p *ProxyAcceleratorCilium) GetConnectionCount() int                               { return 0 }
func (p *ProxyAcceleratorCilium) RecordBytes(conn net.Conn, bytes int64)                {}
func (p *ProxyAcceleratorCilium) Cleanup()                                              {}
func (p *ProxyAcceleratorCilium) Close() error                                          { return nil }

// Degrade-list helpers (fallback: lightweight string checks only)
func ShouldDegradeFor(sni string, port int) bool {
	if s := strings.TrimSpace(sni); s != "" {
		if matchDegradeSNI(s) {
			return true
		}
	}
	if port > 0 {
		if matchDegradePort(port) {
			return true
		}
	}
	return false
}

func matchDegradeSNI(sni string) bool {
	sni = strings.ToLower(strings.TrimSpace(sni))
	if v := strings.TrimSpace(getenv("XRAY_EBPF_DEGRADE_SNI")); v != "" {
		for _, item := range strings.Split(v, ",") {
			it := strings.ToLower(strings.TrimSpace(item))
			if it == "" {
				continue
			}
			if strings.HasPrefix(it, "*.") {
				suf := strings.TrimPrefix(it, "*")
				if strings.HasSuffix(sni, suf) {
					return true
				}
			} else if it == sni {
				return true
			}
		}
	}
	return false
}

func matchDegradePort(port int) bool {
	if v := strings.TrimSpace(getenv("XRAY_EBPF_DEGRADE_PORTS")); v != "" {
		for _, item := range strings.Split(v, ",") {
			it := strings.TrimSpace(item)
			if it == "" {
				continue
			}
			if n, err := strconv.Atoi(it); err == nil && n == port {
				return true
			}
		}
	}
	return false
}

func getenv(k string) string { return "" }
