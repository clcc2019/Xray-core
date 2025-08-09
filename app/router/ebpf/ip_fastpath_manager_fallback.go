//go:build !linux

package ebpf

import (
	"net"
)

func EnableIPFastpath(enable bool)                          {}
func SetIPv4Mark(ip net.IP, mark uint32, ttlSeconds uint32) {}
func SetIPv6Mark(ip net.IP, mark uint32, ttlSeconds uint32) {}
