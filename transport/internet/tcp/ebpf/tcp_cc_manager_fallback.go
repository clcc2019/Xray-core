//go:build !linux

package ebpf

// InitDefaultTCPCCPolicy is a no-op on non-Linux platforms.
func InitDefaultTCPCCPolicy() error { return nil }


