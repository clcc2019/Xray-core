//go:build linux

package platform

import (
	"strconv"
	"strings"
	"syscall"
)

// checkKernelVersion 检查Linux内核版本是否支持eBPF
func checkKernelVersion() bool {
	version := getKernelVersionLinux()
	if version == "" {
		return false
	}

	// 解析版本号
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}

	// eBPF需要Linux 4.18+
	if major > 4 {
		return true
	}
	if major == 4 && minor >= 18 {
		return true
	}

	return false
}

// getKernelVersionLinux 获取Linux内核版本
func getKernelVersionLinux() string {
	var utsname syscall.Utsname
	err := syscall.Uname(&utsname)
	if err != nil {
		return ""
	}

	// 转换字节数组为字符串
	release := make([]byte, 0, len(utsname.Release))
	for _, b := range utsname.Release {
		if b == 0 {
			break
		}
		release = append(release, byte(b))
	}

	return string(release)
}

// getKernelVersion 获取内核版本（Linux实现）
func getKernelVersion() string {
	return getKernelVersionLinux()
}
