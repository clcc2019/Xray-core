package platform

import (
	"runtime"
)

// IsEBpfSupported 检查当前平台是否支持eBPF
func IsEBpfSupported() bool {
	// 只有Linux系统支持eBPF
	if runtime.GOOS != "linux" {
		return false
	}

	// 只支持AMD64架构
	if runtime.GOARCH != "amd64" {
		return false
	}

	// 检查内核版本
	return checkKernelVersion()
}

// IsLinuxServer 检查是否运行在Linux服务器上
func IsLinuxServer() bool {
	return runtime.GOOS == "linux"
}

// GetPlatformInfo 获取平台信息
func GetPlatformInfo() map[string]interface{} {
	info := make(map[string]interface{})

	info["os"] = runtime.GOOS
	info["arch"] = runtime.GOARCH
	info["ebpf_supported"] = IsEBpfSupported()
	info["linux_server"] = IsLinuxServer()

	if runtime.GOOS == "linux" {
		if version := getKernelVersion(); version != "" {
			info["kernel_version"] = version
		}
	}

	return info
}

// IsAndroid 检查是否运行在Android上
func IsAndroid() bool {
	return GetAndroidVersion() != ""
}

// GetAndroidVersion 获取Android版本（如果适用）
func GetAndroidVersion() string {
	// Android检测逻辑
	// 这里可以添加Android特定的检测代码
	return ""
}

// IsMacOS 检查是否运行在macOS上
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

// IsWindows 检查是否运行在Windows上
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// ShouldUseEBpf 根据平台和配置决定是否使用eBPF
func ShouldUseEBpf(forceDisable bool) bool {
	if forceDisable {
		return false
	}

	return IsEBpfSupported()
}
