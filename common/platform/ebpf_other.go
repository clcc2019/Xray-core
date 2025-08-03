//go:build !linux

package platform

// checkKernelVersion 检查内核版本（非Linux平台始终返回false）
func checkKernelVersion() bool {
	return false
}

// getKernelVersion 获取内核版本（非Linux平台返回空字符串）
func getKernelVersion() string {
	return ""
}
