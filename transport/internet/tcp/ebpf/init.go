package ebpf

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

var (
	initOnce sync.Once
	initErr  error
)

// InitTCPRealityAccelerator 初始化TCP+REALITY eBPF加速器
func InitTCPRealityAccelerator() error {
	initOnce.Do(func() {
		ctx := context.Background()
		initErr = InitAccelerator(ctx)
		if initErr != nil {
			errors.LogWarning(ctx, "TCP REALITY eBPF accelerator initialization failed: ", initErr)
		} else {
			errors.LogInfo(ctx, "TCP REALITY eBPF accelerator initialized successfully")
		}
	})
	return initErr
}

// IsAcceleratorAvailable 检查加速器是否可用
func IsAcceleratorAvailable() bool {
	accelerator := GetGlobalAccelerator()
	return accelerator.IsEnabled()
}

// GetAcceleratorStatus 获取加速器状态
func GetAcceleratorStatus() map[string]interface{} {
	return GetAcceleratorInfo()
}

func init() {
	// 延迟初始化，避免在包加载时就尝试加载eBPF程序
	// 实际的初始化会在第一次调用时执行
}
