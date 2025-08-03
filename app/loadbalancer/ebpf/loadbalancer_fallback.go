package ebpf

import (
	"sync"
	"sync/atomic"
)

// LoadBalancer fallback实现
type LoadBalancer struct {
	backends []Backend
	counter  uint64
	mu       sync.RWMutex
}

// Backend 后端服务器信息
type Backend struct {
	IP     string
	Port   uint16
	Weight uint16
	Active bool
}

// NewLoadBalancer 创建负载均衡器
func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		backends: make([]Backend, 0),
	}
}

// AddBackend 添加后端服务器
func (lb *LoadBalancer) AddBackend(ip string, port uint16, weight uint16) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.backends = append(lb.backends, Backend{
		IP:     ip,
		Port:   port,
		Weight: weight,
		Active: true,
	})
}

// GetNextBackend 获取下一个后端服务器（轮询）
func (lb *LoadBalancer) GetNextBackend() *Backend {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if len(lb.backends) == 0 {
		return nil
	}

	// 只选择活跃的后端
	activeBackends := make([]Backend, 0)
	for _, backend := range lb.backends {
		if backend.Active {
			activeBackends = append(activeBackends, backend)
		}
	}

	if len(activeBackends) == 0 {
		return nil
	}

	// 轮询选择
	index := atomic.AddUint64(&lb.counter, 1) % uint64(len(activeBackends))
	return &activeBackends[index]
}

// SetBackendStatus 设置后端状态
func (lb *LoadBalancer) SetBackendStatus(ip string, port uint16, active bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i := range lb.backends {
		if lb.backends[i].IP == ip && lb.backends[i].Port == port {
			lb.backends[i].Active = active
			break
		}
	}
}

// GetStats 获取统计信息
func (lb *LoadBalancer) GetStats() map[string]interface{} {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_backends"] = len(lb.backends)

	activeCount := 0
	for _, backend := range lb.backends {
		if backend.Active {
			activeCount++
		}
	}
	stats["active_backends"] = activeCount
	stats["requests_served"] = atomic.LoadUint64(&lb.counter)
	stats["mode"] = "fallback"

	return stats
}

// IsEnabled 检查是否启用eBPF
func (lb *LoadBalancer) IsEnabled() bool {
	return false // fallback实现始终返回false
}

// Close 关闭负载均衡器
func (lb *LoadBalancer) Close() error {
	return nil // fallback实现无需清理
}
