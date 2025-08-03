package reality

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
)

// 目标域名握手加速机制
// 🎯 通过连接池、预连接、DNS缓存等方式加速目标域名握手

// TargetAccelerator 目标域名加速器
type TargetAccelerator struct {
	mu              sync.RWMutex
	connectionPools map[string]*ConnectionPool
	dnsCache        map[string]*DNSCacheEntry
	preConnections  map[string]*PreConnection
	config          *AccelerationConfig
}

// AccelerationConfig 加速配置
type AccelerationConfig struct {
	EnableConnectionPool bool          `json:"enable_connection_pool"`
	EnablePreConnection  bool          `json:"enable_pre_connection"`
	EnableDNSCache       bool          `json:"enable_dns_cache"`
	MaxPoolSize          int           `json:"max_pool_size"`
	MaxPreConnections    int           `json:"max_pre_connections"`
	DNSCacheTTL          time.Duration `json:"dns_cache_ttl"`
	PreConnectionTTL     time.Duration `json:"pre_connection_ttl"`
	ConnectionTimeout    time.Duration `json:"connection_timeout"`
	HealthCheckInterval  time.Duration `json:"health_check_interval"`
}

// ConnectionPool 连接池
type ConnectionPool struct {
	mu          sync.Mutex
	target      string
	connections chan net.Conn
	maxSize     int
	currentSize int
	lastUsed    time.Time
	healthCheck *time.Ticker
}

// DNSCacheEntry DNS缓存条目
type DNSCacheEntry struct {
	Addresses []net.IP      `json:"addresses"`
	CreatedAt time.Time     `json:"created_at"`
	TTL       time.Duration `json:"ttl"`
	UseCount  int           `json:"use_count"`
}

// PreConnection 预连接
type PreConnection struct {
	Target     string    `json:"target"`
	Connection net.Conn  `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	LastCheck  time.Time `json:"last_check"`
	Healthy    bool      `json:"healthy"`
	UseCount   int       `json:"use_count"`
}

// 全局目标域名加速器
var globalTargetAccelerator *TargetAccelerator

// init 初始化目标域名加速器
func init() {
	config := &AccelerationConfig{
		EnableConnectionPool: true,
		EnablePreConnection:  true,
		EnableDNSCache:       true,
		MaxPoolSize:          10,
		MaxPreConnections:    5,
		DNSCacheTTL:          5 * time.Minute,
		PreConnectionTTL:     30 * time.Second,
		ConnectionTimeout:    10 * time.Second,
		HealthCheckInterval:  60 * time.Second,
	}

	globalTargetAccelerator = &TargetAccelerator{
		connectionPools: make(map[string]*ConnectionPool),
		dnsCache:        make(map[string]*DNSCacheEntry),
		preConnections:  make(map[string]*PreConnection),
		config:          config,
	}

	// 启动后台清理任务
	go globalTargetAccelerator.startBackgroundTasks()
}

// GetGlobalTargetAccelerator 获取全局目标域名加速器
func GetGlobalTargetAccelerator() *TargetAccelerator {
	return globalTargetAccelerator
}

// AccelerateTargetDial 加速目标域名拨号
func (ta *TargetAccelerator) AccelerateTargetDial(ctx context.Context, dest xnet.Destination) (net.Conn, error) {
	target := dest.NetAddr()

	// 🚀 尝试从连接池获取现有连接
	if ta.config.EnableConnectionPool {
		if conn := ta.getFromPool(target); conn != nil {
			errors.LogDebug(ctx, "🏊 Using connection from pool for target: ", target)
			return conn, nil
		}
	}

	// 🎯 尝试使用预连接
	if ta.config.EnablePreConnection {
		if conn := ta.getPreConnection(target); conn != nil {
			errors.LogDebug(ctx, "⚡ Using pre-connection for target: ", target)
			return conn, nil
		}
	}

	// 📡 使用DNS缓存加速解析
	var netDialer net.Dialer
	if ta.config.EnableDNSCache {
		if ips := ta.getCachedIPs(dest.Address.String()); len(ips) > 0 {
			// 使用缓存的IP直接连接
			for _, ip := range ips {
				addr := &net.TCPAddr{
					IP:   ip,
					Port: int(dest.Port),
				}

				ctx, cancel := context.WithTimeout(ctx, ta.config.ConnectionTimeout)
				conn, err := netDialer.DialContext(ctx, "tcp", addr.String())
				cancel()

				if err == nil {
					errors.LogDebug(ctx, "🚀 DNS cache accelerated connection to: ", target)
					// 将连接放入池中供后续使用
					ta.addToPool(target, conn)
					return conn, nil
				}
			}
		}
	}

	// 🔄 常规拨号并缓存结果
	ctx, cancel := context.WithTimeout(ctx, ta.config.ConnectionTimeout)
	defer cancel()

	conn, err := netDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, errors.New("Failed to dial target").Base(err)
	}

	// 🗄️ 缓存DNS解析结果
	if ta.config.EnableDNSCache {
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			ta.cacheDNSResult(dest.Address.String(), []net.IP{tcpAddr.IP})
		}
	}

	// 🏊 将连接放入池中
	if ta.config.EnableConnectionPool {
		ta.addToPool(target, conn)
	}

	// 🎯 创建预连接
	if ta.config.EnablePreConnection {
		go ta.createPreConnection(target)
	}

	return conn, nil
}

// getFromPool 从连接池获取连接
func (ta *TargetAccelerator) getFromPool(target string) net.Conn {
	ta.mu.RLock()
	pool, exists := ta.connectionPools[target]
	ta.mu.RUnlock()

	if !exists {
		return nil
	}

	pool.mu.Lock()
	defer pool.mu.Unlock()

	select {
	case conn := <-pool.connections:
		pool.currentSize--
		pool.lastUsed = time.Now()

		// 检查连接是否仍然有效
		if ta.isConnectionHealthy(conn) {
			return conn
		}
		// 连接无效，关闭并继续
		conn.Close()
		return nil
	default:
		return nil
	}
}

// addToPool 将连接添加到池中
func (ta *TargetAccelerator) addToPool(target string, conn net.Conn) {
	if !ta.config.EnableConnectionPool {
		return
	}

	ta.mu.Lock()
	pool, exists := ta.connectionPools[target]
	if !exists {
		pool = &ConnectionPool{
			target:      target,
			connections: make(chan net.Conn, ta.config.MaxPoolSize),
			maxSize:     ta.config.MaxPoolSize,
			currentSize: 0,
			lastUsed:    time.Now(),
		}
		ta.connectionPools[target] = pool

		// 启动健康检查
		pool.healthCheck = time.NewTicker(ta.config.HealthCheckInterval)
		go ta.poolHealthCheck(pool)
	}
	ta.mu.Unlock()

	pool.mu.Lock()
	defer pool.mu.Unlock()

	if pool.currentSize < pool.maxSize {
		select {
		case pool.connections <- conn:
			pool.currentSize++
		default:
			// 池满了，关闭连接
			conn.Close()
		}
	} else {
		conn.Close()
	}
}

// getPreConnection 获取预连接
func (ta *TargetAccelerator) getPreConnection(target string) net.Conn {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	preConn, exists := ta.preConnections[target]
	if !exists || !preConn.Healthy {
		return nil
	}

	// 检查预连接是否过期
	if time.Since(preConn.CreatedAt) > ta.config.PreConnectionTTL {
		preConn.Connection.Close()
		delete(ta.preConnections, target)
		return nil
	}

	conn := preConn.Connection
	preConn.UseCount++
	delete(ta.preConnections, target) // 使用后移除

	return conn
}

// createPreConnection 创建预连接
func (ta *TargetAccelerator) createPreConnection(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), ta.config.ConnectionTimeout)
	defer cancel()

	var netDialer net.Dialer
	conn, err := netDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}

	preConn := &PreConnection{
		Target:     target,
		Connection: conn,
		CreatedAt:  time.Now(),
		LastCheck:  time.Now(),
		Healthy:    true,
		UseCount:   0,
	}

	ta.mu.Lock()
	// 检查是否已经有预连接
	if _, exists := ta.preConnections[target]; !exists {
		ta.preConnections[target] = preConn
	} else {
		// 已有预连接，关闭新的
		conn.Close()
	}
	ta.mu.Unlock()
}

// getCachedIPs 获取缓存的IP地址
func (ta *TargetAccelerator) getCachedIPs(domain string) []net.IP {
	ta.mu.RLock()
	entry, exists := ta.dnsCache[domain]
	ta.mu.RUnlock()

	if !exists {
		return nil
	}

	// 检查缓存是否过期
	if time.Since(entry.CreatedAt) > entry.TTL {
		ta.mu.Lock()
		delete(ta.dnsCache, domain)
		ta.mu.Unlock()
		return nil
	}

	entry.UseCount++
	return entry.Addresses
}

// cacheDNSResult 缓存DNS解析结果
func (ta *TargetAccelerator) cacheDNSResult(domain string, ips []net.IP) {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	ta.dnsCache[domain] = &DNSCacheEntry{
		Addresses: ips,
		CreatedAt: time.Now(),
		TTL:       ta.config.DNSCacheTTL,
		UseCount:  0,
	}
}

// isConnectionHealthy 检查连接是否健康
func (ta *TargetAccelerator) isConnectionHealthy(conn net.Conn) bool {
	// 简单的健康检查：设置读取超时
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	// 尝试读取0字节，检查连接状态
	_, err := conn.Read(make([]byte, 0))
	return err == nil
}

// poolHealthCheck 连接池健康检查
func (ta *TargetAccelerator) poolHealthCheck(pool *ConnectionPool) {
	defer pool.healthCheck.Stop()

	for range pool.healthCheck.C {
		pool.mu.Lock()

		// 检查池中的所有连接
		healthyConns := make([]net.Conn, 0, pool.currentSize)

		for i := 0; i < pool.currentSize; i++ {
			select {
			case conn := <-pool.connections:
				if ta.isConnectionHealthy(conn) {
					healthyConns = append(healthyConns, conn)
				} else {
					conn.Close()
				}
			default:
				// No more connections in pool
			}
		}

		// 将健康的连接放回池中
		pool.currentSize = 0
		for _, conn := range healthyConns {
			select {
			case pool.connections <- conn:
				pool.currentSize++
			default:
				conn.Close()
			}
		}

		pool.mu.Unlock()
	}
}

// startBackgroundTasks 启动后台清理任务
func (ta *TargetAccelerator) startBackgroundTasks() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ta.cleanup()
	}
}

// cleanup 清理过期的缓存和连接
func (ta *TargetAccelerator) cleanup() {
	ta.mu.Lock()
	defer ta.mu.Unlock()

	now := time.Now()

	// 清理DNS缓存
	for domain, entry := range ta.dnsCache {
		if now.Sub(entry.CreatedAt) > entry.TTL {
			delete(ta.dnsCache, domain)
		}
	}

	// 清理预连接
	for target, preConn := range ta.preConnections {
		if now.Sub(preConn.CreatedAt) > ta.config.PreConnectionTTL {
			preConn.Connection.Close()
			delete(ta.preConnections, target)
		}
	}

	// 清理不活跃的连接池
	for target, pool := range ta.connectionPools {
		if now.Sub(pool.lastUsed) > 10*time.Minute {
			pool.mu.Lock()
			// 关闭池中的所有连接
			for i := 0; i < pool.currentSize; i++ {
				select {
				case conn := <-pool.connections:
					conn.Close()
				default:
					// Pool is empty
				}
			}
			pool.mu.Unlock()

			pool.healthCheck.Stop()
			delete(ta.connectionPools, target)
		}
	}
}
