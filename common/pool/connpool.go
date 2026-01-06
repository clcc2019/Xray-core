// Package pool provides connection pooling for outbound proxies.
package pool

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Dialer 是连接拨号接口
type Dialer interface {
	Dial(ctx context.Context, dest net.Destination) (stat.Connection, error)
}

// PooledConn 表示池中的连接
type PooledConn struct {
	Conn      stat.Connection
	Expire    time.Time
	CreatedAt time.Time
}

// pooledConnPool 用于池化 PooledConn 结构体
var pooledConnPool = sync.Pool{
	New: func() interface{} {
		return &PooledConn{}
	},
}

func acquirePooledConn(conn stat.Connection, expire time.Time) *PooledConn {
	pc := pooledConnPool.Get().(*PooledConn)
	pc.Conn = conn
	pc.Expire = expire
	pc.CreatedAt = time.Now()
	return pc
}

func releasePooledConn(pc *PooledConn) {
	if pc == nil {
		return
	}
	pc.Conn = nil
	pc.Expire = time.Time{}
	pc.CreatedAt = time.Time{}
	pooledConnPool.Put(pc)
}

// Config 连接池配置
type Config struct {
	Workers   int           // 预连接工作协程数
	MinConns  int           // 最小预连接数
	MaxConns  int           // 最大预连接数（缓冲区大小）
	ExpireMin time.Duration // 最小过期时间
	ExpireMax time.Duration // 最大过期时间
	RetryMin  time.Duration // 最小重试间隔
	RetryMax  time.Duration // 最大重试间隔
}

// DefaultConfig 返回默认连接池配置
func DefaultConfig(workers int) Config {
	if workers <= 0 {
		workers = 2
	}
	return Config{
		Workers:   workers,
		MinConns:  workers,     // 至少保持 workers 数量的连接
		MaxConns:  workers * 4, // 最多缓存 workers*4 个连接
		ExpireMin: 90 * time.Second,
		ExpireMax: 150 * time.Second,
		RetryMin:  100 * time.Millisecond,
		RetryMax:  500 * time.Millisecond,
	}
}

// ConnectionPool 管理预连接池
type ConnectionPool struct {
	conns    chan *PooledConn // 连接缓冲通道
	dialer   Dialer           // 连接器
	dest     net.Destination  // 目标地址
	closed   atomic.Bool      // 是否已关闭
	workers  int              // 工作协程数
	minConns int              // 最小连接数
	maxConns int              // 最大连接数

	expireMin time.Duration // 最小过期时间
	expireMax time.Duration // 最大过期时间
	retryMin  time.Duration // 最小重试间隔
	retryMax  time.Duration // 最大重试间隔

	// 统计指标
	totalCreated    atomic.Int64 // 总创建连接数
	totalReused     atomic.Int64 // 总复用连接数
	totalExpired    atomic.Int64 // 总过期连接数
	totalFailed     atomic.Int64 // 总失败连接数
	currentConns    atomic.Int32 // 当前池中连接数
	consecutiveFail atomic.Int32 // 连续失败次数
}

// Stats 连接池统计信息
type Stats struct {
	Created int64
	Reused  int64
	Expired int64
	Failed  int64
	Current int32
}

// New 创建新的连接池
func New(dialer Dialer, dest net.Destination, config Config) *ConnectionPool {
	pool := &ConnectionPool{
		conns:     make(chan *PooledConn, config.MaxConns),
		dialer:    dialer,
		dest:      dest,
		workers:   config.Workers,
		minConns:  config.MinConns,
		maxConns:  config.MaxConns,
		expireMin: config.ExpireMin,
		expireMax: config.ExpireMax,
		retryMin:  config.RetryMin,
		retryMax:  config.RetryMax,
	}

	// 启动预连接工作协程
	for i := 0; i < config.Workers; i++ {
		go pool.worker(i)
	}

	// 启动清理协程
	go pool.cleaner()

	return pool
}

// NewWithDialer 使用标准 internet.Dialer 创建连接池
func NewWithDialer(dialer internet.Dialer, dest net.Destination, config Config) *ConnectionPool {
	return New(&internetDialerWrapper{dialer}, dest, config)
}

// internetDialerWrapper 包装 internet.Dialer
type internetDialerWrapper struct {
	dialer internet.Dialer
}

func (w *internetDialerWrapper) Dial(ctx context.Context, dest net.Destination) (stat.Connection, error) {
	return w.dialer.Dial(ctx, dest)
}

// worker 预连接工作协程
func (p *ConnectionPool) worker(id int) {
	defer func() {
		if r := recover(); r != nil {
			// 如果 worker panic，延迟重启
			time.Sleep(time.Second)
			if !p.closed.Load() {
				go p.worker(id)
			}
		}
	}()

	ctx := xctx.ContextWithID(context.Background(), session.NewID())

	for !p.closed.Load() {
		// 检查是否需要创建新连接
		currentCount := p.currentConns.Load()
		if int(currentCount) >= p.maxConns {
			// 池已满，等待一段时间
			time.Sleep(p.randomDuration(p.retryMin, p.retryMax))
			continue
		}

		// 创建新连接
		conn, err := p.dialer.Dial(ctx, p.dest)
		if err != nil {
			p.totalFailed.Add(1)
			failCount := p.consecutiveFail.Add(1)

			// 指数退避：连续失败次数越多，等待越长
			backoff := p.calculateBackoff(failCount)
			errors.LogWarningInner(ctx, err, "pre-connect failed, retry after ", backoff)
			time.Sleep(backoff)
			continue
		}

		// 重置连续失败计数
		p.consecutiveFail.Store(0)
		p.totalCreated.Add(1)

		// 计算随机过期时间
		expire := time.Now().Add(p.randomDuration(p.expireMin, p.expireMax))
		pc := acquirePooledConn(conn, expire)

		// 尝试放入池中
		select {
		case p.conns <- pc:
			p.currentConns.Add(1)
		default:
			// 池已满，关闭连接
			conn.Close()
			releasePooledConn(pc)
		}

		// 随机延迟，避免所有 worker 同时创建连接
		time.Sleep(p.randomDuration(p.retryMin, p.retryMax))
	}
}

// cleaner 清理过期连接
func (p *ConnectionPool) cleaner() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for !p.closed.Load() {
		<-ticker.C
		p.cleanExpired()
	}
}

// cleanExpired 清理过期的连接
func (p *ConnectionPool) cleanExpired() {
	// 快速检查，避免不必要的操作
	if p.currentConns.Load() == 0 {
		return
	}

	now := time.Now()
	cleaned := 0

	// 非阻塞地检查所有连接
	for i := 0; i < int(p.currentConns.Load()); i++ {
		select {
		case pc := <-p.conns:
			if pc == nil {
				continue
			}

			if now.After(pc.Expire) {
				// 连接已过期
				pc.Conn.Close()
				releasePooledConn(pc)
				p.currentConns.Add(-1)
				p.totalExpired.Add(1)
				cleaned++
			} else {
				// 放回池中
				select {
				case p.conns <- pc:
				default:
					// 池满了，关闭连接
					pc.Conn.Close()
					releasePooledConn(pc)
					p.currentConns.Add(-1)
				}
			}
		default:
			// 没有更多连接可检查
			return
		}
	}

	if cleaned > 0 {
		errors.LogDebug(context.Background(), "cleaned ", cleaned, " expired connections from pool")
	}
}

// Get 获取一个可用的连接
func (p *ConnectionPool) Get(ctx context.Context) (stat.Connection, error) {
	if p.closed.Load() {
		return nil, errors.New("connection pool closed")
	}

	now := time.Now()

	// 首先尝试从池中获取
	for {
		select {
		case pc := <-p.conns:
			if pc == nil {
				return nil, errors.New("connection pool closed")
			}
			p.currentConns.Add(-1)

			// 检查是否过期
			if now.After(pc.Expire) {
				pc.Conn.Close()
				releasePooledConn(pc)
				p.totalExpired.Add(1)
				continue // 继续尝试获取下一个
			}

			// 检查连接健康状态（通过尝试设置deadline）
			if err := pc.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				pc.Conn.Close()
				releasePooledConn(pc)
				continue
			}

			conn := pc.Conn
			releasePooledConn(pc)
			p.totalReused.Add(1)
			return conn, nil

		case <-ctx.Done():
			return nil, ctx.Err()

		default:
			// 池为空，需要新建连接
			return p.dialNew(ctx)
		}
	}
}

// TryGet 尝试从池中获取连接（非阻塞）
func (p *ConnectionPool) TryGet() (stat.Connection, bool) {
	if p.closed.Load() {
		return nil, false
	}

	now := time.Now()

	for {
		select {
		case pc := <-p.conns:
			if pc == nil {
				return nil, false
			}
			p.currentConns.Add(-1)

			// 检查是否过期
			if now.After(pc.Expire) {
				pc.Conn.Close()
				releasePooledConn(pc)
				p.totalExpired.Add(1)
				continue
			}

			// 检查连接健康状态
			if err := pc.Conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				pc.Conn.Close()
				releasePooledConn(pc)
				continue
			}

			conn := pc.Conn
			releasePooledConn(pc)
			p.totalReused.Add(1)
			return conn, true

		default:
			return nil, false
		}
	}
}

// dialNew 创建新连接（池为空时使用）
func (p *ConnectionPool) dialNew(ctx context.Context) (stat.Connection, error) {
	return p.dialer.Dial(ctx, p.dest)
}

// Close 关闭连接池
func (p *ConnectionPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	// 关闭通道
	close(p.conns)

	// 清理所有连接
	for pc := range p.conns {
		if pc != nil && pc.Conn != nil {
			pc.Conn.Close()
			releasePooledConn(pc)
		}
	}

	return nil
}

// Stats 返回连接池统计信息
func (p *ConnectionPool) Stats() Stats {
	return Stats{
		Created: p.totalCreated.Load(),
		Reused:  p.totalReused.Load(),
		Expired: p.totalExpired.Load(),
		Failed:  p.totalFailed.Load(),
		Current: p.currentConns.Load(),
	}
}

// Size 返回当前池中连接数
func (p *ConnectionPool) Size() int {
	return int(p.currentConns.Load())
}

// IsClosed 返回连接池是否已关闭
func (p *ConnectionPool) IsClosed() bool {
	return p.closed.Load()
}

// randomDuration 生成 min 和 max 之间的随机时间
func (p *ConnectionPool) randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	return min + time.Duration(rand.Int63n(int64(max-min)))
}

// calculateBackoff 计算退避时间
func (p *ConnectionPool) calculateBackoff(failCount int32) time.Duration {
	// 指数退避，最大 30 秒
	backoff := p.retryMin * time.Duration(1<<uint(failCount-1))
	maxBackoff := 30 * time.Second
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	// 添加抖动
	jitter := time.Duration(rand.Int63n(int64(backoff / 4)))
	return backoff + jitter
}
