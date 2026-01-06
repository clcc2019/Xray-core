package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"math/rand"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	utls "github.com/refraction-networking/utls"
	proxyman "github.com/xtls/xray-core/app/proxyman/outbound"
	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"github.com/xtls/xray-core/proxy/vless/encryption"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
	"github.com/xtls/xray-core/transport/pipe"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*Config))
	}))
}

// Handler is an outbound connection handler for VLess protocol.
type Handler struct {
	server        *protocol.ServerSpec
	policyManager policy.Manager
	cone          bool
	encryption    *encryption.ClientInstance
	reverse       *Reverse

	testpre uint32
	initpre sync.Once
	pool    *ConnectionPool
}

// ConnectionPool 管理预连接池
type ConnectionPool struct {
	conns     chan *PooledConn // 连接缓冲通道
	dialer    internet.Dialer  // 连接器
	dest      net.Destination  // 目标地址
	closed    atomic.Bool      // 是否已关闭
	workers   int              // 工作协程数
	minConns  int              // 最小连接数
	maxConns  int              // 最大连接数
	expireMin time.Duration    // 最小过期时间
	expireMax time.Duration    // 最大过期时间
	retryMin  time.Duration    // 最小重试间隔
	retryMax  time.Duration    // 最大重试间隔

	// 统计指标
	totalCreated    atomic.Int64 // 总创建连接数
	totalReused     atomic.Int64 // 总复用连接数
	totalExpired    atomic.Int64 // 总过期连接数
	totalFailed     atomic.Int64 // 总失败连接数
	currentConns    atomic.Int32 // 当前池中连接数
	consecutiveFail atomic.Int32 // 连续失败次数
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

// PoolConfig 连接池配置
type PoolConfig struct {
	Workers   int           // 预连接工作协程数
	MinConns  int           // 最小预连接数
	MaxConns  int           // 最大预连接数（缓冲区大小）
	ExpireMin time.Duration // 最小过期时间
	ExpireMax time.Duration // 最大过期时间
	RetryMin  time.Duration // 最小重试间隔
	RetryMax  time.Duration // 最大重试间隔
}

// DefaultPoolConfig 返回默认连接池配置
func DefaultPoolConfig(workers uint32) PoolConfig {
	w := int(workers)
	if w <= 0 {
		w = 2
	}
	return PoolConfig{
		Workers:   w,
		MinConns:  w,     // 至少保持 workers 数量的连接
		MaxConns:  w * 4, // 最多缓存 workers*4 个连接
		ExpireMin: 90 * time.Second,
		ExpireMax: 150 * time.Second,
		RetryMin:  100 * time.Millisecond,
		RetryMax:  500 * time.Millisecond,
	}
}

// NewConnectionPool 创建新的连接池
func NewConnectionPool(dialer internet.Dialer, dest net.Destination, config PoolConfig) *ConnectionPool {
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
		select {
		case <-ticker.C:
			p.cleanExpired()
		}
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
		errors.LogDebug(context.Background(), "cleaned ", cleaned, " expired connections")
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
func (p *ConnectionPool) Stats() (created, reused, expired, failed int64, current int32) {
	return p.totalCreated.Load(),
		p.totalReused.Load(),
		p.totalExpired.Load(),
		p.totalFailed.Load(),
		p.currentConns.Load()
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

// New creates a new VLess outbound handler.
func New(ctx context.Context, config *Config) (*Handler, error) {
	if config.Vnext == nil {
		return nil, errors.New(`no vnext found`)
	}
	server, err := protocol.NewServerSpecFromPB(config.Vnext)
	if err != nil {
		return nil, errors.New("failed to get server spec").Base(err).AtError()
	}

	v := core.MustFromContext(ctx)
	handler := &Handler{
		server:        server,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
		cone:          ctx.Value("cone").(bool),
	}

	a := handler.server.User.Account.(*vless.MemoryAccount)
	if a.Encryption != "" && a.Encryption != "none" {
		s := strings.Split(a.Encryption, ".")
		var nfsPKeysBytes [][]byte
		for _, r := range s {
			b, _ := base64.RawURLEncoding.DecodeString(r)
			nfsPKeysBytes = append(nfsPKeysBytes, b)
		}
		handler.encryption = &encryption.ClientInstance{}
		if err := handler.encryption.Init(nfsPKeysBytes, a.XorMode, a.Seconds, a.Padding); err != nil {
			return nil, errors.New("failed to use encryption").Base(err).AtError()
		}
	}

	if a.Reverse != nil {
		handler.reverse = &Reverse{
			tag:        a.Reverse.Tag,
			dispatcher: v.GetFeature(routing.DispatcherType()).(routing.Dispatcher),
			ctx: session.ContextWithInbound(ctx, &session.Inbound{
				Tag:  a.Reverse.Tag,
				User: handler.server.User, // TODO: email
			}),
			handler: handler,
		}
		handler.reverse.monitorTask = &task.Periodic{
			Execute:  handler.reverse.monitor,
			Interval: time.Second * 2,
		}
		go func() {
			time.Sleep(2 * time.Second)
			handler.reverse.Start()
		}()
	}

	handler.testpre = a.Testpre

	return handler, nil
}

// initPool 初始化连接池（延迟初始化）
func (h *Handler) initPool(dialer internet.Dialer) {
	h.initpre.Do(func() {
		config := DefaultPoolConfig(h.testpre)
		h.pool = NewConnectionPool(dialer, h.server.Destination, config)
		errors.LogInfo(context.Background(), "initialized connection pool with ", config.Workers, " workers")
	})
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	if h.pool != nil {
		h.pool.Close()
	}
	if h.reverse != nil {
		return h.reverse.Close()
	}
	return nil
}

// Process implements proxy.Outbound.Process().
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() && ob.Target.Address.String() != "v1.rvs.cool" {
		return errors.New("target not specified").AtError()
	}
	ob.Name = "vless"

	rec := h.server
	var conn stat.Connection
	var err error

	// 使用优化后的连接池
	if h.testpre > 0 && h.reverse == nil {
		h.initPool(dialer)

		// 从连接池获取连接，设置超时
		poolCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err = h.pool.Get(poolCtx)
		cancel()

		if err != nil {
			errors.LogWarningInner(ctx, err, "failed to get connection from pool, falling back to direct dial")
			conn = nil
		}
	}

	// 如果连接池没有可用连接，直接建立连接
	if conn == nil {
		if err := retry.ExponentialBackoff(5, 200).On(func() error {
			var err error
			conn, err = dialer.Dial(ctx, rec.Destination)
			if err != nil {
				return err
			}
			return nil
		}); err != nil {
			return errors.New("failed to find an available destination").Base(err).AtWarning()
		}
	}
	defer conn.Close()

	ob.Conn = conn // for Vision's pre-connect

	iConn := stat.TryUnwrapStatsConn(conn)
	target := ob.Target
	errors.LogInfo(ctx, "tunneling request to ", target, " via ", rec.Destination.NetAddr())

	if h.encryption != nil {
		var err error
		if conn, err = h.encryption.Handshake(conn); err != nil {
			return errors.New("ML-KEM-768 handshake failed").Base(err).AtInfo()
		}
	}

	command := protocol.RequestCommandTCP
	if target.Network == net.Network_UDP {
		command = protocol.RequestCommandUDP
	}
	if target.Address.Family().IsDomain() {
		switch target.Address.Domain() {
		case "v1.mux.cool":
			command = protocol.RequestCommandMux
		case "v1.rvs.cool":
			if target.Network != net.Network_Unknown {
				return errors.New("nice try baby").AtError()
			}
			command = protocol.RequestCommandRvs
		}
	}

	request := &protocol.RequestHeader{
		Version: encoding.Version,
		User:    rec.User,
		Command: command,
		Address: target.Address,
		Port:    target.Port,
	}

	account := request.User.Account.(*vless.MemoryAccount)

	requestAddons := &encoding.Addons{
		Flow: account.Flow,
	}

	var input *bytes.Reader
	var rawInput *bytes.Buffer
	allowUDP443 := false
	switch requestAddons.Flow {
	case vless.XRV + "-udp443":
		allowUDP443 = true
		requestAddons.Flow = requestAddons.Flow[:16]
		fallthrough
	case vless.XRV:
		ob.CanSpliceCopy = 2
		switch request.Command {
		case protocol.RequestCommandUDP:
			if !allowUDP443 && request.Port == 443 {
				return errors.New("XTLS rejected UDP/443 traffic").AtInfo()
			}
		case protocol.RequestCommandMux:
			fallthrough // let server break Mux connections that contain TCP requests
		case protocol.RequestCommandTCP, protocol.RequestCommandRvs:
			var t reflect.Type
			var p uintptr
			if commonConn, ok := conn.(*encryption.CommonConn); ok {
				if _, ok := commonConn.Conn.(*encryption.XorConn); ok || !proxy.IsRAWTransportWithoutSecurity(iConn) {
					ob.CanSpliceCopy = 3 // full-random xorConn / non-RAW transport / another securityConn should not be penetrated
				}
				t = reflect.TypeOf(commonConn).Elem()
				p = uintptr(unsafe.Pointer(commonConn))
			} else if tlsConn, ok := iConn.(*tls.Conn); ok {
				t = reflect.TypeOf(tlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(tlsConn.Conn))
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				t = reflect.TypeOf(utlsConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(utlsConn.Conn))
			} else if realityConn, ok := iConn.(*reality.UConn); ok {
				t = reflect.TypeOf(realityConn.Conn).Elem()
				p = uintptr(unsafe.Pointer(realityConn.Conn))
			} else {
				return errors.New("XTLS only supports TLS and REALITY directly for now.").AtWarning()
			}
			i, _ := t.FieldByName("input")
			r, _ := t.FieldByName("rawInput")
			input = (*bytes.Reader)(unsafe.Pointer(p + i.Offset))
			rawInput = (*bytes.Buffer)(unsafe.Pointer(p + r.Offset))
		default:
			panic("unknown VLESS request command")
		}
	default:
		ob.CanSpliceCopy = 3
	}

	var newCtx context.Context
	var newCancel context.CancelFunc
	if session.TimeoutOnlyFromContext(ctx) {
		newCtx, newCancel = context.WithCancel(context.Background())
	}

	sessionPolicy := h.policyManager.ForLevel(request.User.Level)
	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, func() {
		cancel()
		if newCancel != nil {
			newCancel()
		}
	}, sessionPolicy.Timeouts.ConnectionIdle)

	clientReader := link.Reader // .(*pipe.Reader)
	clientWriter := link.Writer // .(*pipe.Writer)
	trafficState := proxy.NewTrafficState(account.ID.Bytes())
	if request.Command == protocol.RequestCommandUDP && (requestAddons.Flow == vless.XRV || (h.cone && request.Port != 53 && request.Port != 443)) {
		request.Command = protocol.RequestCommandMux
		request.Address = net.DomainAddress("v1.mux.cool")
		request.Port = net.Port(666)
	}

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
		if err := encoding.EncodeRequestHeader(bufferWriter, request, requestAddons); err != nil {
			return errors.New("failed to encode request header").Base(err).AtWarning()
		}

		// default: serverWriter := bufferWriter
		serverWriter := encoding.EncodeBodyAddons(bufferWriter, request, requestAddons, trafficState, true, ctx, conn, ob)
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			serverWriter = xudp.NewPacketWriter(serverWriter, target, xudp.GetGlobalID(ctx))
		}
		timeoutReader, ok := clientReader.(buf.TimeoutReader)
		if ok {
			multiBuffer, err1 := timeoutReader.ReadMultiBufferTimeout(time.Millisecond * 500)
			if err1 == nil {
				if err := serverWriter.WriteMultiBuffer(multiBuffer); err != nil {
					return err // ...
				}
			} else if err1 != buf.ErrReadTimeout {
				return err1
			} else if requestAddons.Flow == vless.XRV {
				mb := make(buf.MultiBuffer, 1)
				errors.LogInfo(ctx, "Insert padding with empty content to camouflage VLESS header ", mb.Len())
				if err := serverWriter.WriteMultiBuffer(mb); err != nil {
					return err // ...
				}
			}
		} else {
			errors.LogDebug(ctx, "Reader is not timeout reader, will send out vless header separately from first payload")
		}
		// Flush; bufferWriter.WriteMultiBuffer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return errors.New("failed to write A request payload").Base(err).AtWarning()
		}

		if requestAddons.Flow == vless.XRV {
			if tlsConn, ok := iConn.(*tls.Conn); ok {
				if tlsConn.ConnectionState().Version != gotls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, tlsConn.ConnectionState().Version).AtWarning()
				}
			} else if utlsConn, ok := iConn.(*tls.UConn); ok {
				if utlsConn.ConnectionState().Version != utls.VersionTLS13 {
					return errors.New(`failed to use `+requestAddons.Flow+`, found outer tls version `, utlsConn.ConnectionState().Version).AtWarning()
				}
			}
		}
		err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer))
		if err != nil {
			return errors.New("failed to transfer request payload").Base(err).AtInfo()
		}

		// Indicates the end of request payload.
		switch requestAddons.Flow {
		default:
		}
		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons, err := encoding.DecodeResponseHeader(conn, request)
		if err != nil {
			return errors.New("failed to decode response header").Base(err).AtInfo()
		}

		// default: serverReader := buf.NewReader(conn)
		serverReader := encoding.DecodeBodyAddons(conn, request, responseAddons)
		if requestAddons.Flow == vless.XRV {
			serverReader = proxy.NewVisionReader(serverReader, trafficState, false, ctx, conn, input, rawInput, ob)
		}
		if request.Command == protocol.RequestCommandMux && request.Port == 666 {
			if requestAddons.Flow == vless.XRV {
				serverReader = xudp.NewPacketReader(&buf.BufferedReader{Reader: serverReader})
			} else {
				serverReader = xudp.NewPacketReader(conn)
			}
		}

		if requestAddons.Flow == vless.XRV {
			err = encoding.XtlsRead(serverReader, clientWriter, timer, conn, trafficState, false, ctx)
		} else {
			// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBuffer
			err = buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer))
		}

		if err != nil {
			return errors.New("failed to transfer response payload").Base(err).AtInfo()
		}

		return nil
	}

	if newCtx != nil {
		ctx = newCtx
	}

	if err := task.Run(ctx, postRequest, task.OnSuccess(getResponse, task.Close(clientWriter))); err != nil {
		return errors.New("connection ends").Base(err).AtInfo()
	}

	return nil
}

type Reverse struct {
	tag         string
	dispatcher  routing.Dispatcher
	ctx         context.Context
	handler     *Handler
	workers     []*reverse.BridgeWorker
	monitorTask *task.Periodic
}

func (r *Reverse) monitor() error {
	var activeWorkers []*reverse.BridgeWorker
	for _, w := range r.workers {
		if w.IsActive() {
			activeWorkers = append(activeWorkers, w)
		}
	}
	if len(activeWorkers) != len(r.workers) {
		r.workers = activeWorkers
	}

	var numConnections uint32
	var numWorker uint32
	for _, w := range r.workers {
		if w.IsActive() {
			numConnections += w.Connections()
			numWorker++
		}
	}
	if numWorker == 0 || numConnections/numWorker > 16 {
		reader1, writer1 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		reader2, writer2 := pipe.New(pipe.WithSizeLimit(2 * buf.Size))
		link1 := &transport.Link{Reader: reader1, Writer: writer2}
		link2 := &transport.Link{Reader: reader2, Writer: writer1}
		w := &reverse.BridgeWorker{
			Tag:        r.tag,
			Dispatcher: r.dispatcher,
		}
		worker, err := mux.NewServerWorker(session.ContextWithIsReverseMux(r.ctx, true), w, link1)
		if err != nil {
			errors.LogWarningInner(r.ctx, err, "failed to create mux server worker")
			return nil
		}
		w.Worker = worker
		r.workers = append(r.workers, w)
		go func() {
			ctx := session.ContextWithOutbounds(r.ctx, []*session.Outbound{{
				Target: net.Destination{Address: net.DomainAddress("v1.rvs.cool")},
			}})
			r.handler.Process(ctx, link2, session.FullHandlerFromContext(ctx).(*proxyman.Handler))
			common.Interrupt(reader1)
			common.Interrupt(reader2)
		}()
	}
	return nil
}

func (r *Reverse) Start() error {
	return r.monitorTask.Start()
}

func (r *Reverse) Close() error {
	return r.monitorTask.Close()
}
