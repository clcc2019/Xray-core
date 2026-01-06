package encryption

import (
	"crypto/rand"
	"math"
	mrand "math/rand"
	"sync"
	"time"
)

// PaddingStrategy 定义 padding 策略接口
type PaddingStrategy interface {
	// GenerateLength 生成 padding 长度
	GenerateLength(minLen, maxLen int) int
	// GenerateDelay 生成延迟时间
	GenerateDelay(minMs, maxMs int) time.Duration
	// Name 返回策略名称
	Name() string
}

// paddingBufferPool padding 缓冲区池
var paddingBufferPool = sync.Pool{
	New: func() interface{} {
		// 预分配最大可能的 padding 大小
		return make([]byte, 65536)
	},
}

// AcquirePaddingBuffer 获取 padding 缓冲区
func AcquirePaddingBuffer(size int) []byte {
	buf := paddingBufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// ReleasePaddingBuffer 释放 padding 缓冲区
func ReleasePaddingBuffer(buf []byte) {
	if cap(buf) >= 65536 {
		paddingBufferPool.Put(buf[:cap(buf)])
	}
}

// ================================
// 1. 均匀分布策略（默认，兼容原实现）
// ================================

type UniformStrategy struct {
	rng *mrand.Rand
	mu  sync.Mutex
}

func NewUniformStrategy() *UniformStrategy {
	seed := make([]byte, 8)
	rand.Read(seed)
	return &UniformStrategy{
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
	}
}

func (s *UniformStrategy) GenerateLength(minLen, maxLen int) int {
	if maxLen <= minLen {
		return minLen
	}
	s.mu.Lock()
	n := minLen + s.rng.Intn(maxLen-minLen+1)
	s.mu.Unlock()
	return n
}

func (s *UniformStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}
	s.mu.Lock()
	n := minMs + s.rng.Intn(maxMs-minMs+1)
	s.mu.Unlock()
	return time.Duration(n) * time.Millisecond
}

func (s *UniformStrategy) Name() string { return "uniform" }

// ================================
// 2. 正态分布策略（更接近真实流量）
// ================================

type GaussianStrategy struct {
	rng *mrand.Rand
	mu  sync.Mutex
}

func NewGaussianStrategy() *GaussianStrategy {
	seed := make([]byte, 8)
	rand.Read(seed)
	return &GaussianStrategy{
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
	}
}

func (s *GaussianStrategy) GenerateLength(minLen, maxLen int) int {
	if maxLen <= minLen {
		return minLen
	}

	// 使用正态分布，均值在中间，标准差为范围的 1/6
	mean := float64(minLen+maxLen) / 2
	stddev := float64(maxLen-minLen) / 6

	s.mu.Lock()
	n := s.rng.NormFloat64()*stddev + mean
	s.mu.Unlock()

	// 钳制到范围内
	if n < float64(minLen) {
		n = float64(minLen)
	}
	if n > float64(maxLen) {
		n = float64(maxLen)
	}
	return int(n)
}

func (s *GaussianStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}

	mean := float64(minMs+maxMs) / 2
	stddev := float64(maxMs-minMs) / 6

	s.mu.Lock()
	n := s.rng.NormFloat64()*stddev + mean
	s.mu.Unlock()

	if n < float64(minMs) {
		n = float64(minMs)
	}
	if n > float64(maxMs) {
		n = float64(maxMs)
	}
	return time.Duration(n) * time.Millisecond
}

func (s *GaussianStrategy) Name() string { return "gaussian" }

// ================================
// 3. 指数分布策略（模拟网络延迟）
// ================================

type ExponentialStrategy struct {
	rng *mrand.Rand
	mu  sync.Mutex
}

func NewExponentialStrategy() *ExponentialStrategy {
	seed := make([]byte, 8)
	rand.Read(seed)
	return &ExponentialStrategy{
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
	}
}

func (s *ExponentialStrategy) GenerateLength(minLen, maxLen int) int {
	if maxLen <= minLen {
		return minLen
	}

	// 指数分布，大部分值靠近 minLen
	s.mu.Lock()
	u := s.rng.Float64()
	s.mu.Unlock()

	// 使用 CDF 反函数
	lambda := 3.0 / float64(maxLen-minLen) // 调整 lambda 使大部分落在前 1/3
	n := float64(minLen) - math.Log(1-u*(1-math.Exp(-lambda*float64(maxLen-minLen))))/lambda

	if n > float64(maxLen) {
		n = float64(maxLen)
	}
	return int(n)
}

func (s *ExponentialStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}

	s.mu.Lock()
	u := s.rng.Float64()
	s.mu.Unlock()

	lambda := 3.0 / float64(maxMs-minMs)
	n := float64(minMs) - math.Log(1-u*(1-math.Exp(-lambda*float64(maxMs-minMs))))/lambda

	if n > float64(maxMs) {
		n = float64(maxMs)
	}
	return time.Duration(n) * time.Millisecond
}

func (s *ExponentialStrategy) Name() string { return "exponential" }

// ================================
// 4. 帕累托分布策略（80/20 法则，模拟真实网络流量）
// ================================

type ParetoStrategy struct {
	rng   *mrand.Rand
	mu    sync.Mutex
	alpha float64 // 形状参数，典型值 1.16 (80/20) 到 2.0
}

func NewParetoStrategy(alpha float64) *ParetoStrategy {
	if alpha <= 1.0 {
		alpha = 1.16 // 默认 80/20 分布
	}
	seed := make([]byte, 8)
	rand.Read(seed)
	return &ParetoStrategy{
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
		alpha: alpha,
	}
}

func (s *ParetoStrategy) GenerateLength(minLen, maxLen int) int {
	if maxLen <= minLen {
		return minLen
	}

	s.mu.Lock()
	u := s.rng.Float64()
	s.mu.Unlock()

	// 帕累托分布：x = xm / u^(1/alpha)
	xm := float64(minLen)
	if xm < 1 {
		xm = 1
	}
	n := xm / math.Pow(u, 1/s.alpha)

	// 钳制到范围
	if n < float64(minLen) {
		n = float64(minLen)
	}
	if n > float64(maxLen) {
		n = float64(maxLen)
	}
	return int(n)
}

func (s *ParetoStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	return time.Duration(s.GenerateLength(minMs, maxMs)) * time.Millisecond
}

func (s *ParetoStrategy) Name() string { return "pareto" }

// ================================
// 5. 突发流量策略（模拟真实用户行为）
// ================================

type BurstStrategy struct {
	rng          *mrand.Rand
	mu           sync.Mutex
	burstProb    float64 // 突发概率
	burstMinMult float64 // 突发时最小倍数
	burstMaxMult float64 // 突发时最大倍数
}

func NewBurstStrategy(burstProb, burstMinMult, burstMaxMult float64) *BurstStrategy {
	if burstProb <= 0 || burstProb > 1 {
		burstProb = 0.2 // 20% 概率触发突发
	}
	if burstMinMult < 1 {
		burstMinMult = 2
	}
	if burstMaxMult < burstMinMult {
		burstMaxMult = 5
	}
	seed := make([]byte, 8)
	rand.Read(seed)
	return &BurstStrategy{
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
		burstProb:    burstProb,
		burstMinMult: burstMinMult,
		burstMaxMult: burstMaxMult,
	}
}

func (s *BurstStrategy) GenerateLength(minLen, maxLen int) int {
	if maxLen <= minLen {
		return minLen
	}

	s.mu.Lock()
	isBurst := s.rng.Float64() < s.burstProb
	base := minLen + s.rng.Intn(maxLen-minLen+1)

	if isBurst {
		mult := s.burstMinMult + s.rng.Float64()*(s.burstMaxMult-s.burstMinMult)
		base = int(float64(base) * mult)
	}
	s.mu.Unlock()

	if base > maxLen {
		base = maxLen
	}
	return base
}

func (s *BurstStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	if maxMs <= minMs {
		return time.Duration(minMs) * time.Millisecond
	}

	s.mu.Lock()
	// 突发模式下延迟很短，非突发模式延迟正常
	isBurst := s.rng.Float64() < s.burstProb
	var n int
	if isBurst {
		n = minMs // 突发时使用最小延迟
	} else {
		n = minMs + s.rng.Intn(maxMs-minMs+1)
	}
	s.mu.Unlock()
	return time.Duration(n) * time.Millisecond
}

func (s *BurstStrategy) Name() string { return "burst" }

// ================================
// 6. 混合策略（组合多种分布）
// ================================

type MixedStrategy struct {
	strategies []PaddingStrategy
	weights    []float64
	rng        *mrand.Rand
	mu         sync.Mutex
}

func NewMixedStrategy(strategies []PaddingStrategy, weights []float64) *MixedStrategy {
	if len(strategies) == 0 {
		strategies = []PaddingStrategy{
			NewGaussianStrategy(),
			NewExponentialStrategy(),
			NewBurstStrategy(0.15, 2, 4),
		}
		weights = []float64{0.5, 0.3, 0.2}
	}

	// 归一化权重
	total := 0.0
	for _, w := range weights {
		total += w
	}
	for i := range weights {
		weights[i] /= total
	}

	seed := make([]byte, 8)
	rand.Read(seed)
	return &MixedStrategy{
		strategies: strategies,
		weights:    weights,
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
	}
}

func (s *MixedStrategy) selectStrategy() PaddingStrategy {
	s.mu.Lock()
	r := s.rng.Float64()
	s.mu.Unlock()

	cumulative := 0.0
	for i, w := range s.weights {
		cumulative += w
		if r < cumulative {
			return s.strategies[i]
		}
	}
	return s.strategies[len(s.strategies)-1]
}

func (s *MixedStrategy) GenerateLength(minLen, maxLen int) int {
	return s.selectStrategy().GenerateLength(minLen, maxLen)
}

func (s *MixedStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	return s.selectStrategy().GenerateDelay(minMs, maxMs)
}

func (s *MixedStrategy) Name() string { return "mixed" }

// ================================
// 策略工厂
// ================================

var defaultStrategy PaddingStrategy
var defaultStrategyOnce sync.Once

// GetDefaultStrategy 获取默认策略
//
// 最优默认策略基于以下研究：
// 1. 真实 HTTPS 流量分析显示包大小呈双峰分布（小包 ACK + 大包数据）
// 2. 网络延迟呈对数正态分布（log-normal），类似指数但有更长的尾部
// 3. 用户行为具有突发性（阅读时静默，点击时突发）
// 4. 帕累托分布符合网络流量的 80/20 法则
//
// 权重设计：
// - 40% 对数正态分布：模拟真实网络延迟和包大小
// - 25% 帕累托分布：模拟 80/20 流量特征
// - 20% 突发策略：模拟用户点击行为
// - 15% 高斯分布：平滑过渡，增加随机性
func GetDefaultStrategy() PaddingStrategy {
	defaultStrategyOnce.Do(func() {
		defaultStrategy = NewOptimalStrategy()
	})
	return defaultStrategy
}

// OptimalStrategy 最优策略（基于真实流量特征研究）
type OptimalStrategy struct {
	logNormal *LogNormalStrategy
	pareto    *ParetoStrategy
	burst     *BurstStrategy
	gaussian  *GaussianStrategy
	rng       *mrand.Rand
	mu        sync.Mutex
}

// NewOptimalStrategy 创建最优策略
func NewOptimalStrategy() *OptimalStrategy {
	seed := make([]byte, 8)
	rand.Read(seed)
	return &OptimalStrategy{
		logNormal: NewLogNormalStrategy(0.5, 1.0), // mu=0.5, sigma=1.0 模拟网络延迟
		pareto:    NewParetoStrategy(1.16),        // alpha=1.16 (80/20 法则)
		burst:     NewBurstStrategy(0.15, 1.5, 3), // 15% 概率，1.5-3x 倍
		gaussian:  NewGaussianStrategy(),
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
	}
}

func (s *OptimalStrategy) GenerateLength(minLen, maxLen int) int {
	s.mu.Lock()
	r := s.rng.Float64()
	s.mu.Unlock()

	// 权重分配：40% log-normal, 25% pareto, 20% burst, 15% gaussian
	switch {
	case r < 0.40:
		return s.logNormal.GenerateLength(minLen, maxLen)
	case r < 0.65:
		return s.pareto.GenerateLength(minLen, maxLen)
	case r < 0.85:
		return s.burst.GenerateLength(minLen, maxLen)
	default:
		return s.gaussian.GenerateLength(minLen, maxLen)
	}
}

func (s *OptimalStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	s.mu.Lock()
	r := s.rng.Float64()
	s.mu.Unlock()

	// 延迟分布：50% log-normal（最接近真实网络延迟），30% exponential，20% burst
	switch {
	case r < 0.50:
		return s.logNormal.GenerateDelay(minMs, maxMs)
	case r < 0.80:
		// 指数分布延迟（短延迟为主）
		return s.pareto.GenerateDelay(minMs, maxMs)
	default:
		return s.burst.GenerateDelay(minMs, maxMs)
	}
}

func (s *OptimalStrategy) Name() string { return "optimal" }

// ================================
// 7. 对数正态分布策略（最接近真实网络延迟）
// ================================

// LogNormalStrategy 对数正态分布
// 研究表明网络延迟和包大小最接近对数正态分布
type LogNormalStrategy struct {
	rng   *mrand.Rand
	mu    sync.Mutex
	muVal float64 // 对数均值
	sigma float64 // 对数标准差
}

func NewLogNormalStrategy(mu, sigma float64) *LogNormalStrategy {
	if sigma <= 0 {
		sigma = 1.0
	}
	seed := make([]byte, 8)
	rand.Read(seed)
	return &LogNormalStrategy{
		rng: mrand.New(mrand.NewSource(int64(seed[0]) | int64(seed[1])<<8 |
			int64(seed[2])<<16 | int64(seed[3])<<24 |
			int64(seed[4])<<32 | int64(seed[5])<<40 |
			int64(seed[6])<<48 | int64(seed[7])<<56)),
		muVal: mu,
		sigma: sigma,
	}
}

func (s *LogNormalStrategy) GenerateLength(minLen, maxLen int) int {
	if maxLen <= minLen {
		return minLen
	}

	s.mu.Lock()
	// 生成对数正态分布：exp(mu + sigma * Z)，Z 是标准正态
	z := s.rng.NormFloat64()
	s.mu.Unlock()

	// 对数正态值，缩放到范围内
	logNormalVal := math.Exp(s.muVal + s.sigma*z)

	// 归一化到 [0, 1] 范围（使用 CDF 近似）
	// 对数正态的大部分值在 exp(mu - 2*sigma) 到 exp(mu + 2*sigma) 之间
	minVal := math.Exp(s.muVal - 2*s.sigma)
	maxVal := math.Exp(s.muVal + 2*s.sigma)
	normalized := (logNormalVal - minVal) / (maxVal - minVal)

	// 钳制到 [0, 1]
	if normalized < 0 {
		normalized = 0
	}
	if normalized > 1 {
		normalized = 1
	}

	return minLen + int(normalized*float64(maxLen-minLen))
}

func (s *LogNormalStrategy) GenerateDelay(minMs, maxMs int) time.Duration {
	return time.Duration(s.GenerateLength(minMs, maxMs)) * time.Millisecond
}

func (s *LogNormalStrategy) Name() string { return "lognormal" }

// NewPaddingStrategy 根据名称创建策略
func NewPaddingStrategy(name string) PaddingStrategy {
	switch name {
	case "uniform":
		return NewUniformStrategy()
	case "gaussian", "normal":
		return NewGaussianStrategy()
	case "exponential", "exp":
		return NewExponentialStrategy()
	case "pareto":
		return NewParetoStrategy(1.16)
	case "burst":
		return NewBurstStrategy(0.2, 2, 5)
	case "lognormal", "log-normal":
		return NewLogNormalStrategy(0.5, 1.0)
	case "mixed":
		return NewMixedStrategy(nil, nil)
	case "optimal", "":
		return GetDefaultStrategy() // 默认使用最优策略
	default:
		return NewUniformStrategy()
	}
}

// ================================
// 优化后的 Padding 生成函数
// ================================

// OptimizedCreatPadding 优化后的 padding 创建函数
func OptimizedCreatPadding(paddingLens, paddingGaps [][3]int, strategy PaddingStrategy) (length int, lens []int, gaps []time.Duration) {
	if strategy == nil {
		strategy = GetDefaultStrategy()
	}

	if len(paddingLens) == 0 {
		paddingLens = [][3]int{{100, 111, 1111}, {50, 0, 3333}}
		paddingGaps = [][3]int{{75, 0, 111}}
	}

	for _, y := range paddingLens {
		l := 0
		// 使用策略决定是否添加这段 padding
		prob := strategy.GenerateLength(0, 100)
		if y[0] >= prob {
			l = strategy.GenerateLength(y[1], y[2])
		}
		lens = append(lens, l)
		length += l
	}

	for _, y := range paddingGaps {
		g := time.Duration(0)
		prob := strategy.GenerateLength(0, 100)
		if y[0] >= prob {
			g = strategy.GenerateDelay(y[1], y[2])
		}
		gaps = append(gaps, g)
	}
	return
}

// FillRandomPadding 高效填充随机 padding 数据
func FillRandomPadding(buf []byte) {
	// 使用快速随机填充
	// 对于 padding，不需要加密级别随机性，使用更快的方法
	if len(buf) == 0 {
		return
	}

	// 使用 8 字节作为种子，然后用简单的 PRNG 填充
	var seed [8]byte
	rand.Read(seed[:])

	state := uint64(seed[0]) | uint64(seed[1])<<8 |
		uint64(seed[2])<<16 | uint64(seed[3])<<24 |
		uint64(seed[4])<<32 | uint64(seed[5])<<40 |
		uint64(seed[6])<<48 | uint64(seed[7])<<56

	// xorshift64* PRNG - 非常快
	for i := 0; i < len(buf); i += 8 {
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		state *= 0x2545F4914F6CDD1D

		remaining := len(buf) - i
		if remaining >= 8 {
			buf[i] = byte(state)
			buf[i+1] = byte(state >> 8)
			buf[i+2] = byte(state >> 16)
			buf[i+3] = byte(state >> 24)
			buf[i+4] = byte(state >> 32)
			buf[i+5] = byte(state >> 40)
			buf[i+6] = byte(state >> 48)
			buf[i+7] = byte(state >> 56)
		} else {
			for j := 0; j < remaining; j++ {
				buf[i+j] = byte(state >> (j * 8))
			}
		}
	}
}
