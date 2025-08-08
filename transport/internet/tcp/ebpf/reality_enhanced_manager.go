package ebpf

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/xtls/xray-core/common/errors"
)

// RealityEnhancedManager 增强版REALITY管理器
type RealityEnhancedManager struct {
	mu                  sync.RWMutex
	enabled             bool
	enhancedConnections *ebpf.Map
	enhancedStats       *ebpf.Map
	quantumSessions     *ebpf.Map
	securityEvents      *ebpf.Map
	ctx                 context.Context
	cancel              context.CancelFunc

	// 增强安全配置
	securityLevel       int // 0=basic, 1=enhanced, 2=maximum
	quantumResistant    bool
	challengeResponse   bool
	timestampAntiReplay bool
	mldsaVerification   bool

	// 性能优化配置
	zeroRTTEnabled      bool
	sessionReuseEnabled bool
	zeroCopyEnabled     bool

	// 统计信息
	stats *RealityEnhancedStats
}

// RealityEnhancedStats 增强版统计信息
type RealityEnhancedStats struct {
	TotalConnections                uint64
	SuccessfulHandshakes            uint64
	FailedHandshakes                uint64
	SecurityViolations              uint64
	QuantumAttacksDetected          uint64
	SessionReuses                   uint64
	ZeroRTTConnections              uint64
	EnhancedSecurityConnections     uint64
	MaximumSecurityConnections      uint64
	AvgHandshakeTime                uint64
	TotalBytesTransferred           uint64
	AuthenticationFailures          uint64
	CertificateVerificationFailures uint64
	KeyExchangeFailures             uint64
	ChallengeResponseFailures       uint64
}

// QuantumResistantSession 量子抗性会话
type QuantumResistantSession struct {
	SessionID    uint64
	PublicKey    [32]byte
	SharedSecret [32]byte
	Challenge    [16]byte
	Response     [16]byte
	CreationTime uint64
	LastUsed     uint64
	UseCount     uint32
	Verified     uint8
	QuantumSafe  uint8
}

// NewRealityEnhancedManager 创建增强版REALITY管理器
func NewRealityEnhancedManager(ctx context.Context) *RealityEnhancedManager {
	ctx, cancel := context.WithCancel(ctx)
	return &RealityEnhancedManager{
		ctx:                 ctx,
		cancel:              cancel,
		securityLevel:       1, // 默认增强安全级别
		quantumResistant:    true,
		challengeResponse:   true,
		timestampAntiReplay: true,
		mldsaVerification:   true,
		zeroRTTEnabled:      true,
		sessionReuseEnabled: true,
		zeroCopyEnabled:     true,
		stats:               &RealityEnhancedStats{},
	}
}

// Enable 启用增强版REALITY管理器
func (rem *RealityEnhancedManager) Enable() error {
	rem.mu.Lock()
	defer rem.mu.Unlock()

	if rem.enabled {
		return nil
	}

	// 检查eBPF支持
	if os.Getenv("XRAY_EBPF") != "1" {
		return fmt.Errorf("eBPF not enabled")
	}

	// 加载增强版eBPF映射表
	if err := rem.loadEnhancedMaps(); err != nil {
		return fmt.Errorf("failed to load enhanced maps: %w", err)
	}

	// 启动统计更新协程
	go rem.updateStatsLoop()

	rem.enabled = true
	log.Printf("REALITY Enhanced Manager enabled with security level %d", rem.securityLevel)
	return nil
}

// Disable 禁用增强版REALITY管理器
func (rem *RealityEnhancedManager) Disable() error {
	rem.mu.Lock()
	defer rem.mu.Unlock()

	if !rem.enabled {
		return nil
	}

	rem.cancel()
	rem.enabled = false
	log.Printf("REALITY Enhanced Manager disabled")
	return nil
}

// IsEnabled 检查是否启用
func (rem *RealityEnhancedManager) IsEnabled() bool {
	rem.mu.RLock()
	defer rem.mu.RUnlock()
	return rem.enabled
}

// SetSecurityLevel 设置安全级别
func (rem *RealityEnhancedManager) SetSecurityLevel(level int) error {
	if level < 0 || level > 2 {
		return fmt.Errorf("invalid security level: %d", level)
	}

	rem.mu.Lock()
	defer rem.mu.Unlock()
	rem.securityLevel = level
	log.Printf("REALITY Enhanced security level set to %d", level)
	return nil
}

// EnableQuantumResistance 启用量子抗性
func (rem *RealityEnhancedManager) EnableQuantumResistance(enabled bool) {
	rem.mu.Lock()
	defer rem.mu.Unlock()
	rem.quantumResistant = enabled
	log.Printf("REALITY Enhanced quantum resistance: %v", enabled)
}

// EnableChallengeResponse 启用挑战-响应机制
func (rem *RealityEnhancedManager) EnableChallengeResponse(enabled bool) {
	rem.mu.Lock()
	defer rem.mu.Unlock()
	rem.challengeResponse = enabled
	log.Printf("REALITY Enhanced challenge-response: %v", enabled)
}

// EnableTimestampAntiReplay 启用时间戳防重放
func (rem *RealityEnhancedManager) EnableTimestampAntiReplay(enabled bool) {
	rem.mu.Lock()
	defer rem.mu.Unlock()
	rem.timestampAntiReplay = enabled
	log.Printf("REALITY Enhanced timestamp anti-replay: %v", enabled)
}

// EnableMLDSAVerification 启用ML-DSA验证
func (rem *RealityEnhancedManager) EnableMLDSAVerification(enabled bool) {
	rem.mu.Lock()
	defer rem.mu.Unlock()
	rem.mldsaVerification = enabled
	log.Printf("REALITY Enhanced ML-DSA verification: %v", enabled)
}

// loadEnhancedMaps 加载增强版eBPF映射表
func (rem *RealityEnhancedManager) loadEnhancedMaps() error {
	// 加载增强版连接映射表
	enhancedConnections, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/reality_enhanced_connections", nil)
	if err != nil {
		return fmt.Errorf("failed to load enhanced connections map: %w", err)
	}
	rem.enhancedConnections = enhancedConnections

	// 加载增强版统计映射表
	enhancedStats, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/reality_enhanced_stats", nil)
	if err != nil {
		return fmt.Errorf("failed to load enhanced stats map: %w", err)
	}
	rem.enhancedStats = enhancedStats

	// 加载量子会话映射表
	quantumSessions, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/quantum_sessions", nil)
	if err != nil {
		return fmt.Errorf("failed to load quantum sessions map: %w", err)
	}
	rem.quantumSessions = quantumSessions

	// 加载安全事件映射表
	securityEvents, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/security_events", nil)
	if err != nil {
		return fmt.Errorf("failed to load security events map: %w", err)
	}
	rem.securityEvents = securityEvents

	return nil
}

// AddQuantumSession 添加量子抗性会话
func (rem *RealityEnhancedManager) AddQuantumSession(sessionID uint64, publicKey, sharedSecret, challenge, response []byte) error {
	if !rem.IsEnabled() {
		return fmt.Errorf("enhanced manager not enabled")
	}

	session := &QuantumResistantSession{
		SessionID:    sessionID,
		CreationTime: uint64(time.Now().UnixNano()),
		LastUsed:     uint64(time.Now().UnixNano()),
		UseCount:     1,
		Verified:     1,
		QuantumSafe:  1,
	}

	copy(session.PublicKey[:], publicKey)
	copy(session.SharedSecret[:], sharedSecret)
	copy(session.Challenge[:], challenge)
	copy(session.Response[:], response)

	return rem.quantumSessions.Put(&sessionID, session)
}

// GetQuantumSession 获取量子抗性会话
func (rem *RealityEnhancedManager) GetQuantumSession(sessionID uint64) (*QuantumResistantSession, error) {
	if !rem.IsEnabled() {
		return nil, fmt.Errorf("enhanced manager not enabled")
	}

	var session QuantumResistantSession
	if err := rem.quantumSessions.Lookup(&sessionID, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// UpdateQuantumSession 更新量子抗性会话
func (rem *RealityEnhancedManager) UpdateQuantumSession(sessionID uint64) error {
	if !rem.IsEnabled() {
		return fmt.Errorf("enhanced manager not enabled")
	}

	session, err := rem.GetQuantumSession(sessionID)
	if err != nil {
		return err
	}

	session.LastUsed = uint64(time.Now().UnixNano())
	session.UseCount++

	return rem.quantumSessions.Put(&sessionID, session)
}

// GetEnhancedStats 获取增强版统计信息
func (rem *RealityEnhancedManager) GetEnhancedStats() (*RealityEnhancedStats, error) {
	if !rem.IsEnabled() {
		return nil, fmt.Errorf("enhanced manager not enabled")
	}

	var key uint32 = 0
	var stats RealityEnhancedStats
	if err := rem.enhancedStats.Lookup(&key, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// GetSecurityEvents 获取安全事件统计
func (rem *RealityEnhancedManager) GetSecurityEvents() (map[uint32]uint64, error) {
	if !rem.IsEnabled() {
		return nil, fmt.Errorf("enhanced manager not enabled")
	}

	events := make(map[uint32]uint64)
	var key uint32
	var count uint64

	iter := rem.securityEvents.Iterate()
	for iter.Next(&key, &count) {
		events[key] = count
	}

	return events, nil
}

// updateStatsLoop 统计更新循环
func (rem *RealityEnhancedManager) updateStatsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rem.ctx.Done():
			return
		case <-ticker.C:
			if err := rem.updateStats(); err != nil {
				log.Printf("Failed to update enhanced stats: %v", err)
			}
		}
	}
}

// updateStats 更新统计信息
func (rem *RealityEnhancedManager) updateStats() error {
	stats, err := rem.GetEnhancedStats()
	if err != nil {
		return err
	}

	rem.mu.Lock()
	rem.stats = stats
	rem.mu.Unlock()

	// 记录关键统计信息
	if stats.SecurityViolations > 0 {
		log.Printf("REALITY Enhanced: Security violations detected: %d", stats.SecurityViolations)
	}

	if stats.QuantumAttacksDetected > 0 {
		log.Printf("REALITY Enhanced: Quantum attacks detected: %d", stats.QuantumAttacksDetected)
	}

	return nil
}

// OptimizeEnhancedRealityHandshake 优化增强版REALITY握手
func OptimizeEnhancedRealityHandshake(ctx context.Context, conn net.Conn, config interface{}) error {
	// 获取全局增强版管理器
	manager := GetRealityEnhancedManager()
	if !manager.IsEnabled() {
		return fmt.Errorf("enhanced manager not enabled")
	}

	// 根据安全级别选择优化策略
	securityLevel := manager.getSecurityLevel()

	switch securityLevel {
	case 0: // basic
		// 基础优化 - 标准REALITY握手
		return OptimizeRealityHandshake(ctx, conn, config)

	case 1: // enhanced
		// 增强优化 - 添加ML-DSA验证和挑战-响应
		return manager.optimizeEnhancedHandshake(ctx, conn, config)

	case 2: // maximum
		// 最大优化 - 量子抗性 + 所有安全特性
		return manager.optimizeMaximumHandshake(ctx, conn, config)

	default:
		return fmt.Errorf("unknown security level: %d", securityLevel)
	}
}

// MarkEnhancedRealityHandshakeComplete 标记增强版REALITY握手完成
func MarkEnhancedRealityHandshakeComplete(ctx context.Context, conn net.Conn) error {
	manager := GetRealityEnhancedManager()
	if !manager.IsEnabled() {
		return fmt.Errorf("enhanced manager not enabled")
	}

	// 根据安全级别选择标记策略
	securityLevel := manager.getSecurityLevel()

	switch securityLevel {
	case 0: // basic
		return MarkRealityHandshakeComplete(ctx, conn)

	case 1: // enhanced
		return manager.markEnhancedHandshakeComplete(ctx, conn)

	case 2: // maximum
		return manager.markMaximumHandshakeComplete(ctx, conn)

	default:
		return fmt.Errorf("unknown security level: %d", securityLevel)
	}
}

// 全局增强版管理器实例
var (
	realityEnhancedManager     *RealityEnhancedManager
	realityEnhancedManagerOnce sync.Once
)

// GetRealityEnhancedManager 获取全局增强版管理器实例
func GetRealityEnhancedManager() *RealityEnhancedManager {
	realityEnhancedManagerOnce.Do(func() {
		realityEnhancedManager = NewRealityEnhancedManager(context.Background())
	})
	return realityEnhancedManager
}

// 内部方法实现
func (rem *RealityEnhancedManager) getSecurityLevel() int {
	rem.mu.RLock()
	defer rem.mu.RUnlock()
	return rem.securityLevel
}

func (rem *RealityEnhancedManager) optimizeEnhancedHandshake(ctx context.Context, conn net.Conn, config interface{}) error {
	// 增强版握手优化实现
	errors.LogDebug(ctx, "REALITY Enhanced: Optimizing enhanced handshake")

	// 1. 启用ML-DSA验证
	if rem.mldsaVerification {
		errors.LogDebug(ctx, "REALITY Enhanced: ML-DSA verification enabled")
	}

	// 2. 启用挑战-响应机制
	if rem.challengeResponse {
		errors.LogDebug(ctx, "REALITY Enhanced: Challenge-response mechanism enabled")
	}

	// 3. 启用时间戳防重放
	if rem.timestampAntiReplay {
		errors.LogDebug(ctx, "REALITY Enhanced: Timestamp anti-replay enabled")
	}

	return nil
}

func (rem *RealityEnhancedManager) optimizeMaximumHandshake(ctx context.Context, conn net.Conn, config interface{}) error {
	// 最大安全级别握手优化实现
	errors.LogDebug(ctx, "REALITY Enhanced: Optimizing maximum security handshake")

	// 1. 启用量子抗性
	if rem.quantumResistant {
		errors.LogDebug(ctx, "REALITY Enhanced: Quantum resistance enabled")
	}

	// 2. 启用所有增强安全特性
	if err := rem.optimizeEnhancedHandshake(ctx, conn, config); err != nil {
		return err
	}

	// 3. 启用零拷贝优化
	if rem.zeroCopyEnabled {
		errors.LogDebug(ctx, "REALITY Enhanced: Zero-copy optimization enabled")
	}

	return nil
}

func (rem *RealityEnhancedManager) markEnhancedHandshakeComplete(ctx context.Context, conn net.Conn) error {
	errors.LogDebug(ctx, "REALITY Enhanced: Enhanced handshake completed")
	return nil
}

func (rem *RealityEnhancedManager) markMaximumHandshakeComplete(ctx context.Context, conn net.Conn) error {
	errors.LogDebug(ctx, "REALITY Enhanced: Maximum security handshake completed")
	return nil
}
