package reality

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/hkdf"
)

// REALITY 0-RTT 配置和缓存管理
// 🚀 实现REALITY专用的0-RTT机制，保持防检测特性

// ZeroRTTSessionCache REALITY 0-RTT会话缓存
type ZeroRTTSessionCache struct {
	mu       sync.RWMutex
	sessions map[string]*ZeroRTTSession
	maxAge   time.Duration
	maxSize  int
}

// ZeroRTTSession REALITY 0-RTT会话信息
type ZeroRTTSession struct {
	// 🔒 会话安全信息
	ServerName  string  `json:"server_name"`
	ShortId     [8]byte `json:"short_id"`
	AuthKey     []byte  `json:"auth_key"`     // 原始认证密钥
	PSK         []byte  `json:"psk"`          // 派生的PSK
	EarlySecret []byte  `json:"early_secret"` // Early Data密钥
	TicketNonce []byte  `json:"ticket_nonce"` // 防重放nonce

	// ⏰ 时间和使用信息
	CreatedAt    time.Time `json:"created_at"`
	LastUsed     time.Time `json:"last_used"`
	UseCount     int       `json:"use_count"`
	MaxEarlyData uint32    `json:"max_early_data"` // 最大Early Data大小

	// 🎯 目标域名信息
	RealTarget string   `json:"real_target"` // 真实目标地址
	SNI        string   `json:"sni"`         // 用于伪装的SNI
	ALPN       []string `json:"alpn"`        // 协商的ALPN

	// 📊 性能优化信息
	RTT          time.Duration `json:"rtt"`           // 记录的RTT
	Success      bool          `json:"success"`       // 上次是否成功
	FailureCount int           `json:"failure_count"` // 连续失败次数
}

// NewZeroRTTSessionCache 创建0-RTT会话缓存
func NewZeroRTTSessionCache() *ZeroRTTSessionCache {
	return &ZeroRTTSessionCache{
		sessions: make(map[string]*ZeroRTTSession),
		maxAge:   24 * time.Hour, // 24小时过期
		maxSize:  1000,           // 最多缓存1000个会话
	}
}

// 全局0-RTT会话缓存
var globalZeroRTTCache = NewZeroRTTSessionCache()

// GetZeroRTTSession 获取0-RTT会话
func (c *ZeroRTTSessionCache) GetZeroRTTSession(serverName, shortId string) *ZeroRTTSession {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 使用strings.Builder避免栈溢出
	var keyBuilder strings.Builder
	keyBuilder.WriteString(serverName)
	keyBuilder.WriteString(":")
	keyBuilder.WriteString(shortId)
	key := keyBuilder.String()

	session, exists := c.sessions[key]
	if !exists {
		return nil
	}

	// 检查会话是否过期
	if time.Since(session.CreatedAt) > c.maxAge {
		delete(c.sessions, key)
		return nil
	}

	// 检查连续失败次数
	if session.FailureCount > 3 {
		return nil // 暂时不使用失败的会话
	}

	return session
}

// StoreZeroRTTSession 存储0-RTT会话
func (c *ZeroRTTSessionCache) StoreZeroRTTSession(session *ZeroRTTSession) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查缓存大小限制
	if len(c.sessions) >= c.maxSize {
		c.evictOldestSession()
	}

	// 使用strings.Builder避免栈溢出
	var keyBuilder strings.Builder
	keyBuilder.WriteString(session.ServerName)
	keyBuilder.WriteString(":")
	keyBuilder.Write(session.ShortId[:])
	key := keyBuilder.String()

	c.sessions[key] = session

	return nil
}

// DeriveZeroRTTKeys 从REALITY AuthKey派生0-RTT密钥
func DeriveZeroRTTKeys(authKey []byte, serverName string, shortId [8]byte) (*ZeroRTTSession, error) {
	// 🔐 安全的密钥派生过程

	// 1. 生成唯一的会话上下文
	context := make([]byte, 0, len(serverName)+8+8)
	context = append(context, []byte(serverName)...)
	context = append(context, shortId[:]...)

	// 添加时间戳防止重放（精确到小时）
	timeSlot := time.Now().Unix() / 3600
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeSlot))
	context = append(context, timeBytes...)

	// 2. 派生PSK
	pskReader := hkdf.New(sha256.New, authKey, nil, append([]byte("REALITY-0RTT-PSK"), context...))
	psk := make([]byte, 32)
	if _, err := pskReader.Read(psk); err != nil {
		return nil, errors.New("Failed to derive PSK").Base(err)
	}

	// 3. 派生Early Secret
	earlyReader := hkdf.New(sha256.New, authKey, nil, append([]byte("REALITY-0RTT-EARLY"), context...))
	earlySecret := make([]byte, 32)
	if _, err := earlyReader.Read(earlySecret); err != nil {
		return nil, errors.New("Failed to derive early secret").Base(err)
	}

	// 4. 生成防重放nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.New("Failed to generate nonce").Base(err)
	}

	session := &ZeroRTTSession{
		ServerName:   serverName,
		ShortId:      shortId,
		AuthKey:      authKey,
		PSK:          psk,
		EarlySecret:  earlySecret,
		TicketNonce:  nonce,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		UseCount:     0,
		MaxEarlyData: 16384, // 16KB Early Data限制
		Success:      true,
		FailureCount: 0,
	}

	return session, nil
}

// UpdateSessionStatus 更新会话状态
func (c *ZeroRTTSessionCache) UpdateSessionStatus(serverName, shortId string, success bool, rtt time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 使用strings.Builder避免栈溢出
	var keyBuilder strings.Builder
	keyBuilder.WriteString(serverName)
	keyBuilder.WriteString(":")
	keyBuilder.WriteString(shortId)
	key := keyBuilder.String()

	session, exists := c.sessions[key]
	if !exists {
		return
	}

	session.LastUsed = time.Now()
	session.UseCount++
	session.RTT = rtt

	if success {
		session.Success = true
		session.FailureCount = 0
	} else {
		session.Success = false
		session.FailureCount++
	}
}

// evictOldestSession 清理最旧的会话
func (c *ZeroRTTSessionCache) evictOldestSession() {
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, session := range c.sessions {
		if session.LastUsed.Before(oldestTime) {
			oldestTime = session.LastUsed
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(c.sessions, oldestKey)
	}
}

// GetGlobalZeroRTTCache 获取全局0-RTT缓存
func GetGlobalZeroRTTCache() *ZeroRTTSessionCache {
	return globalZeroRTTCache
}
