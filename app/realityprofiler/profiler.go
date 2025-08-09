package realityprofiler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"expvar"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/errors"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

// Profile captures stable, reusable properties observed from a target site.
type Profile struct {
	Host            string   `json:"host"`
	ALPN            []string `json:"alpn"`
	HandshakeRTTMs  int64    `json:"hs_rtt_ms"`
	SPKISHA256      string   `json:"spki_sha256"`
	LastUpdatedUnix int64    `json:"last_updated_unix"`
}

type manager struct {
	mu        sync.RWMutex
	profiles  map[string]*Profile
	pending   map[string]struct{}
	ttl       time.Duration
	interval  time.Duration
	fpPreset  string
	dialTO    time.Duration
	refreshTO time.Duration
	// persistence
	storePath string
	persistCh chan struct{}
	// concurrency control
	maxInflight int
	sem         chan struct{}
	// retry
	retryCount map[string]int

	// metrics
	hits    *expvar.Int
	misses  *expvar.Int
	updates *expvar.Int
}

var global *manager

func init() {
	m := &manager{
		profiles:    make(map[string]*Profile),
		pending:     make(map[string]struct{}),
		ttl:         envDuration("XRAY_REALITY_TTL", 30*time.Minute),
		interval:    envDuration("XRAY_REALITY_REFRESH_INTERVAL", 10*time.Minute),
		fpPreset:    envString("XRAY_REALITY_FP", "chrome"),
		dialTO:      envDuration("XRAY_REALITY_DIAL_TIMEOUT", 5*time.Second),
		refreshTO:   envDuration("XRAY_REALITY_REFRESH_TIMEOUT", 6*time.Second),
		hits:        expvar.NewInt("reality_prebuild_hits_total"),
		misses:      expvar.NewInt("reality_prebuild_misses_total"),
		updates:     expvar.NewInt("reality_prebuild_updates_total"),
		storePath:   defaultStorePath(),
		persistCh:   make(chan struct{}, 1),
		maxInflight: envInt("XRAY_REALITY_MAX_INFLIGHT", 4),
		retryCount:  make(map[string]int),
	}
	if m.maxInflight <= 0 {
		m.maxInflight = 2
	}
	m.sem = make(chan struct{}, m.maxInflight)
	global = m

	// Load persisted profiles (best-effort)
	_ = m.loadFromFile()

	// Persistence worker (debounced)
	go func() {
		var t *time.Timer
		for range m.persistCh {
			if t != nil {
				t.Stop()
			}
			t = time.NewTimer(1 * time.Second)
			<-t.C
			_ = m.storeToFile()
		}
	}()

	// Periodic refresh
	go func() {
		if m.interval <= 0 {
			return
		}
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for range ticker.C {
			m.mu.RLock()
			keys := make([]string, 0, len(m.profiles))
			for k := range m.profiles {
				keys = append(keys, k)
			}
			m.mu.RUnlock()
			for _, k := range keys {
				// Refresh only if close to TTL expiring
				if p := m.Get(k); p != nil && time.Since(time.Unix(p.LastUpdatedUnix, 0)) > m.ttl/2 {
					ctx, cancel := context.WithTimeout(context.Background(), m.refreshTO)
					m.probeAndStore(ctx, k)
					cancel()
				}
			}
		}
	}()
}

func envString(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return def
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	// simple parse
	var x int
	_, err := fmt.Sscanf(v, "%d", &x)
	if err != nil {
		return def
	}
	return x
}

func parseTargets(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// strip port if any, we always probe :443 by default
		if i := strings.IndexByte(p, ':'); i >= 0 {
			p = p[:i]
		}
		out = append(out, p)
	}
	// de-dup
	sort.Strings(out)
	u := out[:0]
	var last string
	for _, v := range out {
		if v != last {
			u = append(u, v)
			last = v
		}
	}
	return u
}

// Get returns a profile if present and fresh; nil otherwise.
func Get(host string) *Profile {
	if global == nil {
		return nil
	}
	return global.Get(host)
}

// EnsureAsync schedules a background probe if not present or stale.
func EnsureAsync(host string) {
	if global == nil || host == "" {
		return
	}
	if p := global.Get(host); p != nil {
		// still valid
		if time.Since(time.Unix(p.LastUpdatedUnix, 0)) < global.ttl {
			return
		}
	}
	go global.probeAndStore(context.Background(), host)
}

func (m *manager) Get(host string) *Profile {
	m.mu.RLock()
	p, ok := m.profiles[strings.ToLower(host)]
	m.mu.RUnlock()
	if ok {
		m.hits.Add(1)
		return p
	}
	m.misses.Add(1)
	return nil
}

func (m *manager) set(host string, p *Profile) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.profiles[strings.ToLower(host)] = p
	delete(m.pending, strings.ToLower(host))
	// notify persist
	select {
	case m.persistCh <- struct{}{}:
	default:
	}
}

func (m *manager) markPending(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := strings.ToLower(host)
	if _, ok := m.pending[h]; ok {
		return false
	}
	m.pending[h] = struct{}{}
	return true
}

func (m *manager) probeAndStore(ctx context.Context, host string) {
	if host == "" || !m.markPending(host) {
		return
	}
	defer func() {
		m.mu.Lock()
		delete(m.pending, strings.ToLower(host))
		m.mu.Unlock()
	}()

	// concurrency limit
	m.sem <- struct{}{}
	defer func() { <-m.sem }()

	start := time.Now()
	prof, err := m.probeOnce(ctx, host)
	if err != nil {
		errors.LogWarning(context.Background(), "REALITY prebuild probe failed for ", host, ": ", err)
		m.scheduleRetry(host)
		return
	}
	prof.HandshakeRTTMs = time.Since(start).Milliseconds()
	prof.LastUpdatedUnix = time.Now().Unix()
	m.set(host, prof)
	m.updates.Add(1)
}

func (m *manager) probeOnce(ctx context.Context, host string) (*Profile, error) {
	// Dial TCP
	d := &net.Dialer{Timeout: m.dialTO}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	// Build uTLS client with selected fingerprint preset
	fp := xtls.GetFingerprint(m.fpPreset)
	if fp == nil {
		// fallback to chrome
		def := "chrome"
		fp = xtls.GetFingerprint(def)
	}
	ucfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		// 模仿浏览器：提供常见 ALPN 顺序，后续由服务器选择
		NextProtos: []string{"h2", "http/1.1"},
		// 允许会话票据更贴近浏览器，但不在此启用 0-RTT
		SessionTicketsDisabled: false,
	}
	uconn := utls.UClient(conn, ucfg, *fp)
	// Trigger TLS handshake
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = uconn.Close()
		return nil, err
	}
	state := uconn.ConnectionState()
	// Compute SPKI SHA-256
	var spkiB64 string
	if len(state.PeerCertificates) > 0 {
		sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		spkiB64 = base64.StdEncoding.EncodeToString(sum[:])
	}
	// NegotiatedProtocol is what server picked; keep offered order too
	alpn := make([]string, 0, 2)
	if state.NegotiatedProtocol != "" {
		alpn = append(alpn, state.NegotiatedProtocol)
	}
	// Keep a sane offer list for reuse
	for _, p := range []string{"h2", "http/1.1"} {
		if state.NegotiatedProtocol != p {
			alpn = append(alpn, p)
		}
	}
	_ = uconn.Close()
	return &Profile{
		Host:       host,
		ALPN:       alpn,
		SPKISHA256: spkiB64,
	}, nil
}

// ApplyToTLSConfig mutates utls.Config with data from profile.
func ApplyToTLSConfig(host string, cfg *utls.Config) {
	if cfg == nil {
		return
	}
	// 默认安全候选（严格、可互通）
	const (
		alpnH2     = "h2"
		alpnHTTP11 = "http/1.1"
	)
	defaultOrder := []string{alpnH2, alpnHTTP11}

	// 读取已缓存的 ALPN；否则触发异步采集
	var order []string
	if host != "" {
		if p := Get(host); p != nil && len(p.ALPN) > 0 {
			order = sanitizeAndClampALPN(p.ALPN)
		} else {
			EnsureAsync(host)
		}
	}

	// 极限保护：
	// - 若无可用 ALPN 或清洗后为空，则回退到默认顺序
	// - 任何情况下都避免产生空的 NextProtos
	if len(order) == 0 {
		order = defaultOrder
	}

	// 应用到配置（覆盖式），避免叠加导致指纹异常
	cfg.NextProtos = append([]string(nil), order...)
}

// For other subsystems which may need RTT for pacing decisions.
func GetHandshakeRTT(host string) time.Duration {
	if p := Get(host); p != nil && p.HandshakeRTTMs > 0 {
		return time.Duration(p.HandshakeRTTMs) * time.Millisecond
	}
	return 0
}

// 仅允许安全/常见的 ALPN 候选，并去重、限长
func sanitizeAndClampALPN(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	// 仅保留 h2 与 http/1.1，并按出现顺序保序去重
	seen := make(map[string]struct{}, 2)
	out := make([]string, 0, 2)
	for _, v := range in {
		v = strings.TrimSpace(strings.ToLower(v))
		switch v {
		case "h2":
			if _, ok := seen[v]; !ok {
				out = append(out, v)
				seen[v] = struct{}{}
			}
		case "http/1.1", "http/1.0":
			// 始终规范化为 http/1.1
			if _, ok := seen["http/1.1"]; !ok {
				out = append(out, "http/1.1")
				seen["http/1.1"] = struct{}{}
			}
		default:
			// 其他一律丢弃，避免指纹异常
		}
		if len(out) >= 2 { // 限长
			break
		}
	}
	return out
}

// Expose a minimal expvar snapshot to aid debugging.
func init() {
	expvar.Publish("reality_profiles", expvar.Func(func() interface{} {
		if global == nil {
			return nil
		}
		global.mu.RLock()
		defer global.mu.RUnlock()
		// Return a shallow copy with limited fields
		m := make(map[string]interface{}, len(global.profiles))
		for k, v := range global.profiles {
			m[k] = map[string]interface{}{
				"alpn":        v.ALPN,
				"rtt_ms":      v.HandshakeRTTMs,
				"updated":     v.LastUpdatedUnix,
				"spki_sha256": v.SPKISHA256,
			}
		}
		return m
	}))
}

// persistence helpers
func defaultStorePath() string {
	p := strings.TrimSpace(os.Getenv("XRAY_REALITY_STORE"))
	if p != "" {
		return p
	}
	// prefer /var/lib if exists
	if _, err := os.Stat("/var/lib"); err == nil {
		return "/var/lib/xray-reality-profiles.json"
	}
	return "/tmp/xray-reality-profiles.json"
}

func (m *manager) storeToFile() error {
	if m.storePath == "" {
		return nil
	}
	// ensure parent dir exists (best-effort)
	if dir := filepath.Dir(m.storePath); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.profiles) == 0 {
		return nil
	}
	tmp := m.storePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", " ")
	if err := enc.Encode(m.profiles); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, m.storePath)
}

func (m *manager) loadFromFile() error {
	if m.storePath == "" {
		return nil
	}
	f, err := os.Open(m.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	var data map[string]*Profile
	dec := json.NewDecoder(f)
	if err := dec.Decode(&data); err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	now := time.Now().Unix()
	m.mu.Lock()
	for k, v := range data {
		// drop obviously stale (older than TTL*2)
		if v != nil && (m.ttl <= 0 || now-int64(m.ttl.Seconds())*2 <= v.LastUpdatedUnix) {
			m.profiles[strings.ToLower(k)] = v
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *manager) scheduleRetry(host string) {
	m.mu.Lock()
	n := m.retryCount[strings.ToLower(host)] + 1
	if n > 6 { // cap backoff steps
		m.mu.Unlock()
		return
	}
	m.retryCount[strings.ToLower(host)] = n
	m.mu.Unlock()
	// exponential backoff with jitter up to ~min(2^n, 300s)
	base := time.Duration(1<<uint(min(n, 8))) * time.Second
	if base > 5*time.Minute {
		base = 5 * time.Minute
	}
	delay := base + time.Duration(int64(time.Millisecond)*int64(100*(n%5)))
	time.AfterFunc(delay, func() { m.probeAndStore(context.Background(), host) })
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
