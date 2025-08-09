package realityprofiler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"expvar"
	"net"
	"os"
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

	// metrics
	hits    *expvar.Int
	misses  *expvar.Int
	updates *expvar.Int
}

var global *manager

func init() {
	// Enable via env: XRAY_REALITY_PREBUILD=1
	if os.Getenv("XRAY_REALITY_PREBUILD") == "" {
		return
	}
	m := &manager{
		profiles:  make(map[string]*Profile),
		pending:   make(map[string]struct{}),
		ttl:       envDuration("XRAY_REALITY_TTL", 30*time.Minute),
		interval:  envDuration("XRAY_REALITY_REFRESH_INTERVAL", 10*time.Minute),
		fpPreset:  envString("XRAY_REALITY_FP", "chrome"),
		dialTO:    envDuration("XRAY_REALITY_DIAL_TIMEOUT", 5*time.Second),
		refreshTO: envDuration("XRAY_REALITY_REFRESH_TIMEOUT", 6*time.Second),
		hits:      expvar.NewInt("reality_prebuild_hits_total"),
		misses:    expvar.NewInt("reality_prebuild_misses_total"),
		updates:   expvar.NewInt("reality_prebuild_updates_total"),
	}
	global = m

	// Kickoff initial targets
	targets := parseTargets(os.Getenv("XRAY_REALITY_TARGETS"))
	for _, h := range targets {
		go m.probeAndStore(context.Background(), h)
	}

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

	start := time.Now()
	prof, err := m.probeOnce(ctx, host)
	if err != nil {
		errors.LogWarning(context.Background(), "REALITY prebuild probe failed for ", host, ": ", err)
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
		// Offer common ALPN order; server will select one we can observe
		NextProtos: []string{"h2", "http/1.1"},
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
	if p := Get(host); p != nil {
		if len(p.ALPN) > 0 {
			cfg.NextProtos = append([]string(nil), p.ALPN...)
		}
	} else {
		EnsureAsync(host)
	}
}

// For other subsystems which may need RTT for pacing decisions.
func GetHandshakeRTT(host string) time.Duration {
	if p := Get(host); p != nil && p.HandshakeRTTMs > 0 {
		return time.Duration(p.HandshakeRTTMs) * time.Millisecond
	}
	return 0
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
