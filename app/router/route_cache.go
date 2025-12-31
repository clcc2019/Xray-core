package router

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
)

const (
	// DefaultRouteCacheSize is the default maximum number of entries in the route cache
	DefaultRouteCacheSize = 4096

	// DefaultRouteCacheTTL is the default TTL for cached routes
	DefaultRouteCacheTTL = 5 * time.Minute

	// cacheShardCount is the number of shards for the cache to reduce lock contention
	cacheShardCount = 32
)

// routeCacheKey represents the key for route cache lookup
// We use a struct that can be used as map key (no slices/maps)
type routeCacheKey struct {
	// Target domain or IP string representation
	target string
	// Target port
	targetPort net.Port
	// Network type (TCP/UDP)
	network net.Network
	// Inbound tag
	inboundTag string
	// Protocol (sniffed)
	protocol string
	// User email
	user string
}

// routeCacheEntry represents a cached route result
type routeCacheEntry struct {
	rule      *Rule
	ruleTag   string
	outTag    string
	expiresAt int64         // Unix timestamp in nanoseconds
	key       routeCacheKey // Store key for O(1) deletion
}

// isExpired checks if the cache entry has expired
func (e *routeCacheEntry) isExpired() bool {
	return time.Now().UnixNano() > e.expiresAt
}

// routeCacheShard is a single shard of the route cache
// Uses doubly-linked list for O(1) LRU operations
type routeCacheShard struct {
	sync.RWMutex
	entries map[routeCacheKey]*list.Element // map key -> list element
	lruList *list.List                      // doubly-linked list for LRU order
	maxSize int
}

// RouteCache is a sharded LRU cache for routing decisions
type RouteCache struct {
	shards    [cacheShardCount]*routeCacheShard
	ttl       time.Duration
	enabled   atomic.Bool
	hits      atomic.Uint64
	misses    atomic.Uint64
	evictions atomic.Uint64
}

// NewRouteCache creates a new route cache
func NewRouteCache(maxSize int, ttl time.Duration) *RouteCache {
	if maxSize <= 0 {
		maxSize = DefaultRouteCacheSize
	}
	if ttl <= 0 {
		ttl = DefaultRouteCacheTTL
	}

	shardSize := maxSize / cacheShardCount
	if shardSize < 16 {
		shardSize = 16
	}

	cache := &RouteCache{
		ttl: ttl,
	}
	cache.enabled.Store(true)

	for i := 0; i < cacheShardCount; i++ {
		cache.shards[i] = &routeCacheShard{
			entries: make(map[routeCacheKey]*list.Element, shardSize),
			lruList: list.New(),
			maxSize: shardSize,
		}
	}

	return cache
}

// getShard returns the shard for a given key
func (c *RouteCache) getShard(key *routeCacheKey) *routeCacheShard {
	// Simple hash based on target string
	h := uint32(0)
	for i := 0; i < len(key.target); i++ {
		h = h*31 + uint32(key.target[i])
	}
	h = h*31 + uint32(key.targetPort)
	h = h*31 + uint32(key.network)
	return c.shards[h%cacheShardCount]
}

// buildCacheKey constructs a cache key from routing context
// Returns nil if the context is not cacheable
func buildCacheKey(ctx routing.Context) *routeCacheKey {
	// Get target - either domain or IP
	target := ctx.GetTargetDomain()
	if target == "" {
		// Try to get target IP
		ips := ctx.GetTargetIPs()
		if len(ips) == 0 {
			return nil // Cannot cache without target
		}
		// Use first IP as key
		target = ips[0].String()
	}

	return &routeCacheKey{
		target:     target,
		targetPort: ctx.GetTargetPort(),
		network:    ctx.GetNetwork(),
		inboundTag: ctx.GetInboundTag(),
		protocol:   ctx.GetProtocol(),
		user:       ctx.GetUser(),
	}
}

// Get retrieves a cached route for the given context
// Returns the cached rule and outbound tag, or nil if not found/expired
func (c *RouteCache) Get(ctx routing.Context) (*Rule, string, bool) {
	if !c.enabled.Load() {
		return nil, "", false
	}

	key := buildCacheKey(ctx)
	if key == nil {
		c.misses.Add(1)
		return nil, "", false
	}

	shard := c.getShard(key)
	shard.RLock()
	elem, exists := shard.entries[*key]
	if !exists {
		shard.RUnlock()
		c.misses.Add(1)
		return nil, "", false
	}
	entry := elem.Value.(*routeCacheEntry)
	expired := entry.isExpired()
	rule := entry.rule
	outTag := entry.outTag
	shard.RUnlock()

	if expired {
		// Entry expired, will be cleaned up on next write
		c.misses.Add(1)
		return nil, "", false
	}

	c.hits.Add(1)
	return rule, outTag, true
}

// Put stores a route result in the cache
func (c *RouteCache) Put(ctx routing.Context, rule *Rule, outTag string) {
	if !c.enabled.Load() {
		return
	}

	key := buildCacheKey(ctx)
	if key == nil {
		return
	}

	// Don't cache routes that use balancers (they may change)
	if rule != nil && rule.Balancer != nil {
		return
	}

	shard := c.getShard(key)
	entry := &routeCacheEntry{
		rule:      rule,
		ruleTag:   "",
		outTag:    outTag,
		expiresAt: time.Now().Add(c.ttl).UnixNano(),
		key:       *key,
	}
	if rule != nil {
		entry.ruleTag = rule.RuleTag
	}

	shard.Lock()
	defer shard.Unlock()

	// Check if key already exists
	if elem, exists := shard.entries[*key]; exists {
		// Update existing entry and move to front - O(1) operation
		elem.Value = entry
		shard.lruList.MoveToFront(elem)
		return
	}

	// Clean up expired entries if we're at capacity
	if len(shard.entries) >= shard.maxSize {
		c.evictOldest(shard)
	}

	// Add new entry to front of LRU list - O(1) operation
	elem := shard.lruList.PushFront(entry)
	shard.entries[*key] = elem
}

// evictOldest removes the oldest entry from the shard
// This is O(k) where k is the number of entries evicted, not O(n)
func (c *RouteCache) evictOldest(shard *routeCacheShard) {
	now := time.Now().UnixNano()

	// Iterate from back (oldest) and remove expired entries
	for elem := shard.lruList.Back(); elem != nil; {
		entry := elem.Value.(*routeCacheEntry)
		prev := elem.Prev()

		if entry.expiresAt < now {
			// Remove expired entry - O(1) operation
			shard.lruList.Remove(elem)
			delete(shard.entries, entry.key)
			c.evictions.Add(1)
		}

		elem = prev

		// Stop if we're under capacity
		if len(shard.entries) < shard.maxSize {
			return
		}
	}

	// If still at capacity after removing expired, remove oldest entries
	for len(shard.entries) >= shard.maxSize {
		elem := shard.lruList.Back()
		if elem == nil {
			break
		}
		entry := elem.Value.(*routeCacheEntry)
		shard.lruList.Remove(elem)
		delete(shard.entries, entry.key)
		c.evictions.Add(1)
	}
}

// Invalidate removes all entries from the cache
func (c *RouteCache) Invalidate() {
	for _, shard := range c.shards {
		shard.Lock()
		shard.entries = make(map[routeCacheKey]*list.Element, shard.maxSize)
		shard.lruList.Init() // Clear the list efficiently
		shard.Unlock()
	}
}

// InvalidateByInboundTag removes all entries with the given inbound tag
func (c *RouteCache) InvalidateByInboundTag(tag string) {
	for _, shard := range c.shards {
		shard.Lock()
		// Iterate through list and remove matching entries
		for elem := shard.lruList.Front(); elem != nil; {
			entry := elem.Value.(*routeCacheEntry)
			next := elem.Next()
			if entry.key.inboundTag == tag {
				shard.lruList.Remove(elem)
				delete(shard.entries, entry.key)
			}
			elem = next
		}
		shard.Unlock()
	}
}

// SetEnabled enables or disables the cache
func (c *RouteCache) SetEnabled(enabled bool) {
	c.enabled.Store(enabled)
	if !enabled {
		c.Invalidate()
	}
}

// IsEnabled returns whether the cache is enabled
func (c *RouteCache) IsEnabled() bool {
	return c.enabled.Load()
}

// Stats returns cache statistics
func (c *RouteCache) Stats() (hits, misses, evictions uint64, size int) {
	hits = c.hits.Load()
	misses = c.misses.Load()
	evictions = c.evictions.Load()

	for _, shard := range c.shards {
		shard.RLock()
		size += len(shard.entries)
		shard.RUnlock()
	}

	return
}

// HitRate returns the cache hit rate as a percentage
func (c *RouteCache) HitRate() float64 {
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	if total == 0 {
		return 0
	}
	return float64(hits) / float64(total) * 100
}
