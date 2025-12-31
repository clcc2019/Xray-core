package dns

import (
	"sync"
	"time"
)

const (
	// defaultShardCount is the number of shards for the DNS cache
	// Using 32 shards provides good balance between memory overhead and lock contention
	defaultShardCount = 32
)

// shardedRecordCache is a sharded map for DNS records to reduce lock contention
type shardedRecordCache struct {
	shards    []*recordCacheShard
	shardMask uint32
}

// fnvHash computes a simple FNV-1a hash inline without allocations
// This is much faster than using hash/fnv which allocates a new hash state each time
func fnvHash(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}

type recordCacheShard struct {
	sync.RWMutex
	items         map[string]*record
	dirtyItems    map[string]*record
	highWatermark int
}

// newShardedRecordCache creates a new sharded cache with the specified number of shards
func newShardedRecordCache(shardCount int) *shardedRecordCache {
	if shardCount <= 0 {
		shardCount = defaultShardCount
	}
	// Round up to power of 2 for efficient modulo operation
	shardCount = nextPowerOf2(shardCount)

	cache := &shardedRecordCache{
		shards:    make([]*recordCacheShard, shardCount),
		shardMask: uint32(shardCount - 1),
	}

	for i := 0; i < shardCount; i++ {
		cache.shards[i] = &recordCacheShard{
			items: make(map[string]*record),
		}
	}

	return cache
}

// nextPowerOf2 returns the next power of 2 >= n
func nextPowerOf2(n int) int {
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// getShard returns the shard for the given key
// Uses inline FNV-1a hash to avoid allocations
func (c *shardedRecordCache) getShard(key string) *recordCacheShard {
	return c.shards[fnvHash(key)&c.shardMask]
}

// Get retrieves a record from the cache
func (c *shardedRecordCache) Get(domain string) *record {
	shard := c.getShard(domain)
	shard.RLock()
	rec := shard.items[domain]
	if rec == nil && shard.dirtyItems != nil {
		rec = shard.dirtyItems[domain]
	}
	shard.RUnlock()
	return rec
}

// Set stores a record in the cache
func (c *shardedRecordCache) Set(domain string, rec *record) {
	shard := c.getShard(domain)
	shard.Lock()
	shard.items[domain] = rec
	shard.Unlock()
}

// GetDirty retrieves a record from the dirty items
func (c *shardedRecordCache) GetDirty(domain string) *record {
	shard := c.getShard(domain)
	shard.RLock()
	var rec *record
	if shard.dirtyItems != nil {
		rec = shard.dirtyItems[domain]
	}
	shard.RUnlock()
	return rec
}

// Delete removes a record from the cache
func (c *shardedRecordCache) Delete(domain string) {
	shard := c.getShard(domain)
	shard.Lock()
	delete(shard.items, domain)
	shard.Unlock()
}

// Len returns the total number of items across all shards
func (c *shardedRecordCache) Len() int {
	total := 0
	for _, shard := range c.shards {
		shard.RLock()
		total += len(shard.items)
		shard.RUnlock()
	}
	return total
}

// CollectExpiredKeys collects expired keys from all shards
func (c *shardedRecordCache) CollectExpiredKeys(now time.Time, serveStale bool, serveExpiredTTL int32) []shardedExpiredKeys {
	if serveStale && serveExpiredTTL != 0 {
		now = now.Add(time.Duration(serveExpiredTTL) * time.Second)
	}

	result := make([]shardedExpiredKeys, len(c.shards))

	for i, shard := range c.shards {
		shard.RLock()
		// Skip if migration is in progress for this shard
		if shard.dirtyItems != nil {
			shard.RUnlock()
			continue
		}

		var keys []string
		for domain, rec := range shard.items {
			if (rec.A != nil && rec.A.Expire.Before(now)) ||
				(rec.AAAA != nil && rec.AAAA.Expire.Before(now)) {
				keys = append(keys, domain)
			}
		}
		shard.RUnlock()

		result[i] = shardedExpiredKeys{
			shardIdx: i,
			keys:     keys,
		}
	}

	return result
}

type shardedExpiredKeys struct {
	shardIdx int
	keys     []string
}

// CleanupShard cleans up expired keys from a specific shard
func (c *shardedRecordCache) CleanupShard(shardIdx int, keys []string, now time.Time, serveStale bool, serveExpiredTTL int32) (cleaned int, shouldShrink bool) {
	if len(keys) == 0 {
		return 0, false
	}

	if serveStale && serveExpiredTTL != 0 {
		now = now.Add(time.Duration(serveExpiredTTL) * time.Second)
	}

	shard := c.shards[shardIdx]
	shard.Lock()
	defer shard.Unlock()

	// Skip if migration is in progress
	if shard.dirtyItems != nil {
		return 0, false
	}

	lenBefore := len(shard.items)
	if lenBefore > shard.highWatermark {
		shard.highWatermark = lenBefore
	}

	for _, domain := range keys {
		rec := shard.items[domain]
		if rec == nil {
			continue
		}
		if rec.A != nil && rec.A.Expire.Before(now) {
			rec.A = nil
		}
		if rec.AAAA != nil && rec.AAAA.Expire.Before(now) {
			rec.AAAA = nil
		}
		if rec.A == nil && rec.AAAA == nil {
			delete(shard.items, domain)
			cleaned++
		}
	}

	lenAfter := len(shard.items)

	// Check if we should shrink this shard
	if lenAfter == 0 && shard.highWatermark >= minSizeForEmptyRebuild/int(c.shardMask+1) {
		shard.items = make(map[string]*record)
		shard.highWatermark = 0
		return cleaned, false
	}

	reductionFromPeak := shard.highWatermark - lenAfter
	perShardThreshold := shrinkAbsoluteThreshold / int(c.shardMask+1)
	if reductionFromPeak > perShardThreshold &&
		float64(reductionFromPeak) > float64(shard.highWatermark)*shrinkRatioThreshold {
		shouldShrink = true
	}

	return cleaned, shouldShrink
}

// StartShardMigration starts migration for a specific shard
func (c *shardedRecordCache) StartShardMigration(shardIdx int) (oldItems map[string]*record, newSize int) {
	shard := c.shards[shardIdx]
	shard.Lock()
	defer shard.Unlock()

	if shard.dirtyItems != nil {
		return nil, 0
	}

	lenAfter := len(shard.items)
	shard.dirtyItems = shard.items
	shard.items = make(map[string]*record, int(float64(lenAfter)*1.1))
	shard.highWatermark = lenAfter

	return shard.dirtyItems, lenAfter
}

// FlushMigrationBatch flushes a batch of migration entries to the new map
func (c *shardedRecordCache) FlushMigrationBatch(shardIdx int, batch []migrationEntry) {
	shard := c.shards[shardIdx]
	shard.Lock()
	defer shard.Unlock()

	for _, dirty := range batch {
		if cur := shard.items[dirty.key]; cur != nil {
			merge := &record{}
			if cur.A == nil {
				merge.A = dirty.value.A
			} else {
				merge.A = cur.A
			}
			if cur.AAAA == nil {
				merge.AAAA = dirty.value.AAAA
			} else {
				merge.AAAA = cur.AAAA
			}
			shard.items[dirty.key] = merge
		} else {
			shard.items[dirty.key] = dirty.value
		}
	}
}

// FinishShardMigration finishes migration for a specific shard
func (c *shardedRecordCache) FinishShardMigration(shardIdx int) {
	shard := c.shards[shardIdx]
	shard.Lock()
	shard.dirtyItems = nil
	shard.Unlock()
}

// UpdateRecord updates a record in the cache with proper locking
func (c *shardedRecordCache) UpdateRecord(domain string, newRec *record, reqType uint16) (oldRec *record, dirtyRec *record) {
	shard := c.getShard(domain)
	shard.Lock()
	oldRec = shard.items[domain]
	if shard.dirtyItems != nil {
		dirtyRec = shard.dirtyItems[domain]
	}
	shard.items[domain] = newRec
	shard.Unlock()
	return
}

// HasDirtyItems checks if any shard has dirty items (migration in progress)
func (c *shardedRecordCache) HasDirtyItems() bool {
	for _, shard := range c.shards {
		shard.RLock()
		hasDirty := shard.dirtyItems != nil
		shard.RUnlock()
		if hasDirty {
			return true
		}
	}
	return false
}
