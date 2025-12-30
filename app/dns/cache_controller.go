package dns

import (
	"context"
	go_errors "errors"
	"runtime"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/signal/pubsub"
	"github.com/xtls/xray-core/common/task"
	dns_feature "github.com/xtls/xray-core/features/dns"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sync/singleflight"
)

const (
	minSizeForEmptyRebuild  = 512
	shrinkAbsoluteThreshold = 10240
	shrinkRatioThreshold    = 0.65
	migrationBatchSize      = 4096
)

type CacheController struct {
	name            string
	disableCache    bool
	serveStale      bool
	serveExpiredTTL int32

	// Use sharded cache for better concurrency
	cache *shardedRecordCache

	pub          *pubsub.Service
	cacheCleanup *task.Periodic
	requestGroup singleflight.Group
}

func NewCacheController(name string, disableCache bool, serveStale bool, serveExpiredTTL uint32) *CacheController {
	c := &CacheController{
		name:            name,
		disableCache:    disableCache,
		serveStale:      serveStale,
		serveExpiredTTL: -int32(serveExpiredTTL),
		cache:           newShardedRecordCache(defaultShardCount),
		pub:             pubsub.NewService(),
	}

	c.cacheCleanup = &task.Periodic{
		Interval: 300 * time.Second,
		Execute:  c.CacheCleanup,
	}
	return c
}

// CacheCleanup clears expired items from cache
func (c *CacheController) CacheCleanup() error {
	if c.cache.Len() == 0 {
		return errors.New("nothing to do. stopping...")
	}

	// Skip if any migration is in progress
	if c.cache.HasDirtyItems() {
		return nil
	}

	now := time.Now()
	expiredKeysList := c.cache.CollectExpiredKeys(now, c.serveStale, c.serveExpiredTTL)

	totalCleaned := 0
	for _, shardKeys := range expiredKeysList {
		if len(shardKeys.keys) == 0 {
			continue
		}

		cleaned, shouldShrink := c.cache.CleanupShard(
			shardKeys.shardIdx,
			shardKeys.keys,
			now,
			c.serveStale,
			c.serveExpiredTTL,
		)
		totalCleaned += cleaned

		if shouldShrink {
			go c.migrateShard(shardKeys.shardIdx)
		}
	}

	if totalCleaned > 0 {
		errors.LogDebug(context.Background(), c.name, " cleaned ", totalCleaned, " expired DNS records")
	}

	return nil
}

type migrationEntry struct {
	key   string
	value *record
}

// migrateShard migrates a single shard in the background
func (c *CacheController) migrateShard(shardIdx int) {
	defer func() {
		if r := recover(); r != nil {
			errors.LogError(context.Background(), c.name, " panic during shard migration: ", r)
			c.cache.FinishShardMigration(shardIdx)
		}
	}()

	oldItems, newSize := c.cache.StartShardMigration(shardIdx)
	if oldItems == nil {
		return
	}

	errors.LogDebug(context.Background(), c.name, " starting background shard ", shardIdx, " migration for ", len(oldItems), " items, new size: ", newSize)

	batch := make([]migrationEntry, 0, migrationBatchSize)
	for domain, recD := range oldItems {
		batch = append(batch, migrationEntry{domain, recD})

		if len(batch) >= migrationBatchSize {
			c.cache.FlushMigrationBatch(shardIdx, batch)
			batch = batch[:0]
			runtime.Gosched()
		}
	}
	if len(batch) > 0 {
		c.cache.FlushMigrationBatch(shardIdx, batch)
	}

	c.cache.FinishShardMigration(shardIdx)
	errors.LogDebug(context.Background(), c.name, " shard ", shardIdx, " migration completed")
}

func (c *CacheController) updateRecord(req *dnsRequest, rep *IPRecord) {
	rtt := time.Since(req.start)

	switch req.reqType {
	case dnsmessage.TypeA:
		c.pub.Publish(req.domain+"4", rep)
	case dnsmessage.TypeAAAA:
		c.pub.Publish(req.domain+"6", rep)
	}

	if c.disableCache {
		errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt)
		return
	}

	lockStart := time.Now()

	newRec := &record{}
	var pubRecord *IPRecord
	var pubSuffix string

	// Get existing records from sharded cache
	oldRec := c.cache.Get(req.domain)
	dirtyRec := c.cache.GetDirty(req.domain)

	switch req.reqType {
	case dnsmessage.TypeA:
		newRec.A = rep
		if oldRec != nil && oldRec.AAAA != nil {
			newRec.AAAA = oldRec.AAAA
			pubRecord = oldRec.AAAA
		} else if dirtyRec != nil && dirtyRec.AAAA != nil {
			pubRecord = dirtyRec.AAAA
		}
		pubSuffix = "6"
	case dnsmessage.TypeAAAA:
		newRec.AAAA = rep
		if oldRec != nil && oldRec.A != nil {
			newRec.A = oldRec.A
			pubRecord = oldRec.A
		} else if dirtyRec != nil && dirtyRec.A != nil {
			pubRecord = dirtyRec.A
		}
		pubSuffix = "4"
	}

	c.cache.Set(req.domain, newRec)
	lockWait := time.Since(lockStart)

	if pubRecord != nil {
		_, ttl, err := pubRecord.getIPs()
		if ttl > 0 && !go_errors.Is(err, errRecordNotFound) {
			c.pub.Publish(req.domain+pubSuffix, pubRecord)
		}
	}

	errors.LogInfo(context.Background(), c.name, " got answer: ", req.domain, " ", req.reqType, " -> ", rep.IP, ", rtt: ", rtt, ", lock: ", lockWait)

	if !c.serveStale || c.serveExpiredTTL != 0 {
		common.Must(c.cacheCleanup.Start())
	}
}

func (c *CacheController) findRecords(domain string) *record {
	return c.cache.Get(domain)
}

func (c *CacheController) registerSubscribers(domain string, option dns_feature.IPOption) (sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	// ipv4 and ipv6 belong to different subscription groups
	if option.IPv4Enable {
		sub4 = c.pub.Subscribe(domain + "4")
	}
	if option.IPv6Enable {
		sub6 = c.pub.Subscribe(domain + "6")
	}
	return
}

func closeSubscribers(sub4 *pubsub.Subscriber, sub6 *pubsub.Subscriber) {
	if sub4 != nil {
		sub4.Close()
	}
	if sub6 != nil {
		sub6.Close()
	}
}
