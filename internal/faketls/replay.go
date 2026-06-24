package faketls

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// ReplayCache хранит уже виденные ClientHello для защиты от replay.
type ReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	max     int
	ttl     time.Duration
	hits    uint64
}

// NewReplayCache создаёт кеш anti-replay.
func NewReplayCache(maxEntries int, ttl time.Duration) *ReplayCache {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &ReplayCache{
		entries: make(map[string]time.Time, maxEntries),
		max:     maxEntries,
		ttl:     ttl,
	}
}

// Check возвращает true, если ClientHello уже встречался (replay).
func (c *ReplayCache) Check(ch *ClientHello) bool {
	if ch == nil {
		return false
	}
	key := replayKey(ch)
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.evict(now)

	if _, ok := c.entries[key]; ok {
		c.hits++
		return true
	}
	c.entries[key] = now
	return false
}

// Hits возвращает число обнаруженных replay.
func (c *ReplayCache) Hits() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits
}

func (c *ReplayCache) evict(now time.Time) {
	for k, t := range c.entries {
		if now.Sub(t) > c.ttl {
			delete(c.entries, k)
		}
	}
	for len(c.entries) > c.max {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
}

func replayKey(ch *ClientHello) string {
	sum := sha256.Sum256(ch.Random[:])
	return hex.EncodeToString(sum[:])
}
