// Package cache provides a lock-free, atomically-swappable in-memory cache
// mapping a cache key (e.g. the numeric ASN as a string) to a formatted DNS
// TXT record value.
package cache

import (
	"sync/atomic"
)

// Cache holds a map[string]string behind an atomic.Value so DNS query handlers
// read without locks and the syncer replaces the whole map in one atomic store.
type Cache struct {
	v atomic.Value // holds map[string]string
}

// New returns a Cache pre-loaded with an empty map so reads never see a nil.
func New() *Cache {
	c := &Cache{}
	c.v.Store(map[string]string{})
	return c
}

// Get returns the TXT value for key and whether it was present. Lock-free.
func (c *Cache) Get(key string) (string, bool) {
	m, _ := c.v.Load().(map[string]string)
	val, ok := m[key]
	return val, ok
}

// Store atomically replaces the entire backing map. The caller must not mutate
// m after passing it in.
func (c *Cache) Store(m map[string]string) {
	c.v.Store(m)
}

// Len returns the number of entries currently in the cache.
func (c *Cache) Len() int {
	m, _ := c.v.Load().(map[string]string)
	return len(m)
}
