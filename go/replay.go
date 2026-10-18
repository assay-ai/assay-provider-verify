package assayverify

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// ReplayStore remembers nonces. CheckAndStore reports true when the nonce was
// not seen before (and is now stored for ttl). Errors make verification fail
// closed: Verify returns the error and the middleware answers 500.
type ReplayStore interface {
	CheckAndStore(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
}

type memoryEntry struct {
	nonce  string
	expiry time.Time
}

type memoryReplayStore struct {
	mu      sync.Mutex
	max     int
	order   *list.List // oldest at the front
	entries map[string]*list.Element
}

// NewMemoryReplayStore returns an in-memory store holding at most maxEntries
// nonces; the oldest inserted are evicted first (default 100000 when maxEntries <= 0).
func NewMemoryReplayStore(maxEntries int) ReplayStore {
	if maxEntries <= 0 {
		maxEntries = 100_000
	}
	return &memoryReplayStore{max: maxEntries, order: list.New(), entries: map[string]*list.Element{}}
}

func (s *memoryReplayStore) CheckAndStore(_ context.Context, nonce string, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if el, ok := s.entries[nonce]; ok {
		if el.Value.(*memoryEntry).expiry.After(now) {
			return false, nil
		}
		s.order.Remove(el)
		delete(s.entries, nonce)
	}
	if ttl < 0 {
		ttl = 0
	}
	s.entries[nonce] = s.order.PushBack(&memoryEntry{nonce: nonce, expiry: now.Add(ttl)})
	for s.order.Len() > s.max {
		oldest := s.order.Front()
		s.order.Remove(oldest)
		delete(s.entries, oldest.Value.(*memoryEntry).nonce)
	}
	return true, nil
}
