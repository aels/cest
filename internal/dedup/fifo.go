package dedup

import "sync"

// FIFOSet remembers the last capacity distinct strings. Repeated values are
// rejected without refreshing their position.
type FIFOSet struct {
	mu           sync.Mutex
	set          map[string]struct{}
	ring         []string
	head, length int
}

func New(capacity int) *FIFOSet {
	if capacity <= 0 {
		panic("dedup: capacity must be positive")
	}
	return &FIFOSet{set: make(map[string]struct{}, capacity), ring: make([]string, capacity)}
}

// Add reports whether value was not already present and has been inserted.
func (f *FIFOSet) Add(value string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.set[value]; ok {
		return false
	}
	if f.length == len(f.ring) {
		delete(f.set, f.ring[f.head])
		f.ring[f.head] = value
		f.head = (f.head + 1) % len(f.ring)
	} else {
		idx := (f.head + f.length) % len(f.ring)
		f.ring[idx] = value
		f.length++
	}
	f.set[value] = struct{}{}
	return true
}

func (f *FIFOSet) Len() int { f.mu.Lock(); defer f.mu.Unlock(); return f.length }
