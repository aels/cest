package ring

import "sync/atomic"

const sortQueuePerThread = 10

// SortQueue is the non-generic domain queue used by sorter workers. Its fixed
// capacity is threads*10. Overflow replaces the oldest unprocessed domain.
type SortQueue struct {
	ring    *Ring[string]
	dropped atomic.Uint64
}

// NewSortQueue creates a sort queue with the required threads*10 capacity.
func NewSortQueue(threads int) *SortQueue {
	if threads <= 0 {
		panic("ring: threads must be positive")
	}
	return &SortQueue{ring: New[string](threads * sortQueuePerThread)}
}

// Push appends a domain and reports whether the oldest domain was evicted.
func (q *SortQueue) Push(domain string) (evicted bool) {
	_, evicted = q.ring.Push(domain)
	if evicted {
		q.dropped.Add(1)
	}
	return evicted
}

// Pop removes the oldest queued domain without blocking.
func (q *SortQueue) Pop() (string, bool) { return q.ring.Pop() }

func (q *SortQueue) Len() int        { return q.ring.Len() }
func (q *SortQueue) Capacity() int   { return q.ring.Cap() }
func (q *SortQueue) Dropped() uint64 { return q.dropped.Load() }
