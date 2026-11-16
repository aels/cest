// Package ring provides fixed-capacity, overwrite-oldest FIFO queues.
package ring

import "sync"

// Ring is a goroutine-safe fixed-capacity FIFO. Push overwrites the oldest
// element when the ring is full. All operations are O(1).
type Ring[T any] struct {
	mu     sync.Mutex
	buf    []T
	head   int
	length int
}

// New creates a ring with the given fixed capacity.
func New[T any](capacity int) *Ring[T] {
	if capacity <= 0 {
		panic("ring: capacity must be positive")
	}
	return &Ring[T]{buf: make([]T, capacity)}
}

// Push appends value. If the ring was full, it returns the overwritten oldest
// value and evicted=true.
func (r *Ring[T]) Push(value T) (evictedValue T, evicted bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.length == len(r.buf) {
		evictedValue = r.buf[r.head]
		r.buf[r.head] = value
		r.head = (r.head + 1) % len(r.buf)
		return evictedValue, true
	}

	index := (r.head + r.length) % len(r.buf)
	r.buf[index] = value
	r.length++
	return evictedValue, false
}

// Pop removes and returns the oldest value. It does not block when empty.
func (r *Ring[T]) Pop() (value T, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.length == 0 {
		return value, false
	}
	value = r.buf[r.head]
	var zero T
	r.buf[r.head] = zero
	r.head = (r.head + 1) % len(r.buf)
	r.length--
	return value, true
}

// Len returns the current number of elements.
func (r *Ring[T]) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.length
}

// Cap returns the fixed capacity.
func (r *Ring[T]) Cap() int { return len(r.buf) }
