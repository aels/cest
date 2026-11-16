package ring

import "testing"

func TestRingEvictsOldest(t *testing.T) {
	r := New[int](3)
	for _, value := range []int{1, 2, 3} {
		if _, evicted := r.Push(value); evicted {
			t.Fatalf("Push(%d) unexpectedly evicted", value)
		}
	}
	if value, evicted := r.Push(4); !evicted || value != 1 {
		t.Fatalf("Push(4) = (%d, %v), want (1, true)", value, evicted)
	}
	for _, want := range []int{2, 3, 4} {
		got, ok := r.Pop()
		if !ok || got != want {
			t.Fatalf("Pop() = (%d, %v), want (%d, true)", got, ok, want)
		}
	}
	if _, ok := r.Pop(); ok {
		t.Fatal("empty ring returned an element")
	}
}

func TestSortQueueCapacityAndDrops(t *testing.T) {
	q := NewSortQueue(1)
	for i := 0; i < 12; i++ {
		q.Push(string(rune('a' + i)))
	}
	if q.Capacity() != 10 || q.Len() != 10 || q.Dropped() != 2 {
		t.Fatalf("queue state = cap %d len %d dropped %d", q.Capacity(), q.Len(), q.Dropped())
	}
	got, _ := q.Pop()
	if got != "c" {
		t.Fatalf("oldest retained value = %q, want c", got)
	}
}
