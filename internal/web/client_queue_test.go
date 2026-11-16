package web

import "testing"

func TestClientQueueEvictsOldestByBytes(t *testing.T) {
	q := NewClientQueue(8) // "aa\n" + "bbb\n" = 7 bytes
	if dropped := q.Push("aa"); dropped != 0 {
		t.Fatalf("first push dropped %d", dropped)
	}
	if dropped := q.Push("bbb"); dropped != 0 {
		t.Fatalf("second push dropped %d", dropped)
	}
	if dropped := q.Push("cccc"); dropped != 2 {
		t.Fatalf("third push dropped %d, want 2", dropped)
	}
	batch := q.PopBatch(100)
	if len(batch) != 1 || batch[0] != "cccc" {
		t.Fatalf("batch = %#v, want [cccc]", batch)
	}
	if q.Dropped() != 2 || q.Bytes() != 0 {
		t.Fatalf("dropped=%d bytes=%d", q.Dropped(), q.Bytes())
	}
}

func TestClientQueueDropsOversizeMessage(t *testing.T) {
	q := NewClientQueue(4)
	if dropped := q.Push("1234"); dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if q.Len() != 0 || q.Dropped() != 1 {
		t.Fatalf("len=%d dropped=%d", q.Len(), q.Dropped())
	}
}

func TestRouteBatchLimits(t *testing.T) {
	if got := routeBatchLimit("all"); got != 100 {
		t.Fatalf("all batch limit = %d, want 100", got)
	}
	if got := routeBatchLimit("wordpress"); got != 1 {
		t.Fatalf("sort route batch limit = %d, want 1", got)
	}
}

func TestClientQueueBatchesAtRequestedLimit(t *testing.T) {
	q := NewClientQueue(1024)
	for i := 0; i < 105; i++ {
		q.Push("x")
	}
	if got := len(q.PopBatch(100)); got != 100 {
		t.Fatalf("batch length = %d", got)
	}
	if got := len(q.PopBatch(100)); got != 5 {
		t.Fatalf("second batch length = %d", got)
	}
}
