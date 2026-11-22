package ctstream

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollRFC6962CatchesUpWithoutRefetchingSTH(t *testing.T) {
	const treeSize, serverCap = 120, 50
	var sthRequests atomic.Int32
	leaf := base64.StdEncoding.EncodeToString(leafFixture(entryX509, []byte{0x30, 0}))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ct/v1/get-sth":
			sthRequests.Add(1)
			fmt.Fprintf(w, `{"tree_size":%d}`, treeSize)
		case "/ct/v1/get-entries":
			start, _ := strconv.Atoi(r.URL.Query().Get("start"))
			end, _ := strconv.Atoi(r.URL.Query().Get("end"))
			if end-start+1 > serverCap {
				end = start + serverCap - 1
			}
			type entry struct {
				LeafInput string `json:"leaf_input"`
			}
			var resp struct {
				Entries []entry `json:"entries"`
			}
			for i := start; i <= end; i++ {
				resp.Entries = append(resp.Entries, entry{leaf})
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s := New(Config{HTTPClient: server.Client(), OutputBuffer: treeSize})
	spec := logSpec{baseURL: server.URL}
	var cur cursor
	var idles []bool
	for range 3 {
		idle, err := s.pollRFC6962(context.Background(), spec, &cur)
		if err != nil {
			t.Fatal(err)
		}
		idles = append(idles, idle)
	}
	if cur.next != treeSize || len(s.entries) != treeSize {
		t.Fatalf("next=%d emitted=%d, want %d", cur.next, len(s.entries), treeSize)
	}
	if want := []bool{false, false, true}; fmt.Sprint(idles) != fmt.Sprint(want) {
		t.Fatalf("idle sequence = %v, want %v", idles, want)
	}
	if n := sthRequests.Load(); n != 1 {
		t.Fatalf("get-sth requests = %d, want 1", n)
	}
}

func TestPollTiledPrefersFullTiles(t *testing.T) {
	const size = tileWidth + 44
	var tileRequests []string
	entry := tileFixture(entryX509, []byte{0x30, 0})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/checkpoint":
			fmt.Fprintf(w, "example.com/log\n%d\nhash\n", size)
		case "/tile/data/000":
			tileRequests = append(tileRequests, r.URL.Path)
			_, _ = w.Write(bytes.Repeat(entry, tileWidth))
		case "/tile/data/001.p/44":
			tileRequests = append(tileRequests, r.URL.Path)
			_, _ = w.Write(bytes.Repeat(entry, 44))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	s := New(Config{HTTPClient: server.Client(), OutputBuffer: 2 * tileWidth, PartialTileDelay: time.Hour})
	spec := logSpec{baseURL: server.URL, kind: sourceTiled}
	cur := cursor{next: 10}
	idle, err := s.pollTiled(context.Background(), spec, &cur)
	if err != nil || idle || cur.next != tileWidth {
		t.Fatalf("full tile: idle=%v err=%v next=%d", idle, err, cur.next)
	}
	// The second tile is incomplete and too young: no tile request.
	idle, err = s.pollTiled(context.Background(), spec, &cur)
	if err != nil || !idle || cur.next != tileWidth || len(tileRequests) != 1 {
		t.Fatalf("young partial: idle=%v err=%v next=%d requests=%v", idle, err, cur.next, tileRequests)
	}
	// After the delay the partial tile is fetched once.
	cur.partialSince = time.Now().Add(-2 * time.Hour)
	idle, err = s.pollTiled(context.Background(), spec, &cur)
	if err != nil || !idle || cur.next != size || !cur.partialSince.IsZero() {
		t.Fatalf("old partial: idle=%v err=%v next=%d", idle, err, cur.next)
	}
	if want := "[/tile/data/000 /tile/data/001.p/44]"; fmt.Sprint(tileRequests) != want {
		t.Fatalf("tile requests = %v, want %s", tileRequests, want)
	}
	if len(s.entries) != size-10 {
		t.Fatalf("emitted %d entries, want %d", len(s.entries), size-10)
	}
}
