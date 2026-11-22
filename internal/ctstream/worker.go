package ctstream

import (
	"bufio"
	"context"
	"encoding/base64"

	"errors"
	"fmt"

	"strconv"
	"strings"
	"time"
)

const tileWidth = 256

var denyLogIDs = map[string]struct{}{
	"utuIpG+cr6QJDoLlk1bbbni0pT9YLbCBl5UkLym2jJg=": {},
	"HIl0B+YBCgEpO7Z439ejaM6xjMpSHcyk04bkoy5bXQQ=": {},
	"lE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9VTcuGdg=": {},
	"RqI5Z8YNtkaHxm89+ZmUdpOmphEghFfVVefj0KHZtkY=": {},
	"lLHBirDQV8R74KwEDh8svI3DdXJ7yVHyClJhJoY7pzw=": {},
	"H1bRq5RwSkHdP+r99GmTVTAsFDG/5hNGCJ//rnldzC8=": {},
	"bP5QGUOoXqkWvFLRM+TcyR7xQRx9JYQg0XOAnhgY6zo=": {},
	"jspHC6zeavOiBrCkeoS3Rv4fxr+VPiXmm07kAkjzxug=": {},
	"ooEAGHNOF24dR+CVQPOBulRml81jqENQcW64CU7a8Q0=": {},
	"g92PTAqC4jctZFmPZBgRxF27h4JAz96XF7b9cOQAZ4c=": {},
}

var denyDescriptions = map[string]struct{}{
	"Google 'ParcelYard2026h2' log": {}, "Google 'ParcelYard2027h1' log": {},
	"DigiCert 'Sphinx2026h2'": {}, "DigiCert 'Sphinx2026h2' log": {},
	"DigiCert 'Sphinx2027h1'": {}, "DigiCert 'Sphinx2027h1' log": {},
	"Let's Encrypt 'Sycamore2026h2'": {}, "Let's Encrypt 'Sycamore2027h1'": {},
	"Let's Encrypt 'Willow2027h1'": {}, "HARICA Selene2027h1": {},
	"Sectigo 'Mammoth2026h2'": {}, "Sectigo 'Sabre2026h2'": {},
}

var denyURLs = map[string]struct{}{
	"https://storage.googleapis.com/parcelyard2026h2.prod.certificate.transparency.goog": {},
	"https://storage.googleapis.com/parcelyard2027h1.prod.certificate.transparency.goog": {},
	"https://sphinx.ct.digicert.com/2026h2":                                              {},
	"https://sphinx.ct.digicert.com/2027h1":                                              {},
	"https://mammoth2026h2.ct.sectigo.com":                                               {},
	"https://sabre2026h2.ct.sectigo.com":                                                 {},
	"https://mon.sycamore.ct.letsencrypt.org/2026h2":                                     {},
	"https://mon.sycamore.ct.letsencrypt.org/2027h1":                                     {},
	"https://mon.willow.ct.letsencrypt.org/2027h1":                                       {},
	"https://selene.mon.ct.harica.eu/selene2027h1":                                       {},
}

func denied(raw rawLog) bool {
	if id := canonicalLogID(raw.LogID); id != "" {
		if _, ok := denyLogIDs[id]; ok {
			return true
		}
	}
	if _, ok := denyDescriptions[raw.Description]; ok {
		return true
	}
	for _, candidate := range []string{raw.URL, raw.MonitoringURL} {
		if normalized, ok := normalizeURL(candidate); ok {
			if _, found := denyURLs[normalized]; found {
				return true
			}
		}
	}
	return false
}

// cursor is the in-memory position of one worker. size is the last observed
// tree size; it is refreshed only when the worker has no known work left.
// partialSince is when the worker first waited on an incomplete data tile.
type cursor struct {
	next, size   uint64
	partialSince time.Time
}

func (c *cursor) caughtUp() bool { return c.next >= c.size }

func (s *Stream) runWorker(ctx context.Context, spec logSpec) {
	backoff := time.Second
	initialized := false
	var cur cursor
	for {
		var err error
		idle := true
		if !initialized {
			if spec.kind == sourceTiled {
				cur.next, err = s.fetchCheckpoint(ctx, spec.baseURL)
			} else {
				cur.next, err = s.fetchSTH(ctx, spec.baseURL)
			}
			cur.size = cur.next
			initialized = err == nil
		} else if spec.kind == sourceTiled {
			idle, err = s.pollTiled(ctx, spec, &cur)
		} else {
			idle, err = s.pollRFC6962(ctx, spec, &cur)
		}
		if err == nil {
			backoff = time.Second
			// A worker that is behind fetches the next batch immediately.
			if !idle {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			if !sleepContext(ctx, s.cfg.PollInterval) {
				return
			}
			continue
		}
		if ctx.Err() != nil {
			return
		}
		s.stats.fetchErrors.Add(1)
		if !sleepContext(ctx, jittered(backoff)) {
			return
		}
		if backoff < time.Minute {
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
	}
}

func (s *Stream) fetchSTH(ctx context.Context, base string) (uint64, error) {
	var sth struct {
		TreeSize uint64 `json:"tree_size"`
	}
	err := s.getJSON(ctx, base+"/ct/v1/get-sth", 1<<20, &sth)
	return sth.TreeSize, err
}

// pollRFC6962 fetches one get-entries batch. It fetches a new STH only when the
// cursor has caught up with the last known tree size. idle reports that no new
// entries are known, so the caller should wait before the next poll.
func (s *Stream) pollRFC6962(ctx context.Context, spec logSpec, cur *cursor) (idle bool, err error) {
	if cur.caughtUp() {
		size, err := s.fetchSTH(ctx, spec.baseURL)
		if err != nil {
			return true, err
		}
		if size > cur.size {
			cur.size = size
		}
		if cur.caughtUp() {
			return true, nil
		}
	}
	next := &cur.next
	end := *next + uint64(s.cfg.BatchSize) - 1
	if end >= cur.size {
		end = cur.size - 1
	}
	endpoint := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", spec.baseURL, *next, end)
	var response struct {
		Entries []struct {
			LeafInput string `json:"leaf_input"`
		} `json:"entries"`
	}
	if err := s.getJSON(ctx, endpoint, maxResponseBody, &response); err != nil {
		return true, err
	}
	if len(response.Entries) == 0 || len(response.Entries) > int(end-*next+1) {
		return true, errors.New("ctstream: invalid get-entries count")
	}
	for _, raw := range response.Entries {
		leaf, err := base64.StdEncoding.DecodeString(raw.LeafInput)
		if err != nil || len(leaf) > maxResponseBody {
			s.stats.malformed.Add(1)
			*next++
			continue
		}
		der, tbs, err := parseLeafInput(leaf)
		if err != nil {
			s.stats.malformed.Add(1)
			*next++
			continue
		}
		if !s.emit(ctx, Entry{DER: der, IsTBS: tbs}) {
			return true, ctx.Err()
		}
		*next++
	}
	return cur.caughtUp(), nil
}

func (s *Stream) fetchCheckpoint(ctx context.Context, base string) (uint64, error) {
	body, err := s.get(ctx, base+"/checkpoint", 64<<10)
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	if !scanner.Scan() || scanner.Text() == "" || !scanner.Scan() {
		return 0, errors.New("ctstream: invalid checkpoint")
	}
	size, err := strconv.ParseUint(scanner.Text(), 10, 64)
	if err != nil || !scanner.Scan() || scanner.Text() == "" {
		return 0, errors.New("ctstream: invalid checkpoint")
	}
	return size, scanner.Err()
}

// pollTiled fetches at most one data tile. It fetches a new checkpoint only when
// the cursor has caught up with the last known tree size.
//
// Full tiles are preferred: a partial tile repeats every entry that an earlier
// partial fetch of the same tile already returned. Pending entries in an
// incomplete tile are fetched only after they have waited PartialTileDelay.
func (s *Stream) pollTiled(ctx context.Context, spec logSpec, cur *cursor) (idle bool, err error) {
	// A worker that waits for the current tile to fill also needs a fresh
	// checkpoint. A worker that is behind by full tiles does not.
	tileEnd := (cur.next/tileWidth + 1) * tileWidth
	if cur.caughtUp() || cur.size < tileEnd {
		size, err := s.fetchCheckpoint(ctx, spec.baseURL)
		if err != nil {
			return true, err
		}
		if size > cur.size {
			cur.size = size
		}
		if cur.caughtUp() {
			return true, nil
		}
	}
	tile := cur.next / tileWidth
	available := cur.size - tile*tileWidth
	width := uint64(tileWidth)
	path := encodeTilePath(tile)
	if available < tileWidth {
		if cur.partialSince.IsZero() {
			cur.partialSince = time.Now()
		}
		if time.Since(cur.partialSince) < s.cfg.PartialTileDelay {
			return true, nil
		}
		width = available
		path += ".p/" + strconv.FormatUint(width, 10)
	}
	body, err := s.get(ctx, spec.baseURL+"/tile/data/"+path, maxResponseBody)
	if err != nil {
		return true, err
	}
	entries, err := parseTileData(body, int(width))
	if err != nil || len(entries) != int(width) {
		s.stats.malformed.Add(1)
		if err == nil {
			err = errMalformedWire
		}
		return true, err
	}
	start := int(cur.next - tile*tileWidth)
	for i := start; i < len(entries); i++ {
		if !s.emit(ctx, Entry{DER: entries[i].der, IsTBS: entries[i].isTBS}) {
			return true, ctx.Err()
		}
		cur.next++
	}
	cur.partialSince = time.Time{}
	return cur.caughtUp(), nil
}

func (s *Stream) emit(ctx context.Context, entry Entry) bool {
	select {
	case <-ctx.Done():
		return false
	case s.entries <- entry:
		s.stats.entries.Add(1)
		return true
	}
}

func encodeTilePath(index uint64) string {
	groups := []string{fmt.Sprintf("%03d", index%1000)}
	for index /= 1000; index > 0; index /= 1000 {
		groups = append(groups, fmt.Sprintf("x%03d", index%1000))
	}
	for i, j := 0, len(groups)-1; i < j; i, j = i+1, j-1 {
		groups[i], groups[j] = groups[j], groups[i]
	}
	return strings.Join(groups, "/")
}
