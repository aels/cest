// Package ctstream follows the current ends of eligible logs in Google's v3
// CT log list. It keeps cursors only in memory and applies bounded backpressure.
package ctstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultLogListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	defaultBuffer     = 1024
	defaultBatch      = 256
	maxListBody       = 4 << 20
	maxResponseBody   = 16 << 20
	reconcileInterval = 24 * time.Hour
	initialRetry      = 3 * time.Second
)

// Entry is certificate material ready for internal/domain. IsTBS is false for
// a full DER Certificate and true for a precertificate TBSCertificate.
type Entry struct {
	DER   []byte
	IsTBS bool
}

// Config permits dependency injection and conservative tuning. Zero values use
// bounded production defaults.
type Config struct {
	HTTPClient   *http.Client
	LogListURL   string
	OutputBuffer int
	BatchSize    int
	PollInterval time.Duration
}

// Stats is a lock-free snapshot accumulated since Start.
type Stats struct {
	Workers         uint64
	Entries         uint64
	Malformed       uint64
	FetchErrors     uint64
	Reconciliations uint64
}

type counters struct {
	workers, entries, malformed, fetchErrors, reconciliations atomic.Uint64
}

// Stream owns reconciliation, workers and the bounded output queue.
type Stream struct {
	cfg     Config
	entries chan Entry
	stats   counters
	mu      sync.Mutex
	wg      sync.WaitGroup
	workers map[string]*workerHandle
	started bool
}

type workerHandle struct {
	spec   logSpec
	cancel context.CancelFunc
}

type sourceKind uint8

const (
	sourceRFC6962 sourceKind = iota
	sourceTiled
)

type logSpec struct {
	key, id, description, baseURL string
	kind                          sourceKind
}

// New constructs a stream but performs no network I/O.
func New(cfg Config) *Stream {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.LogListURL == "" {
		cfg.LogListURL = defaultLogListURL
	}
	if cfg.OutputBuffer <= 0 {
		cfg.OutputBuffer = defaultBuffer
	}
	if cfg.BatchSize <= 0 || cfg.BatchSize > defaultBatch {
		cfg.BatchSize = defaultBatch
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 2 * time.Second
	}
	return &Stream{cfg: cfg, entries: make(chan Entry, cfg.OutputBuffer), workers: make(map[string]*workerHandle)}
}

// Start starts background reconciliation and returns immediately. The first
// catalog fetch is retried every three seconds until it succeeds or ctx ends.
func (s *Stream) Start(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ctstream: nil context")
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("ctstream: already started")
	}
	s.started = true
	s.mu.Unlock()
	go s.run(ctx)
	return nil
}

func (s *Stream) Entries() <-chan Entry { return s.entries }

func (s *Stream) Stats() Stats {
	return Stats{
		Workers: s.stats.workers.Load(), Entries: s.stats.entries.Load(),
		Malformed: s.stats.malformed.Load(), FetchErrors: s.stats.fetchErrors.Load(),
		Reconciliations: s.stats.reconciliations.Load(),
	}
}

func (s *Stream) run(ctx context.Context) {
	defer close(s.entries)
	for {
		specs, err := s.fetchLogList(ctx)
		if err == nil {
			s.reconcile(ctx, specs)
			break
		}
		s.stats.fetchErrors.Add(1)
		if !sleepContext(ctx, initialRetry) {
			s.stopAll()
			return
		}
	}
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.stopAll()
			return
		case <-ticker.C:
			specs, err := s.fetchLogList(ctx)
			if err != nil {
				s.stats.fetchErrors.Add(1)
				continue
			}
			s.reconcile(ctx, specs)
		}
	}
}

func (s *Stream) stopAll() {
	s.mu.Lock()
	for key, w := range s.workers {
		w.cancel()
		delete(s.workers, key)
	}
	s.stats.workers.Store(0)
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Stream) reconcile(parent context.Context, specs []logSpec) {
	wanted := make(map[string]logSpec, len(specs))
	for _, spec := range specs {
		wanted[spec.key] = spec
	}
	s.mu.Lock()
	for key, current := range s.workers {
		next, ok := wanted[key]
		if !ok || next.baseURL != current.spec.baseURL || next.kind != current.spec.kind {
			current.cancel()
			delete(s.workers, key)
		}
	}
	for key, spec := range wanted {
		if _, ok := s.workers[key]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(parent)
		s.workers[key] = &workerHandle{spec: spec, cancel: cancel}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runWorker(ctx, spec)
		}()
	}
	s.stats.workers.Store(uint64(len(s.workers)))
	s.stats.reconciliations.Add(1)
	s.mu.Unlock()
}

type rawLog struct {
	Description   string                     `json:"description"`
	LogID         string                     `json:"log_id"`
	URL           string                     `json:"url"`
	MonitoringURL string                     `json:"monitoring_url"`
	State         map[string]json.RawMessage `json:"state"`
}

type logList struct {
	Operators []struct {
		Logs      []rawLog `json:"logs"`
		TiledLogs []rawLog `json:"tiled_logs"`
	} `json:"operators"`
}

func (s *Stream) fetchLogList(ctx context.Context) ([]logSpec, error) {
	var list logList
	if err := s.getJSON(ctx, s.cfg.LogListURL, maxListBody, &list); err != nil {
		return nil, err
	}
	var out []logSpec
	seen := make(map[string]struct{})
	for _, operator := range list.Operators {
		appendLogs := func(logs []rawLog, kind sourceKind) {
			for _, raw := range logs {
				if !eligible(raw) || denied(raw) {
					continue
				}
				base := raw.URL
				if kind == sourceTiled {
					base = raw.MonitoringURL
				}
				base, ok := normalizeURL(base)
				if !ok {
					continue
				}
				id := canonicalLogID(raw.LogID)
				key := id
				if key == "" {
					key = "url:" + base
				}
				if _, duplicate := seen[key]; duplicate {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, logSpec{key: key, id: id, description: raw.Description, baseURL: base, kind: kind})
			}
		}
		appendLogs(operator.Logs, sourceRFC6962)
		appendLogs(operator.TiledLogs, sourceTiled)
	}
	return out, nil
}

func eligible(raw rawLog) bool {
	if len(raw.State) != 1 {
		return false
	}
	_, usable := raw.State["usable"]
	_, qualified := raw.State["qualified"]
	return usable || qualified
}

func canonicalLogID(id string) string {
	b, err := base64.StdEncoding.DecodeString(id)
	if err != nil || len(b) != 32 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func normalizeURL(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	u.Host = strings.ToLower(u.Host)
	return u.String(), true
}

func (s *Stream) getJSON(ctx context.Context, endpoint string, limit int64, dst any) error {
	body, err := s.get(ctx, endpoint, limit)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("ctstream: decode %s: %w", endpoint, err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return errors.New("ctstream: trailing JSON data")
	}
	return nil
}

func (s *Stream) get(ctx context.Context, endpoint string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cest/ctstream")
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctstream: %s returned %s", endpoint, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errors.New("ctstream: response too large")
	}
	return body, nil
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jittered(d time.Duration) time.Duration {
	// Full multiplicative jitter in [0.75, 1.25).
	return d*3/4 + time.Duration(rand.Uint64N(uint64(d/2)+1))
}
