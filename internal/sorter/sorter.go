// Package sorter resolves domains and classifies their HTTP response bodies.
package sorter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/aels/cest/internal/dnsresolver"
	"github.com/aels/cest/internal/ring"
)

const (
	DefaultThreads         = 2000
	DefaultConnectTimeout  = 2 * time.Second
	DefaultResponseTimeout = 5 * time.Second
	DefaultBodyLimit       = 200 * 1024
	maxThreads             = 100000
)

// Rule maps a case-sensitive literal body substring to a publication path.
type Rule struct {
	Path    string
	Literal string
}

// ParseRule parses path:literal, splitting at the first colon.
func ParseRule(value string) (Rule, error) {
	path, literal, ok := strings.Cut(value, ":")
	if !ok || path == "" || literal == "" {
		return Rule{}, errors.New("sorter: stream rule must be path:non-empty-literal")
	}
	if path == "all" || path == "stats" || path[0] == '.' {
		return Rule{}, fmt.Errorf("sorter: invalid or reserved path %q", path)
	}
	for _, c := range path {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return Rule{}, fmt.Errorf("sorter: invalid path %q", path)
		}
	}
	if !utf8.ValidString(literal) {
		return Rule{}, errors.New("sorter: literal is not valid UTF-8")
	}
	return Rule{Path: path, Literal: literal}, nil
}

// Resolver is implemented by dnsresolver.Resolver.
type Resolver interface {
	LookupIPv4(context.Context, string) (netip.Addr, error)
}

// DialContextFunc permits deterministic network tests. address is always the
// selected numeric IPv4 and the protocol's port; it never contains the domain.
type DialContextFunc func(context.Context, string, string) (net.Conn, error)

// Config describes an independent sorter pipeline.
type Config struct {
	Rules           []Rule
	Threads         int
	ConnectTimeout  time.Duration
	ResponseTimeout time.Duration
	BodyLimit       int
	Resolver        Resolver
	DialContext     DialContextFunc
	Publish         func(path, domain string)
	SuccessCodes    []int // Additional successful HTTP statuses; 200 is always included.
}

// Counters are monotonic and safe for concurrent snapshots.
type Counters struct {
	DNSLookupErrors        atomic.Uint64
	PrivateAddressDrops    atomic.Uint64
	HTTP200                atomic.Uint64
	HTTPS200               atomic.Uint64
	HTTPAdditionalSuccess  atomic.Uint64
	HTTPSAdditionalSuccess atomic.Uint64
	Non200                 atomic.Uint64
	ConnectErrors          atomic.Uint64
	ReadTimeouts           atomic.Uint64
	BodyLimitHits          atomic.Uint64
}

// Stats is a point-in-time snapshot.
type Stats struct {
	DNSLookupErrors        uint64
	PrivateAddressDrops    uint64
	HTTP200                uint64
	HTTPS200               uint64
	HTTPAdditionalSuccess  uint64
	HTTPSAdditionalSuccess uint64
	Non200                 uint64
	ConnectErrors          uint64
	ReadTimeouts           uint64
	BodyLimitHits          uint64
	QueueLength            int
	QueueCapacity          int
	QueueDropped           uint64
}

// Sorter owns a fixed worker pool and an overwrite-oldest input queue.
type Sorter struct {
	cfg      Config
	queue    *ring.SortQueue
	counters Counters
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	wg       sync.WaitGroup
	close    sync.Once
}

func New(parent context.Context, cfg Config) (*Sorter, error) {
	if parent == nil {
		return nil, errors.New("sorter: nil context")
	}
	if len(cfg.Rules) == 0 {
		return nil, errors.New("sorter: at least one rule is required")
	}
	if cfg.Threads == 0 {
		cfg.Threads = DefaultThreads
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.ResponseTimeout == 0 {
		cfg.ResponseTimeout = DefaultResponseTimeout
	}
	if cfg.BodyLimit == 0 {
		cfg.BodyLimit = DefaultBodyLimit
	}
	if cfg.Threads < 1 || cfg.Threads > maxThreads {
		return nil, fmt.Errorf("sorter: threads must be between 1 and %d", maxThreads)
	}
	if cfg.ConnectTimeout < 0 || cfg.ResponseTimeout < 0 || cfg.BodyLimit < 0 {
		return nil, errors.New("sorter: timeouts and body limit must be positive")
	}
	if cfg.Resolver == nil {
		return nil, errors.New("sorter: resolver is required")
	}
	if cfg.Publish == nil {
		return nil, errors.New("sorter: publish callback is required")
	}
	for _, rule := range cfg.Rules {
		if _, err := ParseRule(rule.Path + ":" + rule.Literal); err != nil {
			return nil, err
		}
	}
	seenCodes := map[int]struct{}{200: {}}
	for _, code := range cfg.SuccessCodes {
		if code < 100 || code > 599 {
			return nil, fmt.Errorf("sorter: invalid successful HTTP status %d", code)
		}
		seenCodes[code] = struct{}{}
	}
	cfg.SuccessCodes = cfg.SuccessCodes[:0]
	for code := range seenCodes {
		cfg.SuccessCodes = append(cfg.SuccessCodes, code)
	}
	if cfg.DialContext == nil {
		d := &net.Dialer{Timeout: cfg.ConnectTimeout}
		cfg.DialContext = d.DialContext
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Sorter{cfg: cfg, queue: ring.NewSortQueue(cfg.Threads), ctx: ctx, cancel: cancel, wake: make(chan struct{}, cfg.Threads)}
	s.wg.Add(cfg.Threads)
	for i := 0; i < cfg.Threads; i++ {
		go s.worker()
	}
	return s, nil
}

// Submit queues domain without blocking. On overflow the oldest queued domain is discarded.
func (s *Sorter) Submit(domain string) {
	if s.ctx.Err() != nil {
		return
	}
	s.queue.Push(domain)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Sorter) worker() {
	defer s.wg.Done()
	for {
		if domain, ok := s.queue.Pop(); ok {
			s.process(domain)
			continue
		}
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
	}
}

// Close cancels in-flight work and waits for all workers.
func (s *Sorter) Close() { s.close.Do(s.cancel); s.wg.Wait() }

func (s *Sorter) Counters() *Counters { return &s.counters }
func (s *Sorter) Stats() Stats {
	return Stats{
		DNSLookupErrors: s.counters.DNSLookupErrors.Load(), PrivateAddressDrops: s.counters.PrivateAddressDrops.Load(),
		HTTP200: s.counters.HTTP200.Load(), HTTPS200: s.counters.HTTPS200.Load(),
		HTTPAdditionalSuccess: s.counters.HTTPAdditionalSuccess.Load(), HTTPSAdditionalSuccess: s.counters.HTTPSAdditionalSuccess.Load(), Non200: s.counters.Non200.Load(),
		ConnectErrors: s.counters.ConnectErrors.Load(), ReadTimeouts: s.counters.ReadTimeouts.Load(), BodyLimitHits: s.counters.BodyLimitHits.Load(),
		QueueLength: s.queue.Len(), QueueCapacity: s.queue.Capacity(), QueueDropped: s.queue.Dropped(),
	}
}

func (s *Sorter) process(domain string) {
	ip, err := s.cfg.Resolver.LookupIPv4(s.ctx, domain)
	if err != nil {
		s.counters.DNSLookupErrors.Add(1)
		return
	}
	if !dnsresolver.IsPublicIPv4(ip) {
		s.counters.PrivateAddressDrops.Add(1)
		return
	}
	response, ok := s.request(domain, ip, false)
	if !ok {
		response, ok = s.request(domain, ip, true)
	}
	if !ok {
		return
	}
	matchedPaths := make(map[string]struct{})
	for _, rule := range s.cfg.Rules {
		needle := []byte(rule.Literal)
		if bytes.Contains(response.body, needle) || headerContains(response.header, rule.Literal) {
			matchedPaths[rule.Path] = struct{}{}
		}
	}
	for path := range matchedPaths {
		s.cfg.Publish(path, domain)
	}
}
