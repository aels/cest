// Package dnsresolver implements a small, independent UDP-only DNS resolver.
package dnsresolver

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxCNAMEs      = 3
	maxPacketSize  = 4096
	defaultTimeout = time.Second
)

var (
	// AutomaticServers contains public IPv4 recursive resolvers from different operators.
	AutomaticServers = []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
		"149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
		"76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9", "64.6.64.6",
		"64.6.65.6", "77.88.8.8", "77.88.8.1", "156.154.70.1", "156.154.71.1",
		"195.46.39.39", "195.46.39.40", "84.200.69.80", "84.200.70.40", "45.90.28.0",
	}
	// BenchmarkHostnames are stable public names used to measure recursive resolution.
	BenchmarkHostnames = []string{"example.com", "iana.org", "cloudflare.com"}

	ErrNoServers = errors.New("dnsresolver: no DNS servers available")
	ErrNoAddress = errors.New("dnsresolver: no A address")
	ErrTruncated = errors.New("dnsresolver: truncated UDP response")
)

// Counters may be shared with an application's stats snapshot.
type Counters struct {
	Queries   atomic.Uint64
	Errors    atomic.Uint64
	Timeouts  atomic.Uint64
	Truncated atomic.Uint64
	Retries   atomic.Uint64
}

// Hooks are optional and must return quickly.
type Hooks struct {
	PoolChanged func([]netip.Addr)
	QueryDone   func(server netip.Addr, elapsed time.Duration, err error)
}

type Config struct {
	Servers  []netip.Addr // Empty selects the automatic pool.
	Timeout  time.Duration
	Counters *Counters
	Hooks    Hooks
}

type Resolver struct {
	timeout   time.Duration
	custom    bool
	counters  *Counters
	hooks     Hooks
	pool      atomic.Value // []netip.Addr
	next      atomic.Uint64
	refreshMu sync.Mutex
	cancel    context.CancelFunc
}

// ParseServers validates a comma-separated list of unique IPv4 literals.
func ParseServers(value string) ([]netip.Addr, error) {
	parts := strings.Split(value, ",")
	out := make([]netip.Addr, 0, len(parts))
	seen := make(map[netip.Addr]struct{}, len(parts))
	for _, raw := range parts {
		if raw == "" || strings.TrimSpace(raw) != raw {
			return nil, fmt.Errorf("invalid DNS server %q: expected IPv4 literal", raw)
		}
		ip, err := netip.ParseAddr(raw)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("invalid DNS server %q: expected IPv4 literal without port", raw)
		}
		if _, ok := seen[ip]; ok {
			return nil, fmt.Errorf("duplicate DNS server %q", raw)
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, ErrNoServers
	}
	return out, nil
}

func New(cfg Config) (*Resolver, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("dnsresolver: timeout must be positive")
	}
	if cfg.Counters == nil {
		cfg.Counters = &Counters{}
	}
	r := &Resolver{timeout: cfg.Timeout, custom: len(cfg.Servers) > 0, counters: cfg.Counters, hooks: cfg.Hooks}
	servers := append([]netip.Addr(nil), cfg.Servers...)
	for _, ip := range servers {
		if !ip.Is4() {
			return nil, fmt.Errorf("dnsresolver: server %s is not IPv4", ip)
		}
	}
	r.pool.Store(servers)
	return r, nil
}

// Servers returns a snapshot of the active round-robin pool.
func (r *Resolver) Servers() []netip.Addr {
	return append([]netip.Addr(nil), r.pool.Load().([]netip.Addr)...)
}

// LookupIPv4 resolves name and follows at most three CNAME transitions.
func (r *Resolver) LookupIPv4(ctx context.Context, name string) (netip.Addr, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if err := validName(name); err != nil {
		return netip.Addr{}, err
	}
	hops := 0
	for {
		res, err := r.lookupOnce(ctx, name)
		if err != nil {
			return netip.Addr{}, err
		}
		hops += res.cnameHops
		if hops > maxCNAMEs {
			return netip.Addr{}, errors.New("dnsresolver: CNAME limit exceeded")
		}
		if len(res.addrs) > 0 {
			return res.addrs[0], nil
		}
		if res.cname == "" {
			return netip.Addr{}, ErrNoAddress
		}
		name = res.cname
	}
}

func (r *Resolver) lookupOnce(ctx context.Context, name string) (parsedAnswer, error) {
	servers := r.Servers()
	if len(servers) == 0 {
		r.counters.Errors.Add(1)
		return parsedAnswer{}, ErrNoServers
	}
	start := int(r.next.Add(1)-1) % len(servers)
	attempts := 1
	if len(servers) > 1 {
		attempts = 2
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			r.counters.Retries.Add(1)
		}
		server := servers[(start+i)%len(servers)]
		r.counters.Queries.Add(1)
		began := time.Now()
		ans, err := r.exchange(ctx, server, name)
		if r.hooks.QueryDone != nil {
			r.hooks.QueryDone(server, time.Since(began), err)
		}
		if err == nil {
			return ans, nil
		}
		last = err
		if errors.Is(err, ErrTruncated) {
			r.counters.Truncated.Add(1)
		}
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			r.counters.Timeouts.Add(1)
		}
	}
	r.counters.Errors.Add(1)
	return parsedAnswer{}, last
}

func (r *Resolver) exchange(ctx context.Context, server netip.Addr, name string) (parsedAnswer, error) {
	id, err := randomID()
	if err != nil {
		return parsedAnswer{}, err
	}
	q, err := buildQuery(id, name)
	if err != nil {
		return parsedAnswer{}, err
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(server.String(), "53"))
	if err != nil {
		return parsedAnswer{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return parsedAnswer{}, err
	}
	if _, err = conn.Write(q); err != nil {
		return parsedAnswer{}, err
	}
	buf := make([]byte, maxPacketSize)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return parsedAnswer{}, err
		}
		ans, ignore, err := parseResponse(buf[:n], id, name)
		if ignore {
			continue
		}
		return ans, err
	}
}

func randomID() (uint16, error) {
	var b [2]byte
	_, err := rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:]), err
}
func isTimeout(err error) bool { var ne net.Error; return errors.As(err, &ne) && ne.Timeout() }

// Refresh benchmarks the automatic candidates and atomically installs up to ten best servers.
func (r *Resolver) Refresh(ctx context.Context) error {
	if r.custom {
		return nil
	}
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	type score struct {
		ip        netip.Addr
		successes int
		median    time.Duration
	}
	scores := make([]score, 0, len(AutomaticServers))
	for _, raw := range AutomaticServers {
		ip := netip.MustParseAddr(raw)
		times := make([]time.Duration, 0, len(BenchmarkHostnames))
		for _, host := range BenchmarkHostnames {
			began := time.Now()
			id, _ := randomID()
			q, _ := buildQuery(id, host)
			d := net.Dialer{}
			conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(ip.String(), "53"))
			if err == nil {
				deadline := time.Now().Add(r.timeout)
				if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
					deadline = dl
				}
				_ = conn.SetDeadline(deadline)
				if _, err = conn.Write(q); err == nil {
					b := make([]byte, maxPacketSize)
					var n int
					n, err = conn.Read(b)
					if err == nil {
						_, ignore, pe := parseResponse(b[:n], id, host)
						if ignore {
							err = errors.New("mismatched response")
						} else {
							err = pe
						}
					}
				}
				_ = conn.Close()
			}
			if err == nil {
				times = append(times, time.Since(began))
			}
		}
		if len(times) > 0 {
			sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
			scores = append(scores, score{ip, len(times), times[len(times)/2]})
		}
	}
	sort.SliceStable(scores, func(i, j int) bool {
		if scores[i].successes != scores[j].successes {
			return scores[i].successes > scores[j].successes
		}
		return scores[i].median < scores[j].median
	})
	if len(scores) > 10 {
		scores = scores[:10]
	}
	pool := make([]netip.Addr, len(scores))
	for i := range scores {
		pool[i] = scores[i].ip
	}
	r.pool.Store(pool)
	if r.hooks.PoolChanged != nil {
		r.hooks.PoolChanged(append([]netip.Addr(nil), pool...))
	}
	if len(pool) == 0 {
		return ErrNoServers
	}
	return nil
}

// StartRefresh performs an immediate benchmark and refreshes hourly. While no server works it retries every three seconds.
func (r *Resolver) StartRefresh(ctx context.Context) {
	if r.custom {
		return
	}
	ctx, r.cancel = context.WithCancel(ctx)
	go func() {
		delay := time.Duration(0)
		for {
			if delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
			err := r.Refresh(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				delay = 3 * time.Second
			} else {
				delay = time.Hour
			}
		}
	}()
}
func (r *Resolver) Close() {
	if r.cancel != nil {
		r.cancel()
	}
}
