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
	maxCNAMEs         = 3
	maxPacketSize     = 4096
	defaultTimeout    = time.Second
	automaticPoolSize = 20
	defaultSockets    = 64
)

var (
	// AutomaticServers contains public IPv4 recursive resolvers from different operators.
	AutomaticServers = []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9",
		"149.112.112.112", "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
		"76.76.2.0", "76.76.10.0", "185.228.168.9", "185.228.169.9", "64.6.64.6",
		"64.6.65.6", "77.88.8.8", "77.88.8.1", "156.154.70.1", "156.154.71.1",
		"195.46.39.39", "195.46.39.40", "84.200.69.80", "84.200.70.40", "45.90.28.0",
		// Additional public endpoints, including providers' filtering variants.
		"1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3", // Cloudflare Families
		"9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11", // Quad9
		"94.140.14.140", "94.140.14.141", "94.140.14.15", "94.140.15.16", // AdGuard
		"45.90.30.0",                // NextDNS
		"8.26.56.26", "8.20.247.20", // Comodo
		"74.82.42.42",                    // Hurricane Electric
		"185.222.222.222", "45.11.45.11", // DNS.SB
		"86.54.11.100", "86.54.11.200", // DNS4EU unfiltered
		"95.85.95.85", "2.56.220.2", // Gcore
		"223.5.5.5", "223.6.6.6", // AliDNS
		"119.29.29.29", "182.254.116.116", // DNSPod
		"101.101.101.101", "101.102.103.104", // Quad101
		"114.114.114.114", "114.114.115.115", // 114DNS
		"180.76.76.76",         // Baidu
		"1.2.4.8", "210.2.4.8", // CNNIC SDNS
		"208.67.222.220", "208.67.220.222", // OpenDNS alternate endpoints
	}
	// BenchmarkHostnames are stable public names used to measure recursive resolution.
	BenchmarkHostnames = []string{"example.com", "iana.org", "cloudflare.com"}

	ErrNoServers = errors.New("dnsresolver: no DNS servers available")
	ErrNoAddress = errors.New("dnsresolver: no A address")
	ErrTruncated = errors.New("dnsresolver: truncated UDP response")
	// ErrNXDomain is an authoritative negative answer. It is not retried.
	ErrNXDomain = errors.New("dnsresolver: NXDOMAIN")
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
	// Sockets is the maximum number of idle UDP sockets kept for reuse. Set it
	// to the number of goroutines that resolve concurrently.
	Sockets int
}

type Resolver struct {
	timeout   time.Duration
	custom    bool
	counters  *Counters
	hooks     Hooks
	pool      atomic.Value // []netip.Addr; a stored slice is never modified
	next      atomic.Uint64
	refreshMu sync.Mutex
	cancel    context.CancelFunc
	sockets   chan *udpSocket
	closed    atomic.Bool
	port      uint16 // always 53; tests override it
}

// udpSocket is an unconnected UDP socket with its own receive buffer. One
// socket serves one query at a time and is reused for later queries to any
// server, so a lookup does not open and close a socket.
type udpSocket struct {
	conn *net.UDPConn
	buf  []byte
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
	if cfg.Sockets < 0 {
		return nil, errors.New("dnsresolver: socket pool size must not be negative")
	}
	if cfg.Sockets == 0 {
		cfg.Sockets = defaultSockets
	}
	r := &Resolver{timeout: cfg.Timeout, custom: len(cfg.Servers) > 0, counters: cfg.Counters, hooks: cfg.Hooks, sockets: make(chan *udpSocket, cfg.Sockets), port: 53}
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
	return append([]netip.Addr(nil), r.servers()...)
}

func (r *Resolver) servers() []netip.Addr { return r.pool.Load().([]netip.Addr) }

// Ready reports whether the pool contains at least one server. With automatic
// selection the pool is empty until the first benchmark finds a server.
func (r *Resolver) Ready() bool { return len(r.servers()) > 0 }

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
	servers := r.servers()
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
		if errors.Is(err, ErrNXDomain) {
			break
		}
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
	if err = ctx.Err(); err != nil {
		return parsedAnswer{}, err
	}
	sock, err := r.acquireSocket()
	if err != nil {
		return parsedAnswer{}, err
	}
	// A socket stays reusable after a timeout: a late reply to this query is
	// discarded later by the source, ID, and question checks below.
	reusable := false
	defer func() { r.releaseSocket(sock, reusable) }()
	deadline := time.Now().Add(r.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err = sock.conn.SetDeadline(deadline); err != nil {
		return parsedAnswer{}, err
	}
	dst := netip.AddrPortFrom(server, r.port)
	if _, err = sock.conn.WriteToUDPAddrPort(q, dst); err != nil {
		return parsedAnswer{}, err
	}
	for {
		n, from, err := sock.conn.ReadFromUDPAddrPort(sock.buf)
		if err != nil {
			reusable = isTimeout(err)
			return parsedAnswer{}, err
		}
		if from.Addr().Unmap() != server || from.Port() != r.port {
			continue
		}
		ans, ignore, err := parseResponse(sock.buf[:n], id, name)
		if ignore {
			continue
		}
		reusable = true
		return ans, err
	}
}

func (r *Resolver) acquireSocket() (*udpSocket, error) {
	select {
	case sock := <-r.sockets:
		return sock, nil
	default:
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	return &udpSocket{conn: conn, buf: make([]byte, maxPacketSize)}, nil
}

func (r *Resolver) releaseSocket(sock *udpSocket, reusable bool) {
	if reusable && !r.closed.Load() {
		select {
		case r.sockets <- sock:
			return
		default:
		}
	}
	_ = sock.conn.Close()
}

func randomID() (uint16, error) {
	var b [2]byte
	_, err := rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:]), err
}
func isTimeout(err error) bool { var ne net.Error; return errors.As(err, &ne) && ne.Timeout() }

// Refresh benchmarks the automatic candidates and atomically installs up to
// twenty best servers. All candidates are measured in parallel, so one
// benchmark takes about len(BenchmarkHostnames) timeouts in the worst case.
func (r *Resolver) Refresh(ctx context.Context) error {
	if r.custom {
		return nil
	}
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	scores := make([]benchmarkScore, len(AutomaticServers))
	var wg sync.WaitGroup
	for i, raw := range AutomaticServers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := netip.MustParseAddr(raw)
			times := make([]time.Duration, 0, len(BenchmarkHostnames))
			for _, host := range BenchmarkHostnames {
				began := time.Now()
				if _, err := r.exchange(ctx, ip, host); err == nil {
					times = append(times, time.Since(began))
				}
			}
			if len(times) > 0 {
				sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
				scores[i] = benchmarkScore{ip, len(times), times[len(times)/2]}
			}
		}()
	}
	wg.Wait()
	// Candidates without a successful answer keep a zero score and are
	// removed by selectPool.
	pool := selectPool(scores)
	r.pool.Store(pool)
	if r.hooks.PoolChanged != nil {
		r.hooks.PoolChanged(append([]netip.Addr(nil), pool...))
	}
	if len(pool) == 0 {
		return ErrNoServers
	}
	return nil
}

type benchmarkScore struct {
	ip        netip.Addr
	successes int
	median    time.Duration
}

func selectPool(scores []benchmarkScore) []netip.Addr {
	eligible := scores[:0]
	for _, score := range scores {
		if score.successes > 0 {
			eligible = append(eligible, score)
		}
	}
	scores = eligible
	sort.SliceStable(scores, func(i, j int) bool {
		if scores[i].successes != scores[j].successes {
			return scores[i].successes > scores[j].successes
		}
		return scores[i].median < scores[j].median
	})
	if len(scores) > automaticPoolSize {
		scores = scores[:automaticPoolSize]
	}
	pool := make([]netip.Addr, len(scores))
	for i := range scores {
		pool[i] = scores[i].ip
	}
	return pool
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
	r.closed.Store(true)
	for {
		select {
		case sock := <-r.sockets:
			_ = sock.conn.Close()
		default:
			return
		}
	}
}
