package sorter

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type stubResolver struct {
	ip  netip.Addr
	err error
}

func (r stubResolver) LookupIPv4(context.Context, string) (netip.Addr, error) { return r.ip, r.err }

func TestParseRule(t *testing.T) {
	got, err := ParseRule("shop:a:b")
	if err != nil || got.Path != "shop" || got.Literal != "a:b" {
		t.Fatalf("ParseRule = %#v, %v", got, err)
	}
	for _, value := range []string{"", "x:", ":x", ".x:y", "all:y", "UP:y", "x:\xff"} {
		if _, err := ParseRule(value); err == nil {
			t.Errorf("ParseRule(%q) succeeded", value)
		}
	}
}

// gzipNeedleHandler serves a gzip body larger than the test body limit.
func gzipNeedleHandler(t *testing.T, scheme string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("%s Host = %q", scheme, r.Host)
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Powered-By", "HeaderNeedle")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte("prefix Needle " + strings.Repeat("x", 100)))
		_ = gz.Close()
	}
}

func redirectHandler(t *testing.T, scheme string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("%s Host = %q", scheme, r.Host)
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}
}

// newSchemeServers starts a plain HTTP and a TLS server. The TLS server
// records the SNI it receives.
func newSchemeServers(t *testing.T, httpHandler, httpsHandler http.Handler) (httpAddr, httpsAddr string, sni func() string) {
	t.Helper()
	httpServer := httptest.NewServer(httpHandler)
	t.Cleanup(httpServer.Close)
	var mu sync.Mutex
	var seen string
	httpsServer := httptest.NewUnstartedServer(httpsHandler)
	httpsServer.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		seen = hello.ServerName
		mu.Unlock()
		return nil, nil
	}}
	httpsServer.StartTLS()
	t.Cleanup(httpsServer.Close)
	return strings.TrimPrefix(httpServer.URL, "http://"), strings.TrimPrefix(httpsServer.URL, "https://"),
		func() string { mu.Lock(); defer mu.Unlock(); return seen }
}

// recordingDial sends :443 to httpsAddr and every other port to httpAddr, and
// records the requested addresses in order.
func recordingDial(httpAddr, httpsAddr string) (DialContextFunc, func() []string) {
	var mu sync.Mutex
	var requested []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		requested = append(requested, address)
		mu.Unlock()
		target := httpAddr
		if strings.HasSuffix(address, ":443") {
			target = httpsAddr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	return dial, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requested...)
	}
}

func TestHTTPSFirstSkipsHTTPOnSuccess(t *testing.T) {
	httpAddr, httpsAddr, sni := newSchemeServers(t, redirectHandler(t, "HTTP"), gzipNeedleHandler(t, "HTTPS"))
	dial, requested := recordingDial(httpAddr, httpsAddr)
	published := make(chan string, 2)
	s, err := New(context.Background(), Config{
		Rules:   []Rule{{Path: "hit", Literal: "Needle"}},
		Threads: 1, Resolver: stubResolver{ip: netip.MustParseAddr("93.184.216.34")}, DialContext: dial,
		Publish: func(path, domain string) { published <- path + ":" + domain },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit("example.com")
	select {
	case got := <-published:
		if got != "hit:example.com" {
			t.Fatalf("published %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publication timeout")
	}
	stats := s.Stats()
	if stats.HTTPS200 != 1 || stats.HTTP200 != 0 || stats.Non200 != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if sni() != "example.com" {
		t.Fatalf("SNI = %q", sni())
	}
	if got := requested(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("dial addresses = %v", got)
	}
}

func TestHTTPFallbackDirectIPGzipLimitAndMatching(t *testing.T) {
	httpAddr, httpsAddr, sni := newSchemeServers(t, gzipNeedleHandler(t, "HTTP"), redirectHandler(t, "HTTPS"))
	dial, requested := recordingDial(httpAddr, httpsAddr)
	published := make(chan string, 2)
	s, err := New(context.Background(), Config{
		Rules:   []Rule{{Path: "hit", Literal: "Needle"}, {Path: "hit", Literal: "HeaderNeedle"}, {Path: "case", Literal: "needle"}},
		Threads: 1, BodyLimit: 20, Resolver: stubResolver{ip: netip.MustParseAddr("93.184.216.34")}, DialContext: dial,
		Publish: func(path, domain string) { published <- path + ":" + domain },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit("example.com")
	select {
	case got := <-published:
		if got != "hit:example.com" {
			t.Fatalf("published %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publication timeout")
	}
	select {
	case extra := <-published:
		t.Fatalf("unexpected case-insensitive match %q", extra)
	case <-time.After(30 * time.Millisecond):
	}
	stats := s.Stats()
	if stats.Non200 != 1 || stats.HTTP200 != 1 || stats.HTTPS200 != 0 || stats.BodyLimitHits != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if sni() != "example.com" {
		t.Fatalf("SNI = %q", sni())
	}
	if got := requested(); len(got) != 2 || got[0] != "93.184.216.34:443" || got[1] != "93.184.216.34:80" {
		t.Fatalf("dial addresses = %v", got)
	}
}

func TestAdditionalSuccessCodeAndHeaderMatching(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Technology", "SpecialHeader")
		w.WriteHeader(http.StatusSeeOther)
		_, _ = w.Write([]byte("ignored redirect body"))
	}))
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "http://")
	published := make(chan string, 1)
	s, err := New(context.Background(), Config{
		Rules: []Rule{{Path: "tech", Literal: "SpecialHeader"}}, SuccessCodes: []int{http.StatusSeeOther}, Threads: 1,
		Resolver: stubResolver{ip: netip.MustParseAddr("93.184.216.34")},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
		Publish: func(path, domain string) { published <- path + ":" + domain },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Submit("example.com")
	select {
	case got := <-published:
		if got != "tech:example.com" {
			t.Fatalf("published %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publication timeout")
	}
	stats := s.Stats()
	if stats.HTTPAdditionalSuccess != 1 || stats.HTTPS200 != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSubmitDropsWhileResolverIsNotReady(t *testing.T) {
	var resolved atomic.Bool
	s, err := New(context.Background(), Config{
		Rules: []Rule{{Path: "x", Literal: "x"}}, Threads: 1,
		Resolver: resolverFunc(func() { resolved.Store(true) }),
		Ready:    func() bool { return false },
		Publish:  func(string, string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Submit("example.com")
	s.Close()
	if resolved.Load() || s.Stats().NotReadyDrops != 1 || s.Stats().QueueLength != 0 {
		t.Fatalf("resolved=%v stats=%+v", resolved.Load(), s.Stats())
	}
}

type resolverFunc func()

func (f resolverFunc) LookupIPv4(context.Context, string) (netip.Addr, error) {
	f()
	return netip.Addr{}, context.Canceled
}

func TestPrivateAddressRejectedBeforeDial(t *testing.T) {
	dialed := false
	s, err := New(context.Background(), Config{
		Rules: []Rule{{Path: "x", Literal: "x"}}, Threads: 1,
		Resolver:    stubResolver{ip: netip.MustParseAddr("127.0.0.1")},
		DialContext: func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, context.Canceled },
		Publish:     func(string, string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Submit("example.com")
	deadline := time.Now().Add(time.Second)
	for s.Stats().PrivateAddressDrops == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s.Close()
	if dialed || s.Stats().PrivateAddressDrops != 1 {
		t.Fatalf("dialed=%v stats=%+v", dialed, s.Stats())
	}
}
