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

func TestHTTPFallbackDirectIPGzipLimitAndMatching(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("HTTP Host = %q", r.Host)
		}
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer httpServer.Close()

	var sni string
	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" {
			t.Errorf("HTTPS Host = %q", r.Host)
		}
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte("prefix Needle " + strings.Repeat("x", 100)))
		_ = gz.Close()
	}))
	httpsServer.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = hello.ServerName
		return nil, nil
	}}
	httpsServer.StartTLS()
	defer httpsServer.Close()

	httpAddr := strings.TrimPrefix(httpServer.URL, "http://")
	httpsAddr := strings.TrimPrefix(httpsServer.URL, "https://")
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
	published := make(chan string, 2)
	s, err := New(context.Background(), Config{
		Rules:   []Rule{{Path: "hit", Literal: "Needle"}, {Path: "case", Literal: "needle"}},
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
	if stats.Non200 != 1 || stats.HTTPS200 != 1 || stats.HTTP200 != 0 || stats.BodyLimitHits != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if sni != "example.com" {
		t.Fatalf("SNI = %q", sni)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requested) != 2 || requested[0] != "93.184.216.34:80" || requested[1] != "93.184.216.34:443" {
		t.Fatalf("dial addresses = %v", requested)
	}
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
