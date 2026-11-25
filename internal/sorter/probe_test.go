package sorter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseProbes(t *testing.T) {
	got, err := ParseProbes("http:80, HTTPS:443,3000,http:3000")
	if err != nil {
		t.Fatal(err)
	}
	if want := "[http:80 https:443 https:3000 http:3000]"; fmt.Sprint(got) != want {
		t.Fatalf("ParseProbes = %v, want %s", got, want)
	}
	for _, value := range []string{"", " ", "0", "65536", "ftp:21", "http:", ":80", "http:x", "80,", "https:443:1"} {
		if _, err := ParseProbes(value); err == nil {
			t.Errorf("ParseProbes(%q) succeeded", value)
		}
	}
}

func TestProbeURLHost(t *testing.T) {
	for _, tc := range []struct {
		probe Probe
		want  string
	}{
		{Probe{HTTPS: true, Port: 443}, "example.com"},
		{Probe{HTTPS: false, Port: 80}, "example.com"},
		{Probe{HTTPS: true, Port: 80}, "example.com:80"},
		{Probe{HTTPS: false, Port: 3000}, "example.com:3000"},
	} {
		if got := tc.probe.urlHost("example.com"); got != tc.want {
			t.Errorf("%s: urlHost = %q, want %q", tc.probe, got, tc.want)
		}
	}
}

func TestCustomProbesOrderAndHostPort(t *testing.T) {
	var mu sync.Mutex
	var hosts []string
	recordHost := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			hosts = append(hosts, r.Host)
			mu.Unlock()
			next(w, r)
		}
	}
	redirect := func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusFound) }
	needle := func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("Needle")) }
	httpAddr, httpsAddr, sni := newSchemeServers(t, recordHost(redirect), recordHost(needle))

	var dialed []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, address)
		mu.Unlock()
		target := httpAddr
		if strings.HasSuffix(address, ":8443") {
			target = httpsAddr
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
	published := make(chan string, 1)
	s, err := New(context.Background(), Config{
		Rules: []Rule{{Path: "hit", Literal: "Needle"}}, Threads: 1,
		Probes:   []Probe{{HTTPS: false, Port: 8080}, {HTTPS: true, Port: 8443}, {HTTPS: false, Port: 80}},
		Resolver: stubResolver{ip: netip.MustParseAddr("93.184.216.34")}, DialContext: dial,
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
	mu.Lock()
	defer mu.Unlock()
	// The third probe is not tried: the second one succeeded.
	if want := "[93.184.216.34:8080 93.184.216.34:8443]"; fmt.Sprint(dialed) != want {
		t.Fatalf("dial addresses = %v, want %s", dialed, want)
	}
	if want := "[example.com:8080 example.com:8443]"; fmt.Sprint(hosts) != want {
		t.Fatalf("Host headers = %v, want %s", hosts, want)
	}
	if sni() != "example.com" {
		t.Fatalf("SNI = %q", sni())
	}
	if st := s.Stats(); st.Non200 != 1 || st.HTTPS200 != 1 {
		t.Fatalf("stats = %+v", st)
	}
}
