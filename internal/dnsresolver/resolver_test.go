package dnsresolver

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestAutomaticConfigurationFormat(t *testing.T) {
	if len(AutomaticServers) != 25 {
		t.Fatalf("got %d automatic servers, want 25", len(AutomaticServers))
	}
	seen := map[netip.Addr]bool{}
	for _, s := range AutomaticServers {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() {
			t.Errorf("invalid IPv4 server %q", s)
		}
		if seen[ip] {
			t.Errorf("duplicate server %s", ip)
		}
		seen[ip] = true
	}
	if len(BenchmarkHostnames) != 3 {
		t.Fatalf("got %d benchmark names, want 3", len(BenchmarkHostnames))
	}
	for _, name := range BenchmarkHostnames {
		if err := validName(name); err != nil {
			t.Errorf("invalid benchmark hostname %q: %v", name, err)
		}
		if _, err := netip.ParseAddr(name); err == nil {
			t.Errorf("benchmark hostname must not be an IP: %q", name)
		}
	}
}

func TestParseServers(t *testing.T) {
	got, err := ParseServers("1.1.1.1,8.8.8.8")
	if err != nil || len(got) != 2 {
		t.Fatalf("ParseServers: %v, %#v", err, got)
	}
	bad := []string{"", "1.1.1.1,", "1.1.1.1,1.1.1.1", "dns.example", "[::1]", "8.8.8.8:53", "1.1.1.1, 8.8.8.8"}
	for _, v := range bad {
		if _, err := ParseServers(v); err == nil {
			t.Errorf("ParseServers(%q) unexpectedly succeeded", v)
		}
	}
}

func TestBuildQueryHasEDNS4096(t *testing.T) {
	q, err := buildQuery(0x1234, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(q[10:12]) != 1 {
		t.Fatal("ARCOUNT is not one")
	}
	// The final OPT record is root, type 41, class (UDP payload) 4096, zero TTL/RDLEN.
	want := []byte{0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0}
	if !strings.Contains(string(q), string(want)) {
		t.Fatalf("query does not contain EDNS0 OPT 4096: %x", q)
	}
}

func TestParseResponseCompressedCNAMEAndA(t *testing.T) {
	q, _ := buildQuery(7, "example.com")
	msg := append([]byte(nil), q[:len(q)-11]...) // header + question, without OPT
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[6:8], 2)
	binary.BigEndian.PutUint16(msg[10:12], 0)
	// example.com CNAME target.example.com; target uses compression for example.com.
	msg = append(msg, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 9, 6, 't', 'a', 'r', 'g', 'e', 't', 0xc0, 0x0c)
	// target.example.com A 93.184.216.34. Owner points to CNAME RDATA at offset 41.
	msg = append(msg, 0xc0, 41, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
	ans, ignore, err := parseResponse(msg, 7, "example.com")
	if err != nil || ignore {
		t.Fatalf("parseResponse ignore=%v err=%v packet=%x", ignore, err, msg)
	}
	if len(ans.addrs) != 1 || ans.addrs[0].String() != "93.184.216.34" {
		t.Fatalf("unexpected answer: %#v", ans)
	}
}

func TestDecodeNameRejectsMalformedCompression(t *testing.T) {
	cases := [][]byte{{0xc0, 0}, {0xc0}, {0xc0, 0xff}, {64, 'a'}, {3, 'a'}}
	for _, msg := range cases {
		if _, _, err := decodeName(msg, 0); err == nil {
			t.Errorf("decodeName(%x) unexpectedly succeeded", msg)
		}
	}
}

func TestParseResponseIgnoresWrongIdentity(t *testing.T) {
	q, _ := buildQuery(9, "example.com")
	binary.BigEndian.PutUint16(q[2:4], 0x8180)
	if _, ignore, _ := parseResponse(q, 10, "example.com"); !ignore {
		t.Fatal("transaction ID mismatch was not ignored")
	}
	if _, ignore, _ := parseResponse(q, 9, "other.example"); !ignore {
		t.Fatal("question mismatch was not ignored")
	}
}

func TestIsPublicIPv4(t *testing.T) {
	public := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34"}
	blocked := []string{"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "172.16.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "255.255.255.255", "::1"}
	for _, s := range public {
		if !IsPublicIPv4(netip.MustParseAddr(s)) {
			t.Errorf("public address rejected: %s", s)
		}
	}
	for _, s := range blocked {
		if IsPublicIPv4(netip.MustParseAddr(s)) {
			t.Errorf("reserved address accepted: %s", s)
		}
	}
}
