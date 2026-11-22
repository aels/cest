package dnsresolver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// fakeServer answers every query with the given RCODE and counts queries.
func fakeServer(t *testing.T, rcode uint16) (*Resolver, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var queries atomic.Int32
	go func() {
		buf := make([]byte, maxPacketSize)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			queries.Add(1)
			msg := append([]byte(nil), buf[:n-11]...) // drop OPT
			binary.BigEndian.PutUint16(msg[2:4], 0x8180|rcode)
			binary.BigEndian.PutUint16(msg[10:12], 0)
			_, _ = conn.WriteToUDPAddrPort(msg, from)
		}
	}()
	server := netip.MustParseAddr("127.0.0.1")
	// The same server twice gives the resolver a retry target.
	r, err := New(Config{Servers: []netip.Addr{server, server}, Timeout: time.Second, Sockets: 4})
	if err != nil {
		t.Fatal(err)
	}
	r.port = uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	t.Cleanup(r.Close)
	return r, &queries
}

func TestNXDomainIsNotRetried(t *testing.T) {
	r, queries := fakeServer(t, 3)
	_, err := r.LookupIPv4(context.Background(), "missing.example")
	if !errors.Is(err, ErrNXDomain) {
		t.Fatalf("err = %v, want ErrNXDomain", err)
	}
	if n := queries.Load(); n != 1 {
		t.Fatalf("queries = %d, want 1", n)
	}
}

func TestServFailIsRetried(t *testing.T) {
	r, queries := fakeServer(t, 2)
	if _, err := r.LookupIPv4(context.Background(), "broken.example"); err == nil {
		t.Fatal("SERVFAIL lookup succeeded")
	}
	if n := queries.Load(); n != 2 {
		t.Fatalf("queries = %d, want 2", n)
	}
}

func TestSocketIsReused(t *testing.T) {
	r, _ := fakeServer(t, 3)
	for range 5 {
		_, _ = r.LookupIPv4(context.Background(), "missing.example")
	}
	if n := len(r.sockets); n != 1 {
		t.Fatalf("idle sockets = %d, want 1", n)
	}
}
