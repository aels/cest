package web

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type observedTCPConn struct {
	*net.TCPConn
	mu           sync.Mutex
	readDeadline time.Time
	keepAlive    net.KeepAliveConfig
}

func (c *observedTCPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return c.TCPConn.SetReadDeadline(deadline)
}

func (c *observedTCPConn) SetKeepAliveConfig(cfg net.KeepAliveConfig) error {
	c.mu.Lock()
	c.keepAlive = cfg
	c.mu.Unlock()
	return c.TCPConn.SetKeepAliveConfig(cfg)
}

type observedListener struct {
	net.Listener
	accepted chan *observedTCPConn
}

func (l *observedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	observed := &observedTCPConn{TCPConn: conn.(*net.TCPConn)}
	l.accepted <- observed
	return observed, nil
}

func waitClients(t *testing.T, hub *Hub, path string, count int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		stats, _ := hub.RouteStats(path)
		if stats.Clients == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("route %s did not reach %d clients", path, count)
}

func TestReceiveOnlyWebSocketKeepAliveAndClientIsolation(t *testing.T) {
	hub, err := NewHub([]string{"nextjs"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(hub.Handler())
	listener := &observedListener{Listener: server.Listener, accepted: make(chan *observedTCPConn, 4)}
	server.Listener = listener
	server.Start()
	defer server.Close()
	defer hub.Shutdown(context.Background())

	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/nextjs"
	first, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	firstTCP := <-listener.accepted
	second, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondTCP := <-listener.accepted
	waitClients(t, hub, "nextjs", 2)

	for _, conn := range []*observedTCPConn{firstTCP, secondTCP} {
		conn.mu.Lock()
		deadline, cfg := conn.readDeadline, conn.keepAlive
		conn.mu.Unlock()
		if !deadline.IsZero() {
			t.Fatalf("receive-only client has read deadline: %v", deadline)
		}
		if !cfg.Enable || cfg.Idle != time.Minute || cfg.Interval != 15*time.Second || cfg.Count != 4 {
			t.Fatalf("unexpected TCP keepalive: %+v", cfg)
		}
	}

	// Neither client sends messages or Pong. A silent client still receives data.
	hub.Publish("nextjs", "first.example.org")
	for _, conn := range []*websocket.Conn{first, second} {
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		kind, data, err := conn.ReadMessage()
		if err != nil || kind != websocket.TextMessage || string(data) != "first.example.org" {
			t.Fatalf("received %q, type=%d, err=%v", data, kind, err)
		}
	}

	route := hub.routes["nextjs"]
	route.mu.RLock()
	var disconnected *streamClient
	for client := range route.clients {
		if client.conn.NetConn() == firstTCP {
			disconnected = client
		}
	}
	route.mu.RUnlock()
	if disconnected == nil {
		t.Fatal("first client not registered")
	}
	_ = first.Close()
	waitClients(t, hub, "nextjs", 1)
	select {
	case <-disconnected.done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnected client's goroutines not notified")
	}
	disconnected.queue.mu.Lock()
	closed, cleared := disconnected.queue.closed, disconnected.queue.items == nil
	disconnected.queue.mu.Unlock()
	if !closed || !cleared {
		t.Fatal("disconnected client's buffer not released")
	}

	hub.Publish("nextjs", "second.example.org")
	_, data, err := second.ReadMessage()
	if err != nil || string(data) != "second.example.org" {
		t.Fatalf("surviving client received %q, err=%v", data, err)
	}
}
