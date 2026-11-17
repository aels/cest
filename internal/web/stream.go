package web

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	maxBatch       = 100
	websocketLimit = 512
	writeTimeout   = time.Minute
)

var routeNameRE = regexp.MustCompile(`^[a-z0-9_-][a-z0-9_.-]*$`)

// ClientQueue is a byte-limited overwrite-oldest FIFO. Byte accounting includes
// one byte per item for the newline used while batching frames.
type ClientQueue struct {
	mu      sync.Mutex
	items   []string
	head    int
	length  int
	bytes   int
	limit   int
	dropped uint64
	wake    chan struct{}
	closed  bool
}

func NewClientQueue(byteLimit int) *ClientQueue {
	if byteLimit <= 0 {
		panic("web: client queue byte limit must be positive")
	}
	return &ClientQueue{limit: byteLimit, wake: make(chan struct{}, 1)}
}

// Push never blocks. It returns the number of old/new messages dropped.
func (q *ClientQueue) Push(message string) uint64 {
	size := len(message) + 1
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0
	}
	if size > q.limit {
		q.dropped++
		return 1
	}
	var dropped uint64
	for q.length > 0 && q.bytes+size > q.limit {
		q.bytes -= len(q.items[q.head]) + 1
		q.items[q.head] = ""
		q.head = (q.head + 1) % len(q.items)
		q.length--
		dropped++
	}
	if q.length == len(q.items) {
		q.items = append(q.items, message)
	} else {
		index := (q.head + q.length) % len(q.items)
		q.items[index] = message
	}
	q.length++
	q.bytes += size
	q.dropped += dropped
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return dropped
}

// PopBatch returns up to max oldest messages.
func (q *ClientQueue) PopBatch(max int) []string {
	if max <= 0 {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if max > q.length {
		max = q.length
	}
	batch := make([]string, max)
	for i := range batch {
		batch[i] = q.items[q.head]
		q.bytes -= len(batch[i]) + 1
		q.items[q.head] = ""
		q.head = (q.head + 1) % len(q.items)
		q.length--
	}
	if q.length == 0 {
		q.head = 0
	}
	return batch
}

func (q *ClientQueue) Len() int        { q.mu.Lock(); defer q.mu.Unlock(); return q.length }
func (q *ClientQueue) Bytes() int      { q.mu.Lock(); defer q.mu.Unlock(); return q.bytes }
func (q *ClientQueue) Dropped() uint64 { q.mu.Lock(); defer q.mu.Unlock(); return q.dropped }
func (q *ClientQueue) Close() {
	q.mu.Lock()
	q.closed = true
	q.items = nil
	q.length, q.bytes = 0, 0
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

type route struct {
	mu        sync.RWMutex
	clients   map[*streamClient]struct{}
	published atomic.Uint64
	dropped   atomic.Uint64
}

type streamClient struct {
	conn       *websocket.Conn
	queue      *ClientQueue
	batchLimit int
	done       chan struct{}
	once       sync.Once
}

// RouteStats is an inexpensive atomic snapshot for one route.
type RouteStats struct {
	Clients       int    `json:"clients"`
	Published     uint64 `json:"published"`
	ClientDropped uint64 `json:"client_dropped"`
}

// Hub owns independent websocket routes and their clients.
type Hub struct {
	routes      map[string]*route
	clientBytes int
	stats       atomic.Value // []byte
	upgrader    websocket.Upgrader
}

// NewHub creates /all plus the supplied dynamic route names.
func NewHub(routeNames []string, clientBufferBytes int) (*Hub, error) {
	if clientBufferBytes <= 0 {
		return nil, errors.New("web: client buffer must be positive")
	}
	routes := map[string]*route{"all": {clients: make(map[*streamClient]struct{})}}
	for _, name := range routeNames {
		if name == "all" || name == "stats" || !routeNameRE.MatchString(name) {
			return nil, errors.New("web: invalid or reserved route: " + name)
		}
		if _, exists := routes[name]; exists {
			return nil, errors.New("web: duplicate route: " + name)
		}
		routes[name] = &route{clients: make(map[*streamClient]struct{})}
	}
	h := &Hub{routes: routes, clientBytes: clientBufferBytes}
	h.stats.Store([]byte("{}"))
	h.upgrader.CheckOrigin = func(*http.Request) bool { return true }
	return h, nil
}

// SetStatsSnapshot atomically replaces the exact cached JSON served by /stats.
// The caller may rebuild it on its own five-second schedule.
func (h *Hub) SetStatsSnapshot(snapshot []byte) {
	copyOfSnapshot := append([]byte(nil), snapshot...)
	if len(copyOfSnapshot) == 0 {
		copyOfSnapshot = []byte("{}")
	}
	h.stats.Store(copyOfSnapshot)
}

// Publish fans a domain out without waiting for any client writer.
func (h *Hub) Publish(routeName, domain string) bool {
	r, ok := h.routes[routeName]
	if !ok {
		return false
	}
	r.published.Add(1)
	r.mu.RLock()
	for client := range r.clients {
		r.dropped.Add(client.queue.Push(domain))
	}
	r.mu.RUnlock()
	return true
}
func (h *Hub) PublishAll(domain string) { h.Publish("all", domain) }

func (h *Hub) RouteStats(name string) (RouteStats, bool) {
	r, ok := h.routes[name]
	if !ok {
		return RouteStats{}, false
	}
	r.mu.RLock()
	clients := len(r.clients)
	r.mu.RUnlock()
	return RouteStats{clients, r.published.Load(), r.dropped.Load()}, true
}

// Handler serves /stats, /all, and each configured /<route>.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stats", h.serveStats)
	for name := range h.routes {
		n := name
		mux.HandleFunc("GET /"+n, func(w http.ResponseWriter, r *http.Request) { h.serveWebSocket(n, w, r) })
	}
	return mux
}

func (h *Hub) serveStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.stats.Load().([]byte))
}

func (h *Hub) serveWebSocket(name string, w http.ResponseWriter, request *http.Request) {
	conn, err := h.upgrader.Upgrade(w, request, nil)
	if err != nil {
		return
	}
	// Upgraded connections are receive-only from the client's perspective:
	// TCP probes detect dead peers without requiring application-level Pong.
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return
	}
	if tcp, ok := conn.NetConn().(interface {
		SetKeepAliveConfig(net.KeepAliveConfig) error
	}); ok {
		if err := tcp.SetKeepAliveConfig(net.KeepAliveConfig{
			Enable: true, Idle: time.Minute, Interval: 15 * time.Second, Count: 4,
		}); err != nil {
			log.Printf("websocket TCP keepalive: %v", err)
		}
	}
	client := &streamClient{conn: conn, queue: NewClientQueue(h.clientBytes), batchLimit: routeBatchLimit(name), done: make(chan struct{})}
	r := h.routes[name]
	r.mu.Lock()
	r.clients[client] = struct{}{}
	r.mu.Unlock()
	remove := func() {
		client.once.Do(func() {
			r.mu.Lock()
			delete(r.clients, client)
			r.mu.Unlock()
			client.queue.Close()
			close(client.done)
			_ = conn.Close()
		})
	}
	go h.writeClient(client, remove)
	h.readClient(client, remove)
}

func routeBatchLimit(routeName string) int {
	if routeName == "all" {
		return maxBatch
	}
	return 1
}

func (h *Hub) writeClient(client *streamClient, remove func()) {
	defer remove()
	for {
		select {
		case <-client.done:
			return
		case <-client.queue.wake:
			for {
				batch := client.queue.PopBatch(client.batchLimit)
				if len(batch) == 0 {
					break
				}
				_ = client.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
				if err := client.conn.WriteMessage(websocket.TextMessage, []byte(strings.Join(batch, "\n"))); err != nil {
					return
				}
			}
		}
	}
}

func (h *Hub) readClient(client *streamClient, remove func()) {
	defer remove()
	client.conn.SetReadLimit(websocketLimit)

	for {
		if _, _, err := client.conn.ReadMessage(); err != nil {
			return
		}
	}
}

// Shutdown closes every active client. ctx allows callers to share their
// graceful-shutdown deadline.
func (h *Hub) Shutdown(ctx context.Context) error {
	for _, r := range h.routes {
		r.mu.RLock()
		clients := make([]*streamClient, 0, len(r.clients))
		for c := range r.clients {
			clients = append(clients, c)
		}
		r.mu.RUnlock()
		for _, c := range clients {
			_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutdown"), time.Now().Add(time.Second))
			_ = c.conn.Close()
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
