package main

import (
	"context"
	"encoding/json"
	"errors"

	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strconv"

	"sync/atomic"
	"syscall"
	"time"

	"github.com/aels/ct-sorter/internal/config"
	"github.com/aels/ct-sorter/internal/ctstream"
	"github.com/aels/ct-sorter/internal/dedup"
	"github.com/aels/ct-sorter/internal/dnsresolver"
	"github.com/aels/ct-sorter/internal/domain"
	"github.com/aels/ct-sorter/internal/sorter"
	webhub "github.com/aels/ct-sorter/internal/web"
)

type domainCounters struct{ extracted, invalid, builtinFiltered, customFiltered, duplicates, published atomic.Uint64 }

type app struct {
	start            time.Time
	cfg              config.Config
	ct               *ctstream.Stream
	hub              *webhub.Hub
	sorter           *sorter.Sorter
	resolverCounters *dnsresolver.Counters
	dom              domainCounters
	routes           []string
}

type statsSnapshot struct {
	SnapshotUnix int64                        `json:"snapshot_unix"`
	Uptime       uint64                       `json:"uptime_seconds"`
	CT           any                          `json:"ct"`
	Domains      any                          `json:"domains"`
	DNS          any                          `json:"dns"`
	HTTP         any                          `json:"http"`
	Queues       any                          `json:"queues"`
	Routes       map[string]webhub.RouteStats `json:"routes"`
}

func main() {
	if os.Getenv("CT_SORTER_DAEMON_CHILD") != "" {
		_ = os.Chdir("/")
		syscall.Umask(0o027)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	cfg, done, err := config.Parse(os.Args[1:], os.Stderr)
	if err != nil {
		log.Printf("configuration error: %v", err)
		os.Exit(2)
	}
	if done {
		return
	}
	if cfg.Daemon && os.Getenv("CT_SORTER_DAEMON_CHILD") == "" {
		if err := daemonize(); err != nil {
			log.Printf("daemon: %v", err)
			os.Exit(1)
		}
		return
	}
	if err := run(cfg); err != nil {
		notifyParent("ERROR " + err.Error())
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func daemonize() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		if a != "-d" && a != "--daemon" {
			args = append(args, a)
		}
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	defer r.Close()
	null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), "CT_SORTER_DAEMON_CHILD=1")
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	cmd.ExtraFiles = []*os.File{w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err = cmd.Start(); err != nil {
		w.Close()
		return err
	}
	_ = w.Close()
	ch := make(chan string, 1)
	go func() { buf := make([]byte, 1024); n, _ := r.Read(buf); ch <- string(buf[:n]) }()
	select {
	case msg := <-ch:
		if msg == "READY" {
			return nil
		}
		if msg == "" {
			return errors.New("child exited before readiness")
		}
		return errors.New(msg)
	case <-time.After(45 * time.Second):
		return errors.New("readiness timeout")
	}
}

func notifyParent(message string) {
	if os.Getenv("CT_SORTER_DAEMON_CHILD") == "" {
		return
	}
	f := os.NewFile(3, "daemon-ready")
	if f != nil {
		_, _ = f.WriteString(message)
		_ = f.Close()
	}
}

func run(cfg config.Config) error {
	bind := "127.0.0.1"
	if cfg.Expose {
		bind = "0.0.0.0"
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(cfg.Port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	routes := make([]string, 0, len(cfg.Sort)+1)
	for _, r := range cfg.Sort {
		routes = append(routes, r.Path)
	}
	hub, err := webhub.NewHub(routes, cfg.ClientBufferMB*1024*1024)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	application := &app{start: time.Now(), cfg: cfg, hub: hub, routes: append([]string{"all"}, routes...), resolverCounters: &dnsresolver.Counters{}}
	filter, err := domain.NewFilter(cfg.NoFilter, cfg.Filter)
	if err != nil {
		return err
	}

	if len(cfg.Sort) > 0 {
		var servers []netip.Addr
		if cfg.DNSServers != "" {
			servers, err = dnsresolver.ParseServers(cfg.DNSServers)
			if err != nil {
				return err
			}
		}
		resolver, err := dnsresolver.New(dnsresolver.Config{Servers: servers, Timeout: cfg.DNSTimeout, Counters: application.resolverCounters, Hooks: dnsresolver.Hooks{PoolChanged: func(p []netip.Addr) { log.Printf("DNS pool updated: %v", p) }}})
		if err != nil {
			return err
		}
		resolver.StartRefresh(ctx)
		defer resolver.Close()
		application.sorter, err = sorter.New(ctx, sorter.Config{Rules: cfg.Sort, Threads: cfg.Threads, ConnectTimeout: cfg.ConnectTimeout, ResponseTimeout: cfg.ResponseTimeout, BodyLimit: cfg.BodyLimitKB * 1024, Resolver: resolver, Publish: func(path, name string) { hub.Publish(path, name) }})
		if err != nil {
			return err
		}
		defer application.sorter.Close()
	}

	application.ct = ctstream.New(ctstream.Config{})
	if err = application.ct.Start(ctx); err != nil {
		return err
	}
	server := &http.Server{Handler: hub.Handler(), ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() {
		e := server.Serve(listener)
		if !errors.Is(e, http.ErrServerClosed) {
			serveErr <- e
		}
		close(serveErr)
	}()
	if os.Getenv("CT_SORTER_DAEMON_CHILD") != "" {
		go func() {
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if application.ct.Stats().Reconciliations > 0 {
						notifyParent("READY")
						return
					}
				}
			}
		}()
	}
	log.Printf("ct-sorter %s listening on %s", config.Version, listener.Addr())

	seen := dedup.New(100000)
	go func() {
		for entry := range application.ct.Entries() {
			var names []string
			var e error
			if entry.IsTBS {
				names, e = domain.ExtractTBSCertificate(entry.DER)
			} else {
				names, e = domain.ExtractCertificate(entry.DER)
			}
			if e != nil {
				application.dom.invalid.Add(1)
				continue
			}
			application.dom.extracted.Add(uint64(len(names)))
			for _, name := range names {
				builtin, custom := filter.Match(name)
				if builtin {
					application.dom.builtinFiltered.Add(1)
				}
				if custom {
					application.dom.customFiltered.Add(1)
				}
				if builtin || custom {
					continue
				}
				if !seen.Add(name) {
					application.dom.duplicates.Add(1)
					continue
				}
				hub.PublishAll(name)
				application.dom.published.Add(1)
				if application.sorter != nil {
					application.sorter.Submit(name)
				}
			}
		}
	}()
	application.updateStats()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				application.updateStats()
			}
		}
	}()

	select {
	case <-ctx.Done():
	case e := <-serveErr:
		if e != nil {
			return e
		}
	}
	log.Printf("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	_ = hub.Shutdown(shutdownCtx)
	application.updateStats()
	return nil
}

func (a *app) updateStats() {
	ct := a.ct.Stats()
	var ss sorter.Stats
	if a.sorter != nil {
		ss = a.sorter.Stats()
	}
	rc := a.resolverCounters
	routes := make(map[string]webhub.RouteStats, len(a.routes))
	for _, name := range a.routes {
		if s, ok := a.hub.RouteStats(name); ok {
			routes[name] = s
		}
	}
	s := statsSnapshot{SnapshotUnix: time.Now().Unix(), Uptime: uint64(time.Since(a.start).Seconds()),
		CT:      map[string]uint64{"active_logs": ct.Workers, "entries": ct.Entries, "parse_errors": ct.Malformed, "source_errors": ct.FetchErrors},
		Domains: map[string]uint64{"extracted": a.dom.extracted.Load(), "invalid": a.dom.invalid.Load(), "builtin_filtered": a.dom.builtinFiltered.Load(), "custom_filtered": a.dom.customFiltered.Load(), "duplicates": a.dom.duplicates.Load(), "published_all": a.dom.published.Load()},
		DNS:     map[string]uint64{"queries": rc.Queries.Load(), "errors": rc.Errors.Load(), "timeouts": rc.Timeouts.Load(), "truncated": rc.Truncated.Load(), "private_address_drops": ss.PrivateAddressDrops},
		HTTP:    map[string]uint64{"http_200": ss.HTTP200, "https_200": ss.HTTPS200, "non_200": ss.Non200, "connect_errors": ss.ConnectErrors, "read_timeouts": ss.ReadTimeouts, "body_limit_hits": ss.BodyLimitHits},
		Queues:  map[string]any{"sort_length": ss.QueueLength, "sort_capacity": ss.QueueCapacity, "sort_queue_dropped": ss.QueueDropped}, Routes: routes}
	data, err := json.Marshal(s)
	if err == nil {
		a.hub.SetStatsSnapshot(data)
	}
}
