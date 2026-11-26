package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aels/cest/internal/dnsresolver"
	"github.com/aels/cest/internal/domain"
	"github.com/aels/cest/internal/sorter"
)

const Version = "0.1.0"

type Config struct {
	NoFilter                                    bool
	Filter                                      string
	WSPort                                      int
	Streams                                     []sorter.Rule
	SuccessCodes                                []int
	Probes                                      []sorter.Probe // nil selects sorter.DefaultProbes
	DNSServers                                  string
	Expose, Daemon                              bool
	Threads, ClientBufferMB, BodyLimitKB        int
	DNSTimeout, ConnectTimeout, ResponseTimeout time.Duration
}

type onceValue struct {
	name  string
	set   bool
	apply func(string) error
}

func (v *onceValue) String() string { return "" }
func (v *onceValue) Set(s string) error {
	if v.set {
		return fmt.Errorf("flag --%s may only be specified once", v.name)
	}
	v.set = true
	return v.apply(s)
}

type multiValue struct{ values *[]string }

func (v *multiValue) String() string     { return strings.Join(*v.values, ",") }
func (v *multiValue) Set(s string) error { *v.values = append(*v.values, s); return nil }

func Parse(args []string, stderr io.Writer) (Config, bool, error) {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			printUsage(stderr)
			return Config{}, true, nil
		}
		if arg == "-v" || arg == "--version" {
			fmt.Fprintln(stderr, Version)
			return Config{}, true, nil
		}
	}
	cfg := Config{WSPort: 4949, Threads: 2000, ClientBufferMB: 10, BodyLimitKB: 200, DNSTimeout: time.Second, ConnectTimeout: sorter.DefaultConnectTimeout, ResponseTimeout: sorter.DefaultResponseTimeout}
	fs := flag.NewFlagSet("cest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rawStreams []string
	var help, version bool
	boolAlias := func(short, long string, ptr *bool, usage string) {
		fs.BoolVar(ptr, short, false, usage)
		if long != short {
			fs.BoolVar(ptr, long, false, usage)
		}
	}
	boolAlias("nf", "nofilter", &cfg.NoFilter, "disable built-in filter")
	boolAlias("expose", "expose", &cfg.Expose, "listen on 0.0.0.0")
	boolAlias("d", "daemon", &cfg.Daemon, "run in background")
	boolAlias("h", "help", &help, "show help")
	boolAlias("v", "version", &version, "show version")
	addOnce := func(names []string, name string, apply func(string) error, usage string) {
		v := &onceValue{name: name, apply: apply}
		for _, n := range names {
			fs.Var(v, n, usage)
		}
	}
	atoi := func(dst *int) func(string) error {
		return func(s string) error {
			n, e := strconv.Atoi(s)
			if e != nil {
				return e
			}
			*dst = n
			return nil
		}
	}
	duration := func(dst *time.Duration) func(string) error {
		return func(s string) error {
			d, e := time.ParseDuration(s)
			if e != nil {
				return e
			}
			*dst = d
			return nil
		}
	}
	addOnce([]string{"f", "filter"}, "filter", func(s string) error { cfg.Filter = s; return nil }, "additional regexp")
	addOnce([]string{"ws-port"}, "ws-port", atoi(&cfg.WSPort), "HTTP/WebSocket listen port")
	addOnce([]string{"p", "ports"}, "ports", func(value string) error {
		probes, err := sorter.ParseProbes(value)
		if err != nil {
			return err
		}
		cfg.Probes = probes
		return nil
	}, "ordered HTTP probe list")
	addOnce([]string{"dns"}, "dns", func(s string) error { cfg.DNSServers = s; return nil }, "DNS IPv4 list")
	addOnce([]string{"t", "threads"}, "threads", atoi(&cfg.Threads), "sort workers")
	addOnce([]string{"client-buffer-mb"}, "client-buffer-mb", atoi(&cfg.ClientBufferMB), "per-client buffer")
	addOnce([]string{"body-limit-kb"}, "body-limit-kb", atoi(&cfg.BodyLimitKB), "response body limit")
	addOnce([]string{"dns-timeout"}, "dns-timeout", duration(&cfg.DNSTimeout), "DNS timeout")
	addOnce([]string{"connect-timeout"}, "connect-timeout", duration(&cfg.ConnectTimeout), "connect timeout")
	addOnce([]string{"response-timeout"}, "response-timeout", duration(&cfg.ResponseTimeout), "response timeout")
	addOnce([]string{"c", "code"}, "code", func(value string) error {
		codes, err := parseCodes(value)
		if err != nil {
			return err
		}
		cfg.SuccessCodes = codes
		return nil
	}, "additional successful HTTP status codes")
	mv := &multiValue{values: &rawStreams}
	fs.Var(mv, "s", "path:literal (repeatable)")
	fs.Var(mv, "stream", "path:literal (repeatable)")
	fs.Usage = func() { printUsage(stderr) }
	if err := fs.Parse(args); err != nil {
		return cfg, false, err
	}
	if fs.NArg() != 0 {
		return cfg, false, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if help || version {
		return cfg, true, nil
	}
	if cfg.WSPort < 1 || cfg.WSPort > 65535 {
		return cfg, false, errors.New("ws-port must be 1..65535")
	}
	if cfg.Threads < 1 || cfg.Threads > 100000 {
		return cfg, false, errors.New("threads must be 1..100000")
	}
	if cfg.ClientBufferMB < 1 || cfg.BodyLimitKB < 1 {
		return cfg, false, errors.New("buffer/body limits must be positive")
	}
	if cfg.DNSTimeout <= 0 || cfg.ConnectTimeout <= 0 || cfg.ResponseTimeout <= 0 {
		return cfg, false, errors.New("timeouts must be positive")
	}
	if _, err := domain.NewFilter(cfg.NoFilter, cfg.Filter); err != nil {
		return cfg, false, err
	}
	if cfg.DNSServers != "" {
		if _, err := dnsresolver.ParseServers(cfg.DNSServers); err != nil {
			return cfg, false, err
		}
	}
	for _, raw := range rawStreams {
		r, err := sorter.ParseRule(raw)
		if err != nil {
			return cfg, false, err
		}
		cfg.Streams = append(cfg.Streams, r)
	}
	return cfg, false, nil
}

func parseCodes(value string) ([]int, error) {
	if value == "" {
		return nil, errors.New("code list must not be empty")
	}
	seen := make(map[int]struct{})
	codes := make([]int, 0)
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		code, err := strconv.Atoi(raw)
		if err != nil || code < 100 || code > 599 {
			return nil, fmt.Errorf("invalid HTTP status code %q: expected 100..599", raw)
		}
		if code == http.StatusOK {
			continue
		}
		if _, exists := seen[code]; exists {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
	}
	return codes, nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: cest [options]
  -nf, --nofilter                 disable built-in filter
  -f, --filter REGEX              additional case-insensitive exclusion regexp
  -ws-port, --ws-port PORT        HTTP/WebSocket listen port (default 4949)
  -s, --stream PATH:LITERAL       repeatable header/body classifier
  -p, --ports LIST                ordered probe list, e.g. http:80,https:443,3000
                                  (default https:443,http:80)
  -c, --code CODE,CODE            additional successful HTTP status codes
  -dns, --dns IP,IP,...           custom UDP DNS servers
  -expose, --expose               listen on 0.0.0.0
  -t, --threads N                 sorter workers (default 2000)
      --client-buffer-mb N         per-client buffer (default 10)
      --dns-timeout DURATION       DNS timeout (default 1s)
      --connect-timeout DURATION   connect timeout (default 5s)
      --response-timeout DURATION  response timeout (default 8s)
      --body-limit-kb N            response body limit (default 200)
  -d, --daemon                    run in background
  -h, --help                      show help
  -v, --version                   show version
`)
}
