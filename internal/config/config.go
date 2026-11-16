package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aels/ct-sorter/internal/dnsresolver"
	"github.com/aels/ct-sorter/internal/domain"
	"github.com/aels/ct-sorter/internal/sorter"
)

const Version = "0.1.0"

type Config struct {
	NoFilter                                    bool
	Filter                                      string
	Port                                        int
	Sort                                        []sorter.Rule
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
	cfg := Config{Port: 4949, Threads: 2000, ClientBufferMB: 10, BodyLimitKB: 200, DNSTimeout: time.Second, ConnectTimeout: 2 * time.Second, ResponseTimeout: 5 * time.Second}
	fs := flag.NewFlagSet("ct-sorter", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rawSort []string
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
	addOnce([]string{"p", "port"}, "port", atoi(&cfg.Port), "listen port")
	addOnce([]string{"dns"}, "dns", func(s string) error { cfg.DNSServers = s; return nil }, "DNS IPv4 list")
	addOnce([]string{"t", "threads"}, "threads", atoi(&cfg.Threads), "sort workers")
	addOnce([]string{"client-buffer-mb"}, "client-buffer-mb", atoi(&cfg.ClientBufferMB), "per-client buffer")
	addOnce([]string{"body-limit-kb"}, "body-limit-kb", atoi(&cfg.BodyLimitKB), "response body limit")
	addOnce([]string{"dns-timeout"}, "dns-timeout", duration(&cfg.DNSTimeout), "DNS timeout")
	addOnce([]string{"connect-timeout"}, "connect-timeout", duration(&cfg.ConnectTimeout), "connect timeout")
	addOnce([]string{"response-timeout"}, "response-timeout", duration(&cfg.ResponseTimeout), "response timeout")
	mv := &multiValue{values: &rawSort}
	fs.Var(mv, "s", "path:literal (repeatable)")
	fs.Var(mv, "sort", "path:literal (repeatable)")
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
	if cfg.Port < 1 || cfg.Port > 65535 {
		return cfg, false, errors.New("port must be 1..65535")
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
	seen := map[string]bool{}
	for _, raw := range rawSort {
		r, err := sorter.ParseRule(raw)
		if err != nil {
			return cfg, false, err
		}
		if seen[r.Path] {
			return cfg, false, fmt.Errorf("duplicate sort path %q", r.Path)
		}
		seen[r.Path] = true
		cfg.Sort = append(cfg.Sort, r)
	}
	return cfg, false, nil
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: ct-sorter [options]
  -nf, --nofilter                 disable built-in filter
  -f, --filter REGEX              additional case-insensitive exclusion regexp
  -p, --port PORT                 listen port (default 4949)
  -s, --sort PATH:LITERAL         repeatable HTTP body classifier
  -dns, --dns IP,IP,...           custom UDP DNS servers
  -expose, --expose               listen on 0.0.0.0
  -t, --threads N                 sorter workers (default 2000)
      --client-buffer-mb N         per-client buffer (default 10)
      --dns-timeout DURATION       DNS timeout (default 1s)
      --connect-timeout DURATION   connect timeout (default 2s)
      --response-timeout DURATION  response timeout (default 5s)
      --body-limit-kb N            response body limit (default 200)
  -d, --daemon                    run in background
  -h, --help                      show help
  -v, --version                   show version
`)
}
