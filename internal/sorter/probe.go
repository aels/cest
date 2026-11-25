package sorter

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Probe is one HTTP attempt: a scheme and a TCP port.
type Probe struct {
	HTTPS bool
	Port  uint16
}

// DefaultProbes is used when no probe list is configured: HTTPS on 443 first,
// then plain HTTP on 80.
var DefaultProbes = []Probe{{HTTPS: true, Port: 443}, {HTTPS: false, Port: 80}}

func (p Probe) scheme() string {
	if p.HTTPS {
		return "https"
	}
	return "http"
}

func (p Probe) String() string { return p.scheme() + ":" + strconv.Itoa(int(p.Port)) }

// urlHost returns the URL authority for domain. The default port of the scheme
// is omitted, so the Host header stays the bare domain for 80 and 443.
func (p Probe) urlHost(domain string) string {
	if (p.HTTPS && p.Port == 443) || (!p.HTTPS && p.Port == 80) {
		return domain
	}
	return net.JoinHostPort(domain, strconv.Itoa(int(p.Port)))
}

// ParseProbes parses a comma-separated probe list such as
// "http:80,https:443,3000". An element is "http:PORT", "https:PORT", or a bare
// "PORT". A bare port has no known scheme, so it expands to HTTPS and then
// HTTP on that port. The list order is the attempt order. Repeated attempts
// are removed; the first occurrence keeps its position.
func ParseProbes(value string) ([]Probe, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("sorter: probe list must not be empty")
	}
	var out []Probe
	seen := make(map[Probe]struct{})
	add := func(p Probe) {
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		scheme, portText, hasScheme := strings.Cut(raw, ":")
		if !hasScheme {
			portText = scheme
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, fmt.Errorf("sorter: invalid probe %q: expected http:PORT, https:PORT, or PORT with PORT 1..65535", raw)
		}
		switch {
		case !hasScheme:
			add(Probe{HTTPS: true, Port: uint16(port)})
			add(Probe{HTTPS: false, Port: uint16(port)})
		case strings.EqualFold(scheme, "https"):
			add(Probe{HTTPS: true, Port: uint16(port)})
		case strings.EqualFold(scheme, "http"):
			add(Probe{HTTPS: false, Port: uint16(port)})
		default:
			return nil, fmt.Errorf("sorter: invalid probe %q: scheme must be http or https", raw)
		}
	}
	return out, nil
}
