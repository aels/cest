# ct-sorter

`ct-sorter` is a fast-as-hell and less-greedy Certificate Transparency monitor built for real-time attack-surface discovery as a drop-in replacement for https://github.com/d-Rickyy-b/certstream-server-go.

```bash
go install github.com/aels/ct-sorter/cmd/ct-sorter@latest # but the rusty imperfections, that defines us...
```

The installed binary is placed in `$(go env GOPATH)/bin`. Make sure that directory is in your `PATH`, then run `ct-sorter`.

> The stream is intentionally optimized rather than exhaustive: selected high-overlap CT logs are denied, non-active logs are skipped, the default noise filter removes known high-volume domains, and an in-memory FIFO set suppresses the last 100,000 unique names. Use `--nofilter` when broader visibility is more important than signal-to-noise ratio.

## Made for bug hunters, hackers & 0-day owners.

- **Reduce duplicate noise.** Wildcards are normalized and recent domains are suppressed by a 100,000-entry FIFO set.
- **Filter common trash by default.** The default filter removes most of large cloud, hosting, CDN and platform domains; it can be disabled or extended with your own regular expression.
- **Create your own live feeds.** Shops? VPNs? Any CMS, any app, really. `--sort wp:wp-content` exposes a `/wp` WebSocket containing domains whose HTTP or HTTPS response includes `wp-content`.
- **Use several classifiers at once.** A response may match multiple rules, and the domain will be published to every matching route.
- **Built-in DNS server, no bottlenecks.** The built-in UDP resolver benchmarks public resolvers and rotates among the fastest available servers.
- **Observe when shit goes wrong.** `/stats` reports CT, DNS, HTTP, queue and per-route counters, including evicted sort tasks and client messages.
- **Run cheaply.** Without `--sort`, no DNS resolver, HTTP worker pool, or sort queue is created.

## Requirements and source build

The current stable Go release on Ubuntu or Debian is recommended.

```bash
git clone https://github.com/aels/ct-sorter.git
cd ct-sorter
go build -o ct-sorter ./cmd/ct-sorter
./ct-sorter
```

## Command-line options

Both the short and long forms shown below are supported.

| Option | Default | Description |
|---|---:|---|
| `-nf`, `--nofilter` | disabled | Disable only the built-in noise filter. A regex supplied with `--filter` remains active. |
| `-f REGEX`, `--filter REGEX` | none | Additional case-insensitive exclusion regex applied to normalized full domain names. May be specified once. Invalid expressions stop startup. |
| `-p PORT`, `--port PORT` | `4949` | Port for the HTTP and WebSocket server. |
| `-s PATH:LITERAL`, `--sort PATH:LITERAL` | none | Add an HTTP body classifier and WebSocket route. Repeatable. Search is a case-sensitive literal byte match. |
| `-dns LIST`, `--dns LIST` | automatic | Comma-separated public IPv4 DNS servers, for example `1.1.1.1,8.8.8.8`. Port is always UDP/53. |
| `-expose`, `--expose` | disabled | Bind to `0.0.0.0` instead of `127.0.0.1`. There is no built-in authentication or TLS. |
| `-t N`, `--threads N` | `2000` | Maximum concurrent sort workers. The sort ring buffer holds `N × 10` pending domains. |
| `--client-buffer-mb N` | `10` | Independent unsent-message buffer for each WebSocket client, in MiB. |
| `--dns-timeout DURATION` | `1s` | Timeout for a UDP DNS query. Uses Go durations such as `500ms` or `2s`. |
| `--connect-timeout DURATION` | `2s` | TCP connection timeout for HTTP and HTTPS checks. |
| `--response-timeout DURATION` | `5s` | Total timeout for each HTTP or HTTPS attempt. |
| `--body-limit-kb N` | `200` | Maximum decompressed response bytes inspected per request. |
| `-d`, `--daemon` | disabled | Self-daemonize and run in the background. A service supervisor is still preferable for production. |
| `-h`, `--help` | — | Show command help. |
| `-v`, `--version` | — | Show the version. |

### Sort rule syntax

A sort rule uses `PATH:LITERAL`:

```text
--sort 'wp:wp-content'
          │       └─ case-sensitive string searched in the response body
          └───────── creates WebSocket route /wp
```

The path may contain lowercase `a-z`, digits, `-`, `_` and `.`. `all` and `stats` are reserved. Duplicate paths are rejected. Everything after the first `:` is part of the literal.

For every accepted domain, the sorter:

1. publishes it to `/all` immediately;
2. resolves an A record with the built-in UDP resolver;
3. requests `http://domain/` without following redirects;
4. if HTTP does not return exactly `200 OK`, tries `https://domain/` once;
5. scans only a successful response body and publishes the domain to every matching sort route.

## Examples

### Stream new domains with the default noise filter

```bash
ct-sorter
```

Connect with a WebSocket client such as `websocat`:

```bash
websocat ws://127.0.0.1:4949/all
```

### Disable the built-in filter

```bash
ct-sorter --nofilter
```

### Add a custom exclusion filter

Exclude names containing `dev`, `staging` or `internal` while keeping the built-in filter enabled:

```bash
ct-sorter --filter '(^|\.)(dev|staging|internal)(\.|$)'
```

Disable the built-in filter but retain the custom expression:

```bash
ct-sorter --nofilter --filter '\.example\.com$'
```

### Detect WordPress and Magento targets

```bash
ct-sorter \
  --sort 'wordpress:wp-content' \
  --sort 'magento:Magento_' \
  --sort 'shops:class="cart"'
```

Consume the resulting feeds:

```bash
websocat ws://127.0.0.1:4949/wordpress
websocat ws://127.0.0.1:4949/magento
websocat ws://127.0.0.1:4949/shops
```

A domain may appear in more than one route when multiple literals match.

### Use custom DNS resolvers and tighter timeouts

```bash
ct-sorter \
  --sort 'wordpress:wp-content' \
  --dns '1.1.1.1,8.8.8.8,9.9.9.9' \
  --dns-timeout 750ms \
  --connect-timeout 1500ms \
  --response-timeout 4s
```

### Reduce or increase HTTP concurrency

A smaller deployment:

```bash
ct-sorter --sort 'wordpress:wp-content' --threads 250
```

This creates 250 workers and a 2,500-domain sort ring buffer.

A larger deployment:

```bash
ct-sorter --sort 'wordpress:wp-content' --threads 4000
```

This creates 4,000 workers and a 40,000-domain sort ring buffer. Increase concurrency carefully: open sockets, bandwidth and remote-site latency usually become the limiting factors.

### Listen on an external interface

```bash
ct-sorter --expose --port 8080
```

This exposes the unauthenticated server on `0.0.0.0:8080`. Use a firewall or reverse proxy when the host is reachable from untrusted networks.

### Run in the background

```bash
ct-sorter --daemon --sort 'wordpress:wp-content'
```

### Inspect runtime statistics

```bash
curl http://127.0.0.1:4949/stats
```

The JSON snapshot is rebuilt every five seconds. Important fields include:

- `ct.active_logs`, `ct.entries`, `ct.source_errors`;
- `domains.extracted`, `domains.duplicates`, `domains.published_all`;
- `dns.errors`, `dns.timeouts`, `dns.private_address_drops`;
- `http.http_200`, `http.https_200`, `http.non_200`, `http.read_timeouts`;
- `queues.sort_queue_dropped`;
- `routes.<name>.clients` and `routes.<name>.client_dropped`.

## Endpoints and frame format

| Endpoint | Protocol | Purpose |
|---|---|---|
| `/all` | WebSocket | All accepted domains after filtering and global deduplication. |
| `/<sort-path>` | WebSocket | Domains whose successful HTTP/HTTPS body matched the route literal. |
| `/stats` | HTTP | Cached runtime statistics and health response. |

On `/all`, one WebSocket text frame may contain up to 100 domains separated by `\n`; treat every non-empty line as one domain. On every sort route, each WebSocket text frame contains exactly one domain. New clients receive no history.

## Processing details

- Google v3 `logs` and `tiled_logs` are refreshed daily.
- Only `usable` and `qualified` logs are followed.
- Every source starts at its current STH/checkpoint; no history or disk cursor is used.
- Both certificates and precertificates are processed.
- DNS SAN and legacy CN are extracted without full certificate enrichment.
- Wildcards become their base names, Unicode is converted with IDNA, and malformed names are dropped.
- The global 100,000-name FIFO does not refresh a duplicate's position.
- With sorting enabled, queue overflow evicts the oldest unprocessed domain and increments `sort_queue_dropped`.

## DNS and outbound safety

The sorter uses its own UDP/53 A resolver with EDNS(0), bounded DNS parsing, and at most three CNAME transitions. It does not use `/etc/resolv.conf`, DoH, DoT, DNS-over-TCP, DNSSEC, or a DNS cache.

Automatic resolver candidates:

```text
1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9
149.112.112.112 208.67.222.222 208.67.220.220 94.140.14.14 94.140.15.15
76.76.2.0 76.76.10.0 185.228.168.9 185.228.169.9 64.6.64.6
64.6.65.6 77.88.8.8 77.88.8.1 156.154.70.1 156.154.71.1
195.46.39.39 195.46.39.40 84.200.69.80 84.200.70.40 45.90.28.0
```

They are benchmarked from the running machine against `example.com`, `iana.org` and `cloudflare.com`; up to ten successful resolvers are selected and refreshed hourly.

HTTP connects directly to the selected public IPv4 while preserving the domain in the `Host` header and TLS SNI. Redirects and keep-alive are disabled. HTTPS fallback intentionally accepts invalid, expired, and hostname-mismatched certificates.

## Operational limitations

- The output is optimized for discovery efficiency, not guaranteed complete CT coverage.
- CT signatures, inclusion proofs, and consistency proofs are not verified.
- State is not persisted; domains issued while the process is stopped are not recovered.
- DNS has no TCP fallback. A truncated UDP response is retried once through another resolver and then skipped.
- Only IPv4 A records are used for HTTP sorting.
- The embedded server has no authentication or TLS.
- Recent-domain deduplication intentionally hides repeated certificate issuance until the domain leaves the 100,000-entry FIFO.

## Tests

```bash
go test ./...
go test -race ./internal/ctstream ./internal/dnsresolver \
  ./internal/ring ./internal/sorter ./internal/web ./internal/dedup
```

## License

Custom permissive, WTFPL-style license. See [`LICENSE`](LICENSE); this project does not claim that the text is the official WTFPL wording.
