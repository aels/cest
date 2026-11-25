<img width="1008" height="140" alt="image" src="https://github.com/user-attachments/assets/e2022d42-e156-4d9f-a8d7-92cfd274b156" />

# cest - fastest & lightest CertStream monitor & sorter

`cest` is a fast-as-hell and less-greedy Certificate Transparency monitor built for `put your task here`, as a drop-in replacement for https://github.com/d-Rickyy-b/certstream-server-go.

Why cest?
- Cuz it has 26% less traffic consumption, keeping 99.2% of new domains, compared to `certstream-server-go`.
- It cuts off 99% of useless domains, making domains stream ~31% lighter out of the box.
- It's built with love and supercharged with Ukrainian energy.


Usage:
```bash
go install github.com/aels/cest/cmd/cest@latest # but the rusty imperfections that define us...
```
Than
```bash
cest --daemon
```
Then connect with a WebSocket client such as `websocat`:
```bash
websocat ws://127.0.0.1:4949/all | python3 any-of-your-tools.py
```
The installed binary is placed in `$(go env GOPATH)/bin`. Make sure that directory is in your `PATH`, then run `cest`.

> The cest is intentionally optimized for only one task: "give me only domains feed, fast". Selected high-overlap CT logs are denied, non-active logs are skipped, the default noise filter removes known high-volume domains, and an in-memory FIFO set keeps you from dupes. Use `--nofilter` to find out how deep a rabbit hole is.

## Made for researchers

- **Reduce duplicate noise.** Wildcards are normalized and dupe domains are suppressed by a 100k FIFO set.
- **Filter common trash by default.** The default filter removes most large cloud, hosting, CDN, and platform domains:
```text
\.(google|googleapis|amazon|amazonaws|microsoft|azure|cloudflare|akamai|fastly|github|facebook|apple|netflix|shopify|squarespace|wix|godaddy|wordpress\.com|herokuapp|vercel|netlify|pages\.dev|firebaseapp|cloudfront|letsencrypt|sectigo|digicert|globalsign|comodo|verisign|gov|edu|mil)|workers\.dev|quickconnect\.(to|cn)|icdn\.ru|aws\.dev|\.on\.aws|netcraze\.io|mybluehost\.me|sslip\.io|nip\.io|amplifyapp\.com|platformsh\.site|zendesk\.com|synology\.me|remotewd\.com|meraki\.direct|duckdns\.org|plesk\.page|workdaysuv|website-k\.com|technology2022\.com|altervista\.org|haplorrhini\.com|tunwg\.com|towerbrands\.asia|dpdns\.org|certsbridge\.com|myvolumio\.org|ui\.direct|mybluelantern\.com|sovcloud-core\.fr|hstgr\.cloud|myftpupload\.com|xmit\.dev|mywhc\.ca|sub-site\.eu|endl\.site|hostclusters\.com|server-he\.de|rakkoserver\.net|optum\.com|a2z\.eu|wholesale-nondurable\.org|trucking-warehousing\.org|ciscosecureaccess|sourcemanager\.dev|cpanel\.site|traefik\.me|stratoserver\.net|ts\.net|ccwu\.cc|battery\.cam|servi\.tn|testsoftwares\.site|uhc\.com|flowww\.net|luckysrv\.de|ccaiplatform\.com|skalator\.de|judikamuhoki|freedomsoftsites\.com|ekalamfoundation\.com|gaymonrealtygroup\.com|adison\.co|jnj\.com|pustekno\.id|verify-recruit\.work|beatplugs\.com|texastopn\.top|whm\.
```
That's a lot of trash (like a 30% offload). It can be disabled or extended with your own regular expression, btw.
- **Create your own live feeds.** Shops? VPNs? Any CMS, any app, really. `--stream wp:wp-content` exposes a `/wp` WebSocket containing domains whose successful HTTP or HTTPS response headers or body include `wp-content`.
- **Use several classifiers at once.** A response may match multiple rules, and the domain will be published to every matching route.
- **Built-in DNS server, no bottlenecks.** The built-in UDP resolver benchmarks public resolvers and rotates among the fastest available servers.
- **Observe when shit goes wrong.** `/stats` reports CT, DNS, HTTP, queue, and per-route counters, including evicted sort tasks and client messages.
- **Run cheaply.** Need only a pure domain list? - `/all`. Without `--stream`, no DNS resolver & no HTTP worker pool are created.

## Requirements and source build

The current stable Go release on Ubuntu or Debian is recommended.
```bash
git clone https://github.com/aels/cest.git
cd cest
go build -o cest ./cmd/cest
./cest
```

## Command-line options

Both the short and long forms shown below are supported.

| Option | Default | Description |
|---|---:|---|
| `-nf`, `--nofilter` | disabled | Disable only the built-in noise filter. A regex supplied with `--filter` remains active. |
| `-f REGEX`, `--filter REGEX` | none | Additional case-insensitive exclusion regex applied to normalized full domain names. May be specified once. Invalid expressions stop startup. |
| `-ws-port PORT`, `--ws-port PORT` | `4949` | Port for the HTTP and WebSocket server. |
| `-s PATH:LITERAL`, `--stream PATH:LITERAL` | none | Add a case-sensitive response header/body classifier and WebSocket route. Repeatable; duplicate paths merge into one stream. |
| `-p LIST`, `--ports LIST` | `https:443,http:80` | Ordered list of HTTP attempts for each classified domain, e.g. `http:80,https:443,3000`. See [Probe ports](#probe-ports). |
| `-c LIST`, `--code LIST` | none | Comma-separated additional successful statuses, e.g. `303,404`. Status `200` is always successful. |
| `-dns LIST`, `--dns LIST` | automatic | Comma-separated public IPv4 DNS servers, for example `1.1.1.1,8.8.8.8`. Port is always UDP/53. |
| `-expose`, `--expose` | disabled | Bind to `0.0.0.0` instead of `127.0.0.1`. There is no built-in auth/TLS - share it with friends & enemies. |
| `-t N`, `--threads N` | `2000` | Maximum concurrent sort workers. The sort ring buffer holds `N × 10` pending domains. |
| `--client-buffer-mb N` | `10` | Independent unsent-message buffer for each WebSocket client, in MiB. |
| `--dns-timeout DURATION` | `1s` | Timeout for a UDP DNS query. Uses Go durations such as `500ms` or `2s`. |
| `--connect-timeout DURATION` | `2s` | TCP connection timeout for HTTP and HTTPS checks. |
| `--response-timeout DURATION` | `5s` | Total timeout for each HTTP or HTTPS attempt. |
| `--body-limit-kb N` | `200` | Maximum decompressed response bytes inspected per request. |
| `-d`, `--daemon` | disabled | Self-daemonize and run in the background. A service supervisor is still preferable for production. |
| `-h`, `--help` | — | Show command help. |
| `-v`, `--version` | — | Show the version. |

### Stream rule syntax

A stream rule uses `PATH:LITERAL`:

```text
--stream 'wp:wp-content'
          │       └─ case-sensitive string searched in response headers and body
          └───────── creates or extends WebSocket route /wp
```

The path may contain lowercase letters (`a-z`), digits, hyphens (`-`), underscores (`_`), and periods (`.`). The names `all` and `stats` are reserved. The first colon separates the path from the literal; subsequent colons are part of the literal. Rules with the same path are combined using logical OR. A domain is published to each matching path at most once per processed response.

For each domain admitted to the HTTP classification pipeline, the application performs the following operations:

1. Publishes the domain to `/all` before classification.
2. Resolves its IPv4 address using the integrated UDP DNS resolver.
3. Issues `GET` requests in the order of the `--ports` list, without following redirects. The default list is `https:443,http:80`: `GET https://domain/` first, then `GET http://domain/`.
4. Accepts status `200` and any additional status codes specified by `--code`. The first accepted response stops the sequence; later attempts are not made.
5. Searches the accepted response headers and body for the configured case-sensitive literals and publishes the domain to each matching stream path.

### Probe ports

`-p`/`--ports` sets the ordered list of HTTP attempts. Each comma-separated element has one of these forms:

| Element | Attempts |
|---|---|
| `https:PORT` | HTTPS on `PORT`. |
| `http:PORT` | Plain HTTP on `PORT`. |
| `PORT` | HTTPS on `PORT`, then plain HTTP on `PORT`. The scheme of a bare port is unknown, so both are tried. |

`PORT` must be 1..65535. Attempts run in list order and stop at the first accepted status. Repeated attempts are removed; the first occurrence keeps its position. For example, `http:80,https:443,3000` tries `http:80`, `https:443`, `https:3000`, and `http:3000`.

Every attempt uses the same resolved IPv4 address. The HTTP `Host` header contains the port only when it is not the scheme default (80 for HTTP, 443 for HTTPS); TLS SNI is always the bare domain. Each attempt has its own `--response-timeout`, so a long list increases the worst-case time per domain. The option has no effect without `--stream`.

## Configuration examples

### Configure an additional exclusion expression

The following expression excludes domains with a label equal to `dev`, `staging`, or `internal`. The built-in exclusion filter remains enabled.

```bash
cest --filter '(^|\.)(dev|staging|internal)(\.|$)'
```

To disable the built-in filter while retaining the custom expression:

```bash
cest --nofilter --filter '\.example\.com$'
```

### Configure response classification streams

The following configuration defines two alternative signatures for `/wordpress`, one signature for `/magento`, and one signature for `/shops`. Status codes `303` and `404` are accepted in addition to `200`.

```bash
cest \
  --stream 'wordpress:wp-content' \
  --stream 'wordpress:X-Powered-By: WordPress' \
  --stream 'magento:Magento_' \
  --stream 'shops:class="cart"' \
  --code '303,404'
```

Connect to the resulting WebSocket endpoints:

```bash
websocat ws://127.0.0.1:4949/wordpress
websocat ws://127.0.0.1:4949/magento
websocat ws://127.0.0.1:4949/shops
```

A domain may be published to multiple endpoints if rules with different paths match. Matching both `wordpress` signatures produces only one publication to `/wordpress` for that response. These signatures indicate literal matches, not verified identification of the application or its version.

### Configure probe ports

The following configuration also checks two common application ports. Plain HTTP on 80 goes first, then HTTPS on 443, then both schemes on 8080 and 8443.

```bash
cest \
  --stream 'wordpress:wp-content' \
  --ports 'http:80,https:443,8080,8443'
```

### Configure DNS resolvers and network timeouts

An explicit resolver list disables automatic resolver selection. Each address must be an IPv4 literal; the destination port is UDP/53.

```bash
cest \
  --stream 'wordpress:wp-content' \
  --dns '1.1.1.1,8.8.8.8,9.9.9.9' \
  --dns-timeout 750ms \
  --connect-timeout 1500ms \
  --response-timeout 4s
```

Resolver capacity depends on network latency, packet loss, provider rate limits, and the requested domain set. The number of configured addresses alone does not guarantee a particular lookup throughput.

### Bind to an external interface

```bash
cest --expose --ws-port 4200 --daemon --stream 'wordpress:wp-content'
```

This configuration binds the HTTP and WebSocket server to `0.0.0.0:4200` and runs the process in daemon mode. The server provides neither authentication nor TLS. Restrict network access through a firewall or a reverse proxy as required. Remote clients can consume classified streams without performing the corresponding HTTP requests themselves.

### Retrieve runtime statistics

```bash
curl http://127.0.0.1:4949/stats
```

The server regenerates the cached JSON snapshot every five seconds. The snapshot includes the following counters and gauges:

- `ct.active_logs`, `ct.entries`, and `ct.source_errors`;
- `domains.extracted`, `domains.duplicates`, and `domains.published_all`;
- `dns.errors`, `dns.timeouts`, `dns.private_address_drops`, and `dns.not_ready_drops`;
- `http.http_200`, `http.https_200`, `http.http_additional_code_success`, `http.https_additional_code_success`, `http.non_success_status`, and `http.read_timeouts`;
- `queues.sort_queue_dropped`;
- `routes.<name>.clients` and `routes.<name>.client_dropped`.

## Endpoints and message framing

| Endpoint | Protocol | Description |
|---|---|---|
| `/all` | WebSocket | Domain names accepted by validation, filtering, and global deduplication. |
| `/<stream-path>` | WebSocket | Domain names for which an accepted HTTP or HTTPS response matched at least one literal associated with the path. |
| `/stats` | HTTP | Cached runtime statistics and process health response. |

On `/all`, each WebSocket text frame contains between 1 and 100 domain names separated by `\n`. Clients must process each non-empty line as an individual domain. On named stream endpoints, each text frame contains exactly one domain name. New connections do not receive historical messages.

WebSocket clients may operate in receive-only mode. The server does not require application messages or WebSocket Pong responses and does not impose a read deadline. TCP keepalive is enabled with an idle interval of 60 seconds, a probe interval of 15 seconds, and a probe count of 4. The operating system handles these probes; no application-level response is required.

Each frame write has a one-minute timeout. A read or write failure closes only the affected connection and releases its queue. The endpoint and other clients remain active. Client queue overflow evicts the oldest unsent domain names without closing the connection. TCP keepalive does not verify whether the receiving application is processing messages.

HTTP keep-alive remains disabled for outbound website classification requests.

## Processing behavior

- The application refreshes the Google v3 `logs` and `tiled_logs` catalog every 24 hours.
- Only logs in the `usable` or `qualified` state are monitored, subject to the configured source denylist.
- Each source starts at its current STH or checkpoint. Historical entries are not retrieved, and cursors are not persisted.
- A source that is behind is read batch after batch without a pause. The poll interval applies only when the source has no known new entries.
- Static CT data tiles are read as full tiles. Entries in an incomplete tile are read as a partial tile only after they wait 20 seconds.
- Both certificates and precertificates are processed.
- The ASN.1 parser extracts DNS SAN entries and legacy CN values without constructing a complete certificate representation.
- Wildcard prefixes and trailing periods are removed, names are lowercased, Unicode names are converted using IDNA, and invalid names are discarded.
- The global FIFO deduplication set retains 100,000 unique names. A duplicate does not refresh its position.
- The HTTP classification queue has a capacity of `threads × 10`. On overflow, the oldest pending domain is evicted and `sort_queue_dropped` is incremented.

## DNS resolution and outbound connection policy

The integrated resolver issues IPv4 A queries over UDP/53 with EDNS(0). DNS parsing is bounded, and CNAME traversal is limited to three transitions. UDP sockets are reused across queries; up to `--threads` idle sockets are kept. A failed query is retried once on the next server, except for NXDOMAIN, which is final. The resolver does not use `/etc/resolv.conf`, DoH, DoT, DNS-over-TCP, DNSSEC validation, or a DNS cache.

The automatic selection process evaluates the following 60 public IPv4 resolver addresses:

```text
1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9
149.112.112.112 208.67.222.222 208.67.220.220 94.140.14.14 94.140.15.15
76.76.2.0 76.76.10.0 185.228.168.9 185.228.169.9 64.6.64.6
64.6.65.6 77.88.8.8 77.88.8.1 156.154.70.1 156.154.71.1
195.46.39.39 195.46.39.40 84.200.69.80 84.200.70.40 45.90.28.0
1.1.1.2 1.0.0.2 1.1.1.3 1.0.0.3
9.9.9.10 149.112.112.10 9.9.9.11 149.112.112.11
94.140.14.140 94.140.14.141 94.140.14.15 94.140.15.16
45.90.30.0 8.26.56.26 8.20.247.20 74.82.42.42
185.222.222.222 45.11.45.11 86.54.11.100 86.54.11.200
95.85.95.85 2.56.220.2 223.5.5.5 223.6.6.6
119.29.29.29 182.254.116.116 101.101.101.101 101.102.103.104
114.114.114.114 114.114.115.115 180.76.76.76
1.2.4.8 210.2.4.8 208.67.222.220 208.67.220.222
```

The benchmark runs from the application host and queries `example.com`, `iana.org`, and `cloudflare.com`. Candidates are ranked first by successful-query count and then by median round-trip time. All candidates are measured in parallel. Up to 20 successful candidates are selected and used in round-robin order. Selection is repeated every hour. Until the first selection finds a server, the sort pipeline discards domains and counts them in `dns.not_ready_drops`; `/all` is not affected. If fewer than 20 candidates respond successfully, all successful candidates are used. Multiple addresses may belong to the same operator. Availability varies by network; candidates without successful benchmark responses are excluded.

Some resolvers apply security, family, or regional filtering. Consequently, they may return different answers or block particular domains. Use `--dns` to specify a controlled resolver set and bypass automatic selection. Address references: [public resolver catalogue](https://dnsspeedtester.com/best/) and [regional public DNS list](https://frytea.com/archives/1372/).

Outbound HTTP connections use the selected public IPv4 address directly while preserving the original domain in the HTTP `Host` header and TLS SNI. Private, loopback, link-local, CGNAT, documentation, benchmark, multicast, and reserved IPv4 ranges are rejected before connection establishment.

## Automatic Linux tuning

At startup, the application attempts to apply the following settings:

```text
ulimit -n 524287
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=2
```

`RLIMIT_NOFILE` applies to the current process. The TCP sysctls affect the applicable Linux network namespace and may affect other processes in that namespace. Applying these settings generally requires sufficient privileges or capabilities. Each operation is independent; a failure is reported without preventing application startup.

## Operational limitations

- HTTPS classification intentionally accepts invalid, expired, and hostname-mismatched certificates.
- Outbound HTTP classification does not follow redirects or reuse connections through HTTP keep-alive. This restriction does not apply to WebSocket TCP keepalive.
- The domain stream does not provide complete CT coverage because of source exclusions, filtering, deduplication, and possible queue eviction.
- CT signatures, inclusion proofs, and consistency proofs are not verified.
- Runtime state is not persisted. Entries published while the application is stopped are not recovered.
- DNS resolution does not fall back to TCP. A truncated UDP response is retried through one other configured resolver, if available; the lookup fails if the retry is unsuccessful.
- HTTP classification uses IPv4 A records only; IPv6 AAAA records are not used.
- The embedded HTTP and WebSocket server provides neither authentication nor TLS.
- Repeated certificate issuance for a domain does not produce another publication while the domain remains in the 100,000-entry deduplication set.

## Tests

```bash
go test ./...
go test -race ./internal/ctstream ./internal/dnsresolver \
  ./internal/ring ./internal/sorter ./internal/web ./internal/dedup
```

## License

The project uses a custom permissive license with WTFPL-style wording. See [`LICENSE`](LICENSE). The license text is not the official WTFPL text.
