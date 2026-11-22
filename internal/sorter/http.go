package sorter

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
)

// UserAgent is intentionally centralized so releases can update it easily.
const UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

type responseData struct {
	body   []byte
	header http.Header
	buf    *bytes.Buffer // owns body; returned to bodyPool by release
}

// release returns the pooled body buffer. body must not be used afterwards.
func (r *responseData) release() {
	if r.buf != nil {
		putBodyBuffer(r.buf)
		r.buf, r.body = nil, nil
	}
}

// maxPooledBody keeps one unusually large --body-limit-kb from pinning large
// buffers in the pool.
const maxPooledBody = 1 << 20

// bodyPool and gzipPool reuse per-response memory across requests. Only
// in-flight requests hold a buffer, so idle workers do not pin memory.
var (
	bodyPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}
	gzipPool sync.Pool // *gzip.Reader
)

func putBodyBuffer(b *bytes.Buffer) {
	if b.Cap() > maxPooledBody {
		return
	}
	b.Reset()
	bodyPool.Put(b)
}

func getGzipReader(r io.Reader) (*gzip.Reader, error) {
	if gz, ok := gzipPool.Get().(*gzip.Reader); ok {
		if err := gz.Reset(r); err != nil {
			return nil, err
		}
		return gz, nil
	}
	return gzip.NewReader(r)
}

// dialTarget carries the already-resolved, validated destination for a request.
// It is passed via the request context so one shared transport can serve every
// domain without re-resolving or rebuilding per-request transports.
type dialTarget struct {
	ip         netip.Addr
	serverName string
}

type dialTargetKey struct{}

// initHTTP builds the single transport and client reused by all workers.
// Keep-alives stay disabled, but the transport object itself is shared to avoid
// per-request allocation. Per-request IP and TLS ServerName are read from the
// request context.
func (s *Sorter) initHTTP() {
	s.transport = &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			target, _ := ctx.Value(dialTargetKey{}).(dialTarget)
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			dialCtx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
			defer cancel()
			return s.cfg.DialContext(dialCtx, "tcp4", net.JoinHostPort(target.ip.String(), port))
		},
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			target, _ := ctx.Value(dialTargetKey{}).(dialTarget)
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			dialCtx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
			raw, err := s.cfg.DialContext(dialCtx, "tcp4", net.JoinHostPort(target.ip.String(), port))
			cancel()
			if err != nil {
				return nil, err
			}
			// Sorting intentionally accepts any certificate; SNI is still the domain.
			tlsConn := tls.Client(raw, &tls.Config{ServerName: target.serverName, InsecureSkipVerify: true})
			hsCtx, hsCancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
			defer hsCancel()
			if err := tlsConn.HandshakeContext(hsCtx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	s.client = &http.Client{
		Transport:     s.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (s *Sorter) request(domain string, ip netip.Addr, https bool) (responseData, bool) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResponseTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, dialTargetKey{}, dialTarget{ip: ip, serverName: domain})

	scheme := "http"
	if https {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+domain+"/", nil)
	if err != nil {
		return responseData{}, false
	}
	req.Host = domain
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Close = true

	resp, err := s.client.Do(req)
	if err != nil {
		s.recordNetworkError(err)
		return responseData{}, false
	}
	defer resp.Body.Close()
	if !s.successCode(resp.StatusCode) {
		s.counters.Non200.Add(1)
		return responseData{}, false
	}

	reader := io.Reader(resp.Body)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, gzErr := getGzipReader(resp.Body)
		if gzErr != nil {
			s.recordNetworkError(gzErr)
			return responseData{}, false
		}
		// A reader that failed Reset is not returned to the pool.
		defer gzipPool.Put(gz)
		reader = gz
	}
	buf := bodyPool.Get().(*bytes.Buffer)
	if _, err = buf.ReadFrom(io.LimitReader(reader, int64(s.cfg.BodyLimit)+1)); err != nil {
		putBodyBuffer(buf)
		s.recordNetworkError(err)
		return responseData{}, false
	}
	body := buf.Bytes()
	if len(body) > s.cfg.BodyLimit {
		s.counters.BodyLimitHits.Add(1)
		body = body[:s.cfg.BodyLimit]
	}
	if https {
		if resp.StatusCode == http.StatusOK {
			s.counters.HTTPS200.Add(1)
		} else {
			s.counters.HTTPSAdditionalSuccess.Add(1)
		}
	} else if resp.StatusCode == http.StatusOK {
		s.counters.HTTP200.Add(1)
	} else {
		s.counters.HTTPAdditionalSuccess.Add(1)
	}
	// resp.Header is not mutated after the response is returned and keep-alives
	// are disabled, so it is safe to reference without cloning.
	return responseData{body: body, header: resp.Header, buf: buf}, true
}

func (s *Sorter) successCode(code int) bool {
	for _, accepted := range s.cfg.SuccessCodes {
		if code == accepted {
			return true
		}
	}
	return false
}

// headerBlob renders the response headers as "Name: value\n" lines once, so a
// single literal scan covers both header names, values, and their combined
// "Name: value" form. Returns nil when there are no headers.
func headerBlob(header http.Header) []byte {
	if len(header) == 0 {
		return nil
	}
	var b bytes.Buffer
	for name, values := range header {
		for _, value := range values {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(value)
			b.WriteByte('\n')
		}
	}
	return b.Bytes()
}

func (s *Sorter) recordNetworkError(err error) {
	if errors.Is(err, context.DeadlineExceeded) {
		s.counters.ReadTimeouts.Add(1)
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		s.counters.ReadTimeouts.Add(1)
		return
	}
	s.counters.ConnectErrors.Add(1)
}
