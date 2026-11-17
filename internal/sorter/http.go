package sorter

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// UserAgent is intentionally centralized so releases can update it easily.
const UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"

type responseData struct {
	body   []byte
	header http.Header
}

func (s *Sorter) request(domain string, ip netip.Addr, https bool) (responseData, bool) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.ResponseTimeout)
	defer cancel()

	scheme, port := "http", "80"
	if https {
		scheme, port = "https", "443"
	}
	address := net.JoinHostPort(ip.String(), port)
	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{ServerName: domain, InsecureSkipVerify: true}, // Sorting intentionally accepts any certificate.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialCtx, dialCancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
			defer dialCancel()
			return s.cfg.DialContext(dialCtx, "tcp4", address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+domain+"/", nil)
	if err != nil {
		return responseData{}, false
	}
	req.Host = domain
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Close = true

	resp, err := client.Do(req)
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
		gz, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			s.recordNetworkError(gzErr)
			return responseData{}, false
		}
		defer gz.Close()
		reader = gz
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(s.cfg.BodyLimit)+1))
	if err != nil {
		s.recordNetworkError(err)
		return responseData{}, false
	}
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
	return responseData{body: body, header: resp.Header.Clone()}, true
}

func (s *Sorter) successCode(code int) bool {
	for _, accepted := range s.cfg.SuccessCodes {
		if code == accepted {
			return true
		}
	}
	return false
}

func headerContains(header http.Header, literal string) bool {
	for name, values := range header {
		if strings.Contains(name, literal) {
			return true
		}
		for _, value := range values {
			if strings.Contains(value, literal) || strings.Contains(name+": "+value, literal) {
				return true
			}
		}
	}
	return false
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
