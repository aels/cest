package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func benchCertificate(b *testing.B) []byte {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"example.com", "www.example.com", "api.example.com", "cdn.example.com", "*.staging.example.com"},
		NotBefore:    time.Unix(0, 0), NotAfter: time.Unix(3600, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	return der
}

func BenchmarkExtractCertificate(b *testing.B) {
	der := benchCertificate(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ExtractCertificate(der); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFilterMatch(b *testing.B) {
	filter, err := NewFilter(false, "")
	if err != nil {
		b.Fatal(err)
	}
	// Mix of filtered and unfiltered names to exercise the built-in regexp.
	names := []string{
		"login.corp-target.com", "api.shop.example", "assets.google.com",
		"random-startup.io", "mail.github.io", "vpn.internal-bank.net",
		"cdn.fastly.net", "staging.acme.dev", "portal.gov.uk", "x.duckdns.org",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter.Match(names[i%len(names)])
	}
}

func BenchmarkNormalize(b *testing.B) {
	names := []string{"*.Example.COM.", "xn--bcher-kva.example", "WWW.Target.Org", "a.b.c.d.example.net"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Normalize(names[i%len(names)])
	}
}
