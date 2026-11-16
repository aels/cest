package domain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func testCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Example.COM."},
		DNSNames:     []string{"*.Example.com", "xn--bcher-kva.example", "example.com", "bad_name.example"},
		NotBefore:    time.Unix(0, 0), NotAfter: time.Unix(3600, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestExtractCertificateAndTBS(t *testing.T) {
	der := testCertificate(t)
	want := []string{"example.com", "xn--bcher-kva.example"}
	got, err := ExtractCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	got, err = ExtractTBSCertificate(cert.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TBS got %q, want %q", got, want)
	}
}

func TestMalformedDER(t *testing.T) {
	der := testCertificate(t)
	for _, bad := range [][]byte{nil, der[:len(der)-1], append(append([]byte{}, der...), 0)} {
		if _, err := ExtractCertificate(bad); !errors.Is(err, ErrMalformedDER) {
			t.Fatalf("error = %v", err)
		}
	}
	// Non-minimal long-form length must be rejected before any field parsing.
	if _, err := ExtractCertificate([]byte{0x30, 0x81, 0x01, 0x00}); !errors.Is(err, ErrMalformedDER) {
		t.Fatalf("error = %v", err)
	}
}

func TestNormalize(t *testing.T) {
	tests := map[string]string{
		" \t*.BÜCHER.Example.\r\n": "xn--bcher-kva.example",
		"WWW.Example.COM.":         "www.example.com",
	}
	for in, want := range tests {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	invalid := []string{"localhost", "a..com", "-a.example", "a-.example", "a.example.123", "127.0.0.1", "*.foo.*.com", "foo_bar.com", "a.。com"}
	for _, in := range invalid {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
		}
	}
	longLabel := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example"
	if _, err := Normalize(longLabel); err == nil {
		t.Error("accepted 64-byte label")
	}
}

func TestFilter(t *testing.T) {
	f, err := NewFilter(false, `SECRET|\.blocked$`)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"x.googleapis.com", "workers.dev.example", "mysecret.example", "ok.blocked"} {
		if !f.Excluded(name) {
			t.Errorf("did not exclude %q", name)
		}
	}
	if f.Excluded("ordinary.example") {
		t.Error("excluded ordinary.example")
	}
	if got := f.Apply([]string{"ordinary.example", "x.google.com"}); !reflect.DeepEqual(got, []string{"ordinary.example"}) {
		t.Fatalf("Apply = %q", got)
	}

	nf, err := NewFilter(true, `SeCrEt`)
	if err != nil {
		t.Fatal(err)
	}
	if nf.Excluded("x.google.com") || !nf.Excluded("mysecret.example") {
		t.Error("nofilter/custom semantics are wrong")
	}
	if _, err = NewFilter(true, `(`); err == nil {
		t.Error("invalid regexp accepted")
	}
}
