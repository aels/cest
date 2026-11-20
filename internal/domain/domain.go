// Package domain extracts, normalizes, validates, and filters DNS names from
// narrowly parsed X.509 DER. It intentionally does not perform full certificate
// validation or expose unrelated certificate fields.
package domain

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var (
	// ErrMalformedDER means that the input is not a structurally valid DER
	// Certificate/TBSCertificate for the fields needed by this package.
	ErrMalformedDER = errors.New("domain: malformed DER")
	// ErrInvalidName means that a name cannot be normalized to a valid DNS name.
	ErrInvalidName = errors.New("domain: invalid DNS name")
)

// ExtractCertificate returns normalized DNS SANs in certificate order, followed
// by the legacy subject CN when it is valid and not already present. Invalid
// individual names are omitted; malformed DER fails the whole extraction.
func ExtractCertificate(der []byte) ([]string, error) {
	r := newDER(der)
	cert, err := r.read(0x30)
	if err != nil || !r.empty() {
		return nil, ErrMalformedDER
	}
	cr := newDER(cert)
	tbs, err := cr.readRaw(0x30)
	if err != nil {
		return nil, ErrMalformedDER
	}
	if _, err = cr.read(0x30); err != nil { // signatureAlgorithm
		return nil, ErrMalformedDER
	}
	if _, err = cr.read(0x03); err != nil || !cr.empty() { // signatureValue
		return nil, ErrMalformedDER
	}
	return ExtractTBSCertificate(tbs)
}

// ExtractTBSCertificate is like ExtractCertificate but accepts a DER-encoded
// TBSCertificate directly, including a CT defanged precertificate TBS.
func ExtractTBSCertificate(der []byte) ([]string, error) {
	r := newDER(der)
	tbs, err := r.read(0x30)
	if err != nil || !r.empty() {
		return nil, ErrMalformedDER
	}
	tr := newDER(tbs)
	if tr.peek(0xa0) {
		if _, err = tr.read(0xa0); err != nil {
			return nil, ErrMalformedDER
		}
	}
	for _, tag := range []byte{0x02, 0x30, 0x30, 0x30} { // serial, signature, issuer, validity
		if _, err = tr.read(tag); err != nil {
			return nil, ErrMalformedDER
		}
	}
	subject, err := tr.read(0x30)
	if err != nil {
		return nil, ErrMalformedDER
	}
	cn, err := parseSubject(subject)
	if err != nil {
		return nil, ErrMalformedDER
	}
	if _, err = tr.read(0x30); err != nil {
		return nil, ErrMalformedDER
	} // SPKI

	var sans []string
	seenExt := false
	for !tr.empty() {
		switch {
		case tr.peek(0x81), tr.peek(0x82):
			if _, err = tr.read(tr.data[tr.off]); err != nil {
				return nil, ErrMalformedDER
			}
		case tr.peek(0xa3):
			if seenExt {
				return nil, ErrMalformedDER
			}
			seenExt = true
			ext, e := tr.read(0xa3)
			if e != nil {
				return nil, ErrMalformedDER
			}
			sans, e = parseExtensions(ext)
			if e != nil {
				return nil, ErrMalformedDER
			}
		default:
			return nil, ErrMalformedDER
		}
	}

	out := make([]string, 0, len(sans)+1)
	seen := make(map[string]struct{}, len(sans)+1)
	add := func(raw string) {
		n, e := Normalize(raw)
		if e != nil {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	for _, san := range sans {
		add(san)
	}
	if cn != "" {
		add(cn)
	}
	return out, nil
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(true), idna.Transitional(false), idna.VerifyDNSLength(false))

// Normalize applies ASCII-space trimming, lowercase/trailing-dot/wildcard
// normalization, IDNA A-label conversion, and strict DNS syntax validation.
func Normalize(name string) (string, error) {
	name = strings.Trim(name, " \t\r\n\v\f")
	name = strings.ToLower(name)
	name = strings.TrimSuffix(name, ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" || strings.ContainsRune(name, '*') || !utf8.ValidString(name) {
		return "", ErrInvalidName
	}
	ascii, err := idnaProfile.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidName, err)
	}
	ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
	if len(ascii) == 0 || len(ascii) > 253 || net.ParseIP(ascii) != nil {
		return "", ErrInvalidName
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrInvalidName
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidName
		}
		for i := range label {
			c := label[i]
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
				return "", ErrInvalidName
			}
		}
	}
	tld := labels[len(labels)-1]
	allDigits := true
	for i := range tld {
		if tld[i] < '0' || tld[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", ErrInvalidName
	}
	return ascii, nil
}

// builtInPattern is the authoritative specification of the built-in deny rule,
// kept for documentation and cross-checked against builtInNeedles in tests. It
// is not compiled at runtime; matchBuiltIn performs the equivalent, much cheaper
// case-insensitive substring search.
const builtInPattern = `\.(google|googleapis|amazon|amazonaws|microsoft|azure|cloudflare|akamai|fastly|github|facebook|apple|netflix|shopify|squarespace|wix|godaddy|wordpress\.com|herokuapp|vercel|netlify|pages\.dev|firebaseapp|cloudfront|letsencrypt|sectigo|digicert|globalsign|comodo|verisign)|\.(edu|gov|mil)(\.|$)|workers\.dev|quickconnect\.(to|cn)|icdn\.ru|aws\.dev|\.on\.aws|netcraze\.io|mybluehost\.me|sslip\.io|nip\.io|amplifyapp\.com|platformsh\.site|zendesk\.com|synology\.me|remotewd\.com|meraki\.direct|duckdns\.org|plesk\.page|workdaysuv|website-k\.com|technology2022\.com|altervista\.org|haplorrhini\.com|tunwg\.com|towerbrands\.asia|dpdns\.org|certsbridge\.com|myvolumio\.org|ui\.direct|mybluelantern\.com|sovcloud-core\.fr|hstgr\.cloud|myftpupload\.com|xmit\.dev|mywhc\.ca|sub-site\.eu|endl\.site|hostclusters\.com|server-he\.de|rakkoserver\.net|optum\.com|a2z\.eu|wholesale-nondurable\.org|trucking-warehousing\.org|ciscosecureaccess|sourcemanager\.dev|cpanel\.site|traefik\.me|stratoserver\.net|ts\.net|ccwu\.cc|battery\.cam|servi\.tn|testsoftwares\.site|uhc\.com|flowww\.net|luckysrv\.de|ccaiplatform\.com|skalator\.de|judikamuhoki|freedomsoftsites\.com|ekalamfoundation\.com|gaymonrealtygroup\.com|adison\.co|jnj\.com|pustekno\.id|verify-recruit\.work|beatplugs\.com|texastopn\.top|whm\.`

// builtInNeedles is the set of case-insensitive substrings equivalent to
// builtInPattern. The regexp is an unanchored alternation, so each alternative
// reduces to a substring test. Group members prefixed with "." come from the
// leading `\.` in the pattern's first alternation. Equivalence with
// builtInPattern is verified by a randomized cross-check test.
var builtInNeedles = []string{
	".google", ".googleapis", ".amazon", ".amazonaws", ".microsoft", ".azure",
	".cloudflare", ".akamai", ".fastly", ".github", ".facebook", ".apple",
	".netflix", ".shopify", ".squarespace", ".wix", ".godaddy", ".wordpress.com",
	".herokuapp", ".vercel", ".netlify", ".pages.dev", ".firebaseapp",
	".cloudfront", ".letsencrypt", ".sectigo", ".digicert", ".globalsign",
	".comodo", ".verisign",
	"workers.dev", "quickconnect.to", "quickconnect.cn", "icdn.ru", "aws.dev",
	".on.aws", "netcraze.io", "mybluehost.me", "sslip.io", "nip.io",
	"amplifyapp.com", "platformsh.site", "zendesk.com", "synology.me",
	"remotewd.com", "meraki.direct", "duckdns.org", "plesk.page", "workdaysuv",
	"website-k.com", "technology2022.com", "altervista.org", "haplorrhini.com",
	"tunwg.com", "towerbrands.asia", "dpdns.org", "certsbridge.com",
	"myvolumio.org", "ui.direct", "mybluelantern.com", "sovcloud-core.fr",
	"hstgr.cloud", "myftpupload.com", "xmit.dev", "mywhc.ca", "sub-site.eu",
	"endl.site", "hostclusters.com", "server-he.de", "rakkoserver.net",
	"optum.com", "a2z.eu", "wholesale-nondurable.org", "trucking-warehousing.org",
	"ciscosecureaccess", "sourcemanager.dev", "cpanel.site", "traefik.me",
	"stratoserver.net", "ts.net", "ccwu.cc", "battery.cam", "servi.tn",
	"testsoftwares.site", "uhc.com", "flowww.net", "luckysrv.de",
	"ccaiplatform.com", "skalator.de", "judikamuhoki", "freedomsoftsites.com",
	"ekalamfoundation.com", "gaymonrealtygroup.com", "adison.co", "jnj.com",
	"pustekno.id", "verify-recruit.work", "beatplugs.com", "texastopn.top", "whm.",
}

// builtInLabelNeedles are denied only when they appear as a whole DNS label that
// is not the first label: the domain ends with ".<needle>" or contains
// ".<needle>.". This avoids matching unrelated names such as "education",
// "government", or "milano".
var builtInLabelNeedles = []string{"edu", "gov", "mil"}

// Filter applies the built-in deny rule and an optional custom regexp.
type Filter struct {
	builtIn []string
	labels  []string
	custom  *regexp.Regexp
}

// NewFilter constructs a filter. noBuiltIn implements --nofilter semantics;
// custom remains active and is always compiled case-insensitively.
func NewFilter(noBuiltIn bool, custom string) (*Filter, error) {
	f := &Filter{}
	if !noBuiltIn {
		f.builtIn = builtInNeedles
		f.labels = builtInLabelNeedles
	}
	if custom != "" {
		r, err := regexp.Compile(`(?i:` + custom + `)`)
		if err != nil {
			return nil, fmt.Errorf("domain: invalid filter regexp: %w", err)
		}
		f.custom = r
	}
	return f, nil
}

// matchBuiltIn reports whether name matches any built-in deny rule,
// case-insensitively. Normalized input is already lowercase, so ToLower returns
// it without allocating. Plain needles use a substring test; label needles must
// appear as a whole, non-leading DNS label.
func matchBuiltIn(needles, labels []string, name string) bool {
	s := strings.ToLower(name)
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	for _, l := range labels {
		if matchLabel(s, l) {
			return true
		}
	}
	return false
}

// matchLabel reports whether s contains ".<label>" immediately followed by a dot
// or the end of string, i.e. label is a whole DNS label preceded by another.
func matchLabel(s, label string) bool {
	needle := "." + label
	for from := 0; ; {
		i := strings.Index(s[from:], needle)
		if i < 0 {
			return false
		}
		end := from + i + len(needle)
		if end == len(s) || s[end] == '.' {
			return true
		}
		from += i + 1
	}
}

// Match reports which filters exclude a normalized full domain.
func (f *Filter) Match(name string) (builtIn, custom bool) {
	if f == nil {
		return false, false
	}
	return f.builtIn != nil && matchBuiltIn(f.builtIn, f.labels, name), f.custom != nil && f.custom.MatchString(name)
}

// Excluded reports whether a normalized full domain matches either active rule.
func (f *Filter) Excluded(name string) bool {
	builtIn, custom := f.Match(name)
	return builtIn || custom
}

// Apply returns a newly allocated slice containing names not excluded by f.
func (f *Filter) Apply(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if !f.Excluded(name) {
			out = append(out, name)
		}
	}
	return out
}
