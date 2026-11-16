package dnsresolver

import "net/netip"

var forbiddenIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// IsPublicIPv4 reports whether ip is safe as an outbound HTTP destination.
// It rejects private, loopback, link-local, CGNAT, documentation, benchmark,
// multicast, reserved, unspecified and limited-broadcast addresses.
func IsPublicIPv4(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.Is4() {
		return false
	}
	for _, p := range forbiddenIPv4 {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
