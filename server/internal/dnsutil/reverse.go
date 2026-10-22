package dnsutil

import (
	"fmt"
	"net"
	"strings"
)

// IsReverseZone reports whether name is under in-addr.arpa or ip6.arpa.
func IsReverseZone(name string) bool {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	return strings.HasSuffix(n, ".in-addr.arpa") || strings.HasSuffix(n, ".ip6.arpa") || n == "in-addr.arpa" || n == "ip6.arpa"
}

// ReverseZoneFromCIDR converts 192.0.2.0/24 or 2001:db8::/32 into its reverse zone name.
// IPv4 prefixes must fall on an octet boundary and IPv6 prefixes on a nibble boundary.
func ReverseZoneFromCIDR(cidr string) (string, error) {
	ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return "", err
	}
	ones, _ := n.Mask.Size()
	if v4 := ip.To4(); v4 != nil {
		if ones%8 != 0 || ones == 0 || ones > 24 {
			return "", fmt.Errorf("IPv4 reverse zones need a /8, /16 or /24 prefix")
		}
		v4 = n.IP.To4()
		parts := []string{}
		for i := ones/8 - 1; i >= 0; i-- {
			parts = append(parts, fmt.Sprint(v4[i]))
		}
		return strings.Join(parts, ".") + ".in-addr.arpa.", nil
	}
	if ones%4 != 0 || ones == 0 || ones > 124 {
		return "", fmt.Errorf("IPv6 reverse zones need a prefix that is a multiple of 4")
	}
	hex := fmt.Sprintf("%x", []byte(n.IP.To16()))
	nibbles := hex[:ones/4]
	parts := make([]string, 0, len(nibbles))
	for i := len(nibbles) - 1; i >= 0; i-- {
		parts = append(parts, string(nibbles[i]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa.", nil
}

// PTRName returns the fully-qualified reverse name for an IP address.
func PTRName(ipStr string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", fmt.Errorf("%q is not an IP address", ipStr)
	}
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0]), nil
	}
	hex := fmt.Sprintf("%x", []byte(ip.To16()))
	parts := make([]string, 0, 32)
	for i := len(hex) - 1; i >= 0; i-- {
		parts = append(parts, string(hex[i]))
	}
	return strings.Join(parts, ".") + ".ip6.arpa.", nil
}
