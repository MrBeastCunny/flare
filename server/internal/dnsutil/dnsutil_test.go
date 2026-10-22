package dnsutil

import (
	"net/netip"
	"strings"
	"testing"
)

func TestCanonicalZone(t *testing.T) {
	cases := map[string]string{
		"Example.COM":             "example.com.",
		"https://example.com/foo": "example.com.",
		"example.co.uk.":          "example.co.uk.",
		"bücher.de":               "xn--bcher-kva.de.",
	}
	for in, want := range cases {
		got, err := CanonicalZone(in)
		if err != nil || got != want {
			t.Errorf("CanonicalZone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "localhost", "-bad.com", "exa mple.com", "a..b.com"} {
		if _, err := CanonicalZone(bad); err == nil {
			t.Errorf("CanonicalZone(%q) expected error", bad)
		}
	}
}

func TestRecordName(t *testing.T) {
	zone := "example.com."
	cases := map[string]string{
		"":                 "example.com.",
		"@":                "example.com.",
		"www":              "www.example.com.",
		"WWW":              "www.example.com.",
		"www.example.com":  "www.example.com.",
		"www.example.com.": "www.example.com.",
		"*.dev":            "*.dev.example.com.",
		"_dmarc":           "_dmarc.example.com.",
		"example.com":      "example.com.",
	}
	for in, want := range cases {
		got, err := RecordName(in, zone)
		if err != nil || got != want {
			t.Errorf("RecordName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := RecordName("other.org.", zone); err == nil {
		t.Error("expected error for name outside zone")
	}
}

func TestNormalizeContent(t *testing.T) {
	zone := "example.com."
	cases := []struct{ typ, in, want string }{
		{"A", "192.0.2.1", "192.0.2.1"},
		{"AAAA", "2001:DB8::1", "2001:db8::1"},
		{"CNAME", "www", "www.example.com."},
		{"CNAME", "target.example.net.", "target.example.net."},
		{"MX", "10 mail", "10 mail.example.com."},
		{"TXT", "v=spf1 -all", `"v=spf1 -all"`},
		{"TXT", `"already quoted"`, `"already quoted"`},
		{"CAA", `0 issue "letsencrypt.org"`, `0 issue "letsencrypt.org"`},
		{"SRV", "10 60 5060 sip.example.com.", "10 60 5060 sip.example.com."},
		{"ALIAS", "lb.example.net", "lb.example.net."},
	}
	for _, c := range cases {
		got, err := NormalizeContent(zone, "x.example.com.", c.typ, 300, c.in)
		if err != nil || got != c.want {
			t.Errorf("NormalizeContent(%s %q) = %q, %v; want %q", c.typ, c.in, got, err, c.want)
		}
	}
	for _, c := range []struct{ typ, in string }{{"A", "1.2.3"}, {"A", "::1"}, {"AAAA", "1.2.3.4"}, {"MX", "mail"}, {"A", ""}} {
		if _, err := NormalizeContent(zone, "x.example.com.", c.typ, 300, c.in); err == nil {
			t.Errorf("NormalizeContent(%s %q) expected error", c.typ, c.in)
		}
	}
}

func TestQuoteTXTSplitsLongStrings(t *testing.T) {
	long := make([]byte, 600)
	for i := range long {
		long[i] = 'a'
	}
	got := QuoteTXT(string(long))
	if got[0] != '"' || got[len(got)-1] != '"' {
		t.Fatalf("not quoted: %s", got)
	}
	parts := 0
	for i := 0; i < len(got); i++ {
		if got[i] == '"' {
			parts++
		}
	}
	if parts != 6 { // three strings
		t.Errorf("expected 3 character-strings, got %d quotes in %s", parts, got)
	}
}

func TestParseZoneFile(t *testing.T) {
	text := "$TTL 300\n@ IN SOA ns1 hostmaster 1 2 3 4 5\nwww IN A 192.0.2.1\nmail IN MX 10 mx.example.net.\nother.org. IN A 192.0.2.2\n"
	recs, warnings, err := ParseZoneFile(text, "example.com.", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 records (SOA, A, MX), got %d: %+v", len(recs), recs)
	}
	if len(warnings) != 1 {
		t.Errorf("expected 1 warning for out-of-zone record, got %v", warnings)
	}
	if recs[1].Name != "www.example.com." || recs[1].TTL != 300 {
		t.Errorf("unexpected record %+v", recs[1])
	}
	if _, _, err := ParseZoneFile("www IN A notanip\n", "example.com.", 3600); err == nil {
		t.Error("expected parse error")
	}
}

func TestDelegationMatches(t *testing.T) {
	assigned := []string{"ns1.flare.test.", "ns2.flare.test."}
	if !DelegationMatches(assigned, []string{"NS1.flare.test", "ns2.flare.test."}) {
		t.Error("expected match")
	}
	if !DelegationMatches(assigned, []string{"ns1.flare.test."}) {
		t.Error("subset should match")
	}
	if DelegationMatches(assigned, []string{"ns1.flare.test.", "ns.other.net."}) {
		t.Error("foreign nameserver should not match")
	}
	if DelegationMatches(assigned, nil) {
		t.Error("empty delegation should not match")
	}
}

func TestHostmaster(t *testing.T) {
	if got := HostmasterToRName("dns.admin@example.com"); got != `dns\.admin.example.com.` {
		t.Errorf("got %q", got)
	}
	if got := RNameToEmail(`dns\.admin.example.com.`); got != "dns.admin@example.com" {
		t.Errorf("got %q", got)
	}
	if got := RNameToEmail("hostmaster.example.com."); got != "hostmaster@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestReverse(t *testing.T) {
	cases := map[string]string{
		"192.0.2.0/24":    "2.0.192.in-addr.arpa.",
		"10.0.0.0/8":      "10.in-addr.arpa.",
		"2001:db8::/32":   "8.b.d.0.1.0.0.2.ip6.arpa.",
		"2001:db8:1::/48": "1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
	}
	for in, want := range cases {
		got, err := CanonicalZone(in)
		if err != nil || got != want {
			t.Errorf("CanonicalZone(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := CanonicalZone("192.0.2.0/25"); err == nil {
		t.Error("non-octet IPv4 prefix should fail")
	}
	if p, _ := PTRName("192.0.2.10"); p != "10.2.0.192.in-addr.arpa." {
		t.Errorf("PTRName v4 = %q", p)
	}
	if p, _ := PTRName("2001:db8::1"); !strings.HasPrefix(p, "1.0.0.0.") || !strings.HasSuffix(p, ".8.b.d.0.1.0.0.2.ip6.arpa.") {
		t.Errorf("PTRName v6 = %q", p)
	}
	if !IsReverseZone("2.0.192.in-addr.arpa.") || IsReverseZone("example.com.") {
		t.Error("IsReverseZone")
	}
}

func TestIsUnroutable(t *testing.T) {
	for ip, want := range map[string]bool{
		"198.18.7.1": true, "198.19.255.255": true, "127.0.0.1": true, "0.0.0.0": true, "169.254.1.1": true,
		"100.64.0.1": true, "240.0.0.1": true, "224.0.0.1": true, "::1": true, "fe80::1": true, "fc00::5": true,
		"::ffff:198.18.0.1": true, "93.184.215.14": false, "10.0.0.5": false, "192.168.1.1": false, "2606:4700::1111": false,
	} {
		if got := IsUnroutable(netip.MustParseAddr(ip)); got != want {
			t.Errorf("IsUnroutable(%s) = %v, want %v", ip, got, want)
		}
	}
}
