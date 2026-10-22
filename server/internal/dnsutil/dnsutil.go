// Package dnsutil validates and normalizes DNS data and performs live lookups.
package dnsutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// SupportedTypes lists record types that can be managed through the dashboard.
var SupportedTypes = []string{
	"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "CAA", "PTR", "ALIAS", "DNAME", "DS", "DNSKEY", "HTTPS", "SVCB",
	"TLSA", "SSHFP", "NAPTR", "LOC", "CERT", "SMIMEA", "URI", "SPF", "HINFO", "RP", "OPENPGPKEY", "SOA",
}

var supported = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range SupportedTypes {
		m[t] = true
	}
	return m
}()

func IsSupportedType(t string) bool { return supported[t] }

// CanonicalZone converts a user-entered domain into lowercase, punycode, fully-qualified form.
func CanonicalZone(input string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if strings.Contains(s, "/") && !strings.Contains(s, "://") {
		if z, err := ReverseZoneFromCIDR(s); err == nil {
			return z, nil
		} else if net.ParseIP(strings.Split(s, "/")[0]) != nil {
			return "", err
		}
	}
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", errors.New("enter a domain name")
	}
	ascii, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid domain name", input)
	}
	if !strings.Contains(ascii, ".") {
		return "", errors.New("enter a full domain such as example.com")
	}
	fq := dns.Fqdn(ascii)
	if _, ok := dns.IsDomainName(fq); !ok || len(fq) > 254 {
		return "", fmt.Errorf("%q is not a valid domain name", input)
	}
	for _, l := range dns.SplitDomainName(fq) {
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return "", fmt.Errorf("%q is not a valid domain name", input)
		}
	}
	return fq, nil
}

// Hostname validates a nameserver hostname and returns its FQDN form.
func Hostname(input string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" {
		return "", errors.New("hostname is required")
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(s, "."))
	if err != nil || !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("%q is not a valid hostname", input)
	}
	fq := dns.Fqdn(ascii)
	if _, ok := dns.IsDomainName(fq); !ok {
		return "", fmt.Errorf("%q is not a valid hostname", input)
	}
	return fq, nil
}

// RecordName turns a user-entered name ("@", "www", "www.example.com") into an FQDN inside zone.
func RecordName(input, zone string) (string, error) {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" || s == "@" {
		return zone, nil
	}
	if strings.HasSuffix(s, ".") {
		s = strings.TrimSuffix(s, ".")
	} else if s+"." != zone && !strings.HasSuffix(s+".", "."+zone) {
		s = s + "." + strings.TrimSuffix(zone, ".")
	}
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if l == "*" && i == 0 {
			continue
		}
		if l == "" {
			return "", fmt.Errorf("%q is not a valid record name", input)
		}
		if a, err := idna.Lookup.ToASCII(l); err == nil {
			labels[i] = a
		} else if !strings.HasPrefix(l, "_") {
			return "", fmt.Errorf("%q is not a valid record name", input)
		}
	}
	fq := dns.Fqdn(strings.Join(labels, "."))
	if _, ok := dns.IsDomainName(fq); !ok {
		return "", fmt.Errorf("%q is not a valid record name", input)
	}
	if fq != zone && !strings.HasSuffix(fq, "."+zone) {
		return "", fmt.Errorf("record name must be inside %s", strings.TrimSuffix(zone, "."))
	}
	return fq, nil
}

// QuoteTXT wraps free text into DNS character-strings when the user did not quote it.
func QuoteTXT(content string) string {
	c := strings.TrimSpace(content)
	if strings.HasPrefix(c, `"`) {
		return c
	}
	c = strings.ReplaceAll(c, `\`, `\\`)
	c = strings.ReplaceAll(c, `"`, `\"`)
	var parts []string
	for len(c) > 255 {
		cut := 255
		// do not split an escape sequence
		for cut > 0 && c[cut-1] == '\\' {
			cut--
		}
		parts = append(parts, `"`+c[:cut]+`"`)
		c = c[cut:]
	}
	parts = append(parts, `"`+c+`"`)
	return strings.Join(parts, " ")
}

// NormalizeContent validates content for a record type and returns the canonical presentation
// format expected by PowerDNS.
func NormalizeContent(zone, name, typ string, ttl int, content string) (string, error) {
	typ = strings.ToUpper(typ)
	content = strings.TrimSpace(content)
	if content == "" {
		return "", errors.New("content is required")
	}
	switch typ {
	case "TXT", "SPF":
		content = QuoteTXT(content)
	case "ALIAS":
		h, err := Hostname(content)
		if err != nil {
			return "", err
		}
		return h, nil
	case "A":
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("%q is not a valid IPv4 address", content)
		}
		return ip.To4().String(), nil
	case "AAAA":
		ip := net.ParseIP(content)
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("%q is not a valid IPv6 address", content)
		}
		return ip.String(), nil
	}
	if ttl <= 0 {
		ttl = 3600
	}
	line := fmt.Sprintf("%s %d IN %s %s", name, ttl, typ, content)
	zp := dns.NewZoneParser(strings.NewReader(line), zone, "")
	rr, ok := zp.Next()
	if err := zp.Err(); err != nil {
		return "", cleanParseErr(err)
	}
	if !ok || rr == nil {
		return "", fmt.Errorf("invalid %s record content", typ)
	}
	out := strings.TrimPrefix(rr.String(), rr.Header().String())
	return strings.TrimSpace(out), nil
}

func cleanParseErr(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "dns: "); i >= 0 {
		msg = msg[i+5:]
	}
	if i := strings.Index(msg, ": \""); i >= 0 {
		msg = msg[:i]
	}
	if msg == "" {
		msg = "invalid record content"
	}
	return errors.New(strings.ToUpper(msg[:1]) + msg[1:])
}

// ParsedRR is a record read from a zone file.
type ParsedRR struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Content string `json:"content"`
}

// ParseZoneFile reads a BIND-style zone file into records.
func ParseZoneFile(text, zone string, defaultTTL int) ([]ParsedRR, []string, error) {
	zp := dns.NewZoneParser(strings.NewReader(text), zone, "")
	zp.SetDefaultTTL(uint32(defaultTTL))
	zp.SetIncludeAllowed(false)
	var out []ParsedRR
	var warnings []string
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		name := strings.ToLower(h.Name)
		if name != zone && !strings.HasSuffix(name, "."+zone) {
			warnings = append(warnings, fmt.Sprintf("Skipped %s: outside of %s", strings.TrimSuffix(name, "."), strings.TrimSuffix(zone, ".")))
			continue
		}
		typ := dns.TypeToString[h.Rrtype]
		if typ == "" {
			warnings = append(warnings, fmt.Sprintf("Skipped unsupported record type on %s", name))
			continue
		}
		content := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
		out = append(out, ParsedRR{Name: name, Type: typ, TTL: int(h.Ttl), Content: content})
	}
	if err := zp.Err(); err != nil {
		return nil, nil, cleanParseErr(err)
	}
	return out, warnings, nil
}

// ---- Live lookups ----

type Resolver struct {
	Addr    string
	Timeout time.Duration
}

func (r *Resolver) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	m.SetEdns0(1232, false)
	c := &dns.Client{Timeout: r.timeout()}
	resp, _, err := c.ExchangeContext(ctx, m, r.Addr)
	if err != nil {
		return nil, err
	}
	if resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, r.Addr)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

func (r *Resolver) timeout() time.Duration {
	if r.Timeout == 0 {
		return 4 * time.Second
	}
	return r.Timeout
}

// LookupNS returns the delegated nameservers for zone as seen by the recursive resolver.
func (r *Resolver) LookupNS(ctx context.Context, zone string) ([]string, error) {
	resp, err := r.exchange(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	if resp.Rcode == dns.RcodeNameError {
		return []string{}, nil
	}
	out := []string{}
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok && strings.EqualFold(ns.Hdr.Name, zone) {
			out = append(out, strings.ToLower(ns.Ns))
		}
	}
	sort.Strings(out)
	return out, nil
}

// LookupTXT returns TXT strings (joined per record) for name.
func (r *Resolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	resp, err := r.exchange(ctx, name, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range resp.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out, nil
}

// DelegationMatches reports whether the observed delegation points at our nameservers.
func DelegationMatches(assigned, observed []string) bool {
	if len(observed) == 0 || len(assigned) == 0 {
		return false
	}
	want := map[string]bool{}
	for _, a := range assigned {
		want[strings.ToLower(dns.Fqdn(a))] = true
	}
	for _, o := range observed {
		if !want[strings.ToLower(dns.Fqdn(o))] {
			return false
		}
	}
	return true
}

var scanLabels = []string{"", "www", "mail", "webmail", "smtp", "imap", "pop", "ftp", "api", "app", "admin", "blog", "shop",
	"cdn", "static", "assets", "dev", "staging", "test", "m", "vpn", "portal", "status", "docs", "support", "help", "login",
	"auth", "sso", "git", "autodiscover", "autoconfig", "remote", "cloud", "files", "calendar", "news", "media", "img", "web"}

// Scan discovers commonly used records for a domain that is not yet hosted here, so they can be
// imported when the zone is created.
func (r *Resolver) Scan(ctx context.Context, zone string) []ParsedRR {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	type q struct {
		name  string
		qtype uint16
	}
	var queries []q
	for _, l := range scanLabels {
		name := zone
		if l != "" {
			name = l + "." + zone
		}
		queries = append(queries, q{name, dns.TypeA}, q{name, dns.TypeAAAA})
	}
	queries = append(queries, q{zone, dns.TypeMX}, q{zone, dns.TypeTXT}, q{zone, dns.TypeCAA},
		q{"_dmarc." + zone, dns.TypeTXT}, q{"_domainkey." + zone, dns.TypeTXT},
		q{"_sip._tls." + zone, dns.TypeSRV}, q{"_sipfederationtls._tcp." + zone, dns.TypeSRV},
		q{"_autodiscover._tcp." + zone, dns.TypeSRV})

	// Detect wildcard records: answers identical to a random label's are covered by "*".
	wildcard := map[string]bool{}
	var out []ParsedRR
	probe := "flare-probe-" + strconv.FormatInt(time.Now().UnixNano()%1e9, 36) + "." + zone
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		resp, err := r.exchange(ctx, probe, qt)
		if err != nil || resp.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range resp.Answer {
			h := rr.Header()
			typ := dns.TypeToString[h.Rrtype]
			if !strings.EqualFold(h.Name, probe) || (typ != "A" && typ != "AAAA" && typ != "CNAME") {
				continue
			}
			content := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
			key := typ + "|" + content
			if !wildcard[key] {
				wildcard[key] = true
				out = append(out, ParsedRR{Name: "*." + zone, Type: typ, TTL: max(int(h.Ttl), 300), Content: content})
			}
		}
	}

	var mu sync.Mutex
	seen := map[string]bool{}
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, item := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(item q) {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := r.exchange(ctx, item.name, item.qtype)
			if err != nil || resp.Rcode != dns.RcodeSuccess {
				return
			}
			for _, rr := range resp.Answer {
				h := rr.Header()
				name := strings.ToLower(h.Name)
				if name != zone && !strings.HasSuffix(name, "."+zone) {
					continue
				}
				typ := dns.TypeToString[h.Rrtype]
				if typ == "" || typ == "RRSIG" || typ == "NSEC" || typ == "NSEC3" {
					continue
				}
				// Only keep the first link of CNAME chains that belong to the zone.
				if typ != "CNAME" && typ != dns.TypeToString[item.qtype] {
					continue
				}
				content := strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String()))
				if name != zone && wildcard[typ+"|"+content] {
					continue
				}
				key := name + "|" + typ + "|" + content
				mu.Lock()
				if !seen[key] {
					seen[key] = true
					ttl := int(h.Ttl)
					if ttl < 300 {
						ttl = 300
					}
					out = append(out, ParsedRR{Name: name, Type: typ, TTL: ttl, Content: content})
				}
				mu.Unlock()
			}
		}(item)
	}
	wg.Wait()

	// Drop A/AAAA answers that were produced by following a CNAME at the same name.
	cnames := map[string]bool{}
	for _, rr := range out {
		if rr.Type == "CNAME" {
			cnames[rr.Name] = true
		}
	}
	filtered := out[:0]
	for _, rr := range out {
		if cnames[rr.Name] && rr.Type != "CNAME" {
			continue
		}
		filtered = append(filtered, rr)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Name != filtered[j].Name {
			return filtered[i].Name < filtered[j].Name
		}
		return filtered[i].Type < filtered[j].Type
	})
	return filtered
}

// SOAContent builds SOA content.
func SOAContent(primary, hostmaster string, serial int64, refresh, retry, expire, minimum int) string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", dns.Fqdn(primary), HostmasterToRName(hostmaster), serial, refresh, retry, expire, minimum)
}

// HostmasterToRName converts hostmaster@example.com to hostmaster.example.com.
func HostmasterToRName(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return "hostmaster.invalid."
	}
	if i := strings.Index(email, "@"); i >= 0 {
		local := strings.ReplaceAll(email[:i], ".", `\.`)
		return dns.Fqdn(local + "." + email[i+1:])
	}
	return dns.Fqdn(email)
}

// RNameToEmail converts the SOA rname back to an email address for display.
func RNameToEmail(rname string) string {
	r := strings.TrimSuffix(rname, ".")
	for i := 0; i < len(r); i++ {
		if r[i] == '\\' {
			i++
			continue
		}
		if r[i] == '.' {
			return strings.ReplaceAll(r[:i], `\.`, ".") + "@" + r[i+1:]
		}
	}
	return r
}
