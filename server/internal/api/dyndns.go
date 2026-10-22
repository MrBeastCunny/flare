package api

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
)

// handleDynDNS implements the DynDNS2 update protocol used by routers, ddclient and inadyn:
//
//	GET /nic/update?hostname=home.example.com&myip=203.0.113.4
//
// Authenticate with HTTP Basic auth using any username and an API token with the
// "DNS edit" permission as the password. Responses are plain text per the protocol.
func (a *App) handleDynDNS(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	reply := func(status int, body string) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body + "\n"))
	}
	if !a.limiter.allow("dyndns:"+a.clientIP(r), 60, 30) {
		reply(429, "abuse")
		return
	}
	_, secret, ok := r.BasicAuth()
	if !ok {
		secret = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	tok, err := a.Store.APITokenByHash(ctx, secure.HashToken(strings.TrimSpace(secret)))
	if err != nil || secret == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="DynDNS"`)
		reply(401, "badauth")
		return
	}
	if len(tok.IPAllowlist) > 0 && !ipAllowed(a.clientIP(r), tok.IPAllowlist) {
		reply(403, "badauth")
		return
	}
	if !hasPerm(tokenRolePerms[tok.Role], PermDNSEdit) {
		reply(403, "badauth")
		return
	}
	_ = a.Store.TouchAPIToken(ctx, tok.ID, a.clientIP(r))
	org, err := a.Store.OrgByID(ctx, tok.OrgID)
	if err != nil || org.Suspended {
		reply(403, "badauth")
		return
	}
	act := &Actor{Type: "api_token", Token: tok, OrgID: &tok.OrgID, ID: &tok.ID, Label: "API token: " + tok.Name + " (DynDNS)"}
	ctx = withOrg(context.WithValue(ctx, keyActor, act), org, &access{Role: tok.Role, ZoneIDs: tok.ZoneIDs})
	r = r.WithContext(ctx)

	q := r.URL.Query()
	ips := cleanList(append(strings.Split(q.Get("myip"), ","), strings.Split(q.Get("myipv6"), ",")...))
	if len(ips) == 0 {
		ips = []string{a.clientIP(r)}
	}
	var v4, v6 string
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			reply(400, "badip")
			return
		}
		if ip.To4() != nil {
			v4 = ip.String()
		} else {
			v6 = ip.String()
		}
	}
	zones, err := a.Store.ListZones(ctx, org.ID, tok.ZoneIDs)
	if err != nil {
		reply(500, "911")
		return
	}
	ttl := orInt(a.Settings(ctx).DynDNSTTL, 60)
	var lines []string
	for _, host := range cleanList(strings.Split(q.Get("hostname"), ",")) {
		fq, err := dnsutil.CanonicalZone(host)
		if err != nil {
			lines = append(lines, "notfqdn")
			continue
		}
		var zone *store.Zone
		for i := range zones {
			z := &zones[i]
			if (fq == z.Name || strings.HasSuffix(fq, "."+z.Name)) && (zone == nil || len(z.Name) > len(zone.Name)) {
				zone = z
			}
		}
		if zone == nil || zone.Kind == "Slave" {
			lines = append(lines, "nohost")
			continue
		}
		res, err := a.dynUpdate(r, zone, fq, v4, v6, ttl)
		if err != nil {
			a.Log.Warn("dyndns update failed", "host", fq, "err", err)
			lines = append(lines, "dnserr")
			continue
		}
		lines = append(lines, res+" "+strings.Join(cleanList([]string{v4, v6}), ","))
	}
	if len(lines) == 0 {
		reply(400, "notfqdn")
		return
	}
	reply(200, strings.Join(lines, "\n"))
}

func hasPerm(list []Perm, p Perm) bool {
	for _, x := range list {
		if x == p {
			return true
		}
	}
	return false
}

// dynUpdate replaces the A and/or AAAA rrsets for host. It returns "good" or "nochg".
func (a *App) dynUpdate(r *http.Request, z *store.Zone, host, v4, v6 string, ttl int) (string, error) {
	ctx := r.Context()
	unlock := lockZone(z.ID)
	defer unlock()
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		return "", err
	}
	pz, err := c.GetZone(ctx, z.Name, true)
	if err != nil {
		return "", err
	}
	if err := conflictCheck(pz.RRSets, host, "A", nil); err != nil {
		return "", err
	}
	var patches []pdns.RRSet
	changed := map[string]string{}
	for typ, ip := range map[string]string{"A": v4, "AAAA": v6} {
		if ip == "" {
			continue
		}
		if cur := findRRSet(pz.RRSets, host, typ); cur != nil && len(cur.Records) == 1 && cur.Records[0].Content == ip && !cur.Records[0].Disabled {
			continue
		}
		patches = append(patches, pdns.RRSet{Name: host, Type: typ, TTL: ttl, ChangeType: "REPLACE", Records: []pdns.Record{{Content: ip}},
			Comments: []pdns.Comment{}})
		changed[typ] = ip
	}
	if len(patches) == 0 {
		return "nochg", nil
	}
	if err := c.PatchRRSets(ctx, z.Name, patches); err != nil {
		return "", err
	}
	a.audit(r, auditEvent{ZoneID: &z.ID, Action: "record.dyndns_update", ResourceType: "record", ResourceName: host,
		Metadata: map[string]any{"zone": z.Name, "addresses": changed, "ttl": ttl}})
	return "good", nil
}
