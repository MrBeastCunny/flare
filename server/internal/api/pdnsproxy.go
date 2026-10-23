package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// PowerDNS-compatible API.
//
// Tools built for the PowerDNS HTTP API (external-dns, cert-manager webhooks, the
// Terraform PowerDNS provider, acme.sh, octoDNS) can target Flare directly: they send a
// Flare API token in the X-API-Key header and use the usual /api/v1/servers/localhost
// paths. Requests are scoped to the token's organization and zones, permission-checked
// and written to the audit log, so automation never needs the real PowerDNS key.

type pdnsError struct {
	Error string `json:"error"`
}

func pdnsFail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, pdnsError{Error: msg})
}

// pdnsFailErr maps internal errors to PowerDNS-style error bodies.
func (a *App) pdnsFailErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	var pe *pdns.Error
	switch {
	case errors.As(err, &ae):
		msg := ae.Message
		for _, v := range ae.Fields {
			msg = v
		}
		pdnsFail(w, ae.Status, msg)
	case errors.As(err, &pe):
		pdnsFail(w, pe.Status, pe.Message)
	case errors.Is(err, db.ErrNotFound):
		pdnsFail(w, 404, "Not Found")
	default:
		a.Log.Error("pdns compat request failed", "err", err, "path", r.URL.Path)
		pdnsFail(w, 500, "Internal Server Error")
	}
}

// PDNSCompat requires an API token and loads its organization into the context. Global tokens
// have no single organization: zone routes resolve it from the zone (CompatZoneOrg), zone listing
// covers every organization in scope, and zone creation picks one with the "account" field.
func (a *App) PDNSCompat(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		act := actorFrom(r.Context())
		if act == nil || act.Type != "api_token" {
			pdnsFail(w, 401, "Unauthorized: send a Flare API token in the X-API-Key header")
			return
		}
		if act.Token.OrgID == nil {
			next.ServeHTTP(w, r)
			return
		}
		org, err := a.Store.OrgByID(r.Context(), *act.Token.OrgID)
		if err != nil {
			pdnsFail(w, 403, "Organization unavailable")
			return
		}
		acc, err := a.tokenAccess(r, act.Token, org)
		if err != nil {
			pdnsFail(w, 403, "Organization unavailable or IP address not allowed")
			return
		}
		next.ServeHTTP(w, r.WithContext(withOrg(r.Context(), org, acc)))
	})
}

// CompatZoneOrg scopes a global token's zone request to the organization that owns the zone.
func (a *App) CompatZoneOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if orgFrom(ctx) != nil {
			next.ServeHTTP(w, r)
			return
		}
		name, ok := compatZoneName(r)
		var z *store.Zone
		var org *store.Org
		var acc *access
		var err error
		if ok {
			if z, err = a.Store.ZoneByName(ctx, name); err == nil {
				if org, err = a.Store.OrgByID(ctx, z.OrgID); err == nil {
					acc, err = a.tokenAccess(r, actorFrom(ctx).Token, org)
				}
			}
		}
		if !ok || err != nil {
			pdnsFail(w, 404, "Could not find domain '"+name+"'")
			return
		}
		next.ServeHTTP(w, r.WithContext(withOrg(ctx, org, acc)))
	})
}

// compatOrgForCreate picks the organization a global token creates a zone in: the one named by
// the PowerDNS "account" field (ID or slug), or the only organization the token can use.
func (a *App) compatOrgForCreate(r *http.Request, account string) (*store.Org, *access, error) {
	ctx := r.Context()
	tok := actorFrom(ctx).Token
	var org *store.Org
	var err error
	account = strings.TrimSpace(account)
	switch {
	case account != "":
		if id, perr := uuid.Parse(account); perr == nil {
			org, err = a.Store.OrgByID(ctx, id)
		} else {
			org, err = a.Store.OrgBySlug(ctx, strings.ToLower(account))
		}
	case len(tok.OrgIDs) == 1:
		org, err = a.Store.OrgByID(ctx, tok.OrgIDs[0])
	default:
		return nil, nil, errBadRequest("Set \"account\" to the ID or slug of the organization that should own the zone.")
	}
	if err != nil {
		return nil, nil, errBadRequest("Organization \"" + account + "\" not found.")
	}
	acc, err := a.tokenAccess(r, tok, org)
	if err != nil {
		return nil, nil, errBadRequest("Organization \"" + account + "\" not found.")
	}
	return org, acc, nil
}

func pdnsServerObject(version string) map[string]any {
	return map[string]any{
		"type": "Server", "id": "localhost", "daemon_type": "authoritative", "version": version,
		"url": "/api/v1/servers/localhost", "config_url": "/api/v1/servers/localhost/config{/config_setting}",
		"zones_url": "/api/v1/servers/localhost/zones{/zone}",
	}
}

func (a *App) handleCompatServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, []any{pdnsServerObject("flare-" + Version)})
}

func (a *App) handleCompatServer(w http.ResponseWriter, r *http.Request) {
	if chi.URLParam(r, "serverID") != "localhost" {
		pdnsFail(w, 404, "Not Found")
		return
	}
	writeJSON(w, 200, pdnsServerObject("flare-"+Version))
}

func compatZoneObject(z *store.Zone) map[string]any {
	return map[string]any{
		"id": z.Name, "name": z.Name, "type": "Zone", "url": "/api/v1/servers/localhost/zones/" + z.Name,
		"kind": z.Kind, "account": "", "dnssec": false, "masters": []string{}, "serial": 0, "notified_serial": 0, "edited_serial": 0,
	}
}

func (a *App) handleCompatListZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if orgFrom(ctx) == nil {
		a.compatListGlobalZones(w, r)
		return
	}
	if !a.can(ctx, PermZonesRead) {
		pdnsFail(w, 403, "Forbidden")
		return
	}
	zones, err := a.Store.ListZones(ctx, orgFrom(ctx).ID, accessFrom(ctx).ZoneIDs)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	filter := strings.ToLower(r.URL.Query().Get("zone"))
	if filter != "" && !strings.HasSuffix(filter, ".") {
		filter += "."
	}
	out := []any{}
	for i := range zones {
		if filter == "" || zones[i].Name == filter {
			out = append(out, compatZoneObject(&zones[i]))
		}
	}
	writeJSON(w, 200, out)
}

// compatListGlobalZones lists zones in every organization a global token can use, with the
// organization's slug in "account".
func (a *App) compatListGlobalZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tok := actorFrom(ctx).Token
	orgs, err := a.Store.OrgsByIDs(ctx, tok.OrgIDs)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	filter, _ := compatNameParam(r.URL.Query().Get("zone"))
	out := []any{}
	for i := range orgs {
		if _, err := a.tokenAccess(r, tok, &orgs[i]); err != nil {
			continue
		}
		zones, err := a.Store.ListZones(ctx, orgs[i].ID, nil)
		if err != nil {
			a.pdnsFailErr(w, r, err)
			return
		}
		for j := range zones {
			if filter == "" || zones[j].Name == filter {
				obj := compatZoneObject(&zones[j])
				obj["account"] = orgs[i].Slug
				out = append(out, obj)
			}
		}
	}
	writeJSON(w, 200, out)
}

// compatNameParam normalizes a zone name from a PowerDNS API path or query.
func compatNameParam(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	name, err := url.PathUnescape(raw)
	if err != nil {
		return "", false
	}
	name = strings.ReplaceAll(strings.ToLower(name), "=2f", "/")
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name, true
}

func compatZoneName(r *http.Request) (string, bool) {
	return compatNameParam(chi.URLParam(r, "zoneID"))
}

// compatZone resolves the {zoneID} path parameter within the token's scope.
func (a *App) compatZone(r *http.Request) (*store.Zone, error) {
	ctx := r.Context()
	name, ok := compatZoneName(r)
	if !ok {
		return nil, errNotFound("Zone")
	}
	z, err := a.Store.ZoneByName(ctx, name)
	if err != nil || z.OrgID != orgFrom(ctx).ID || !zoneAllowed(accessFrom(ctx), z.ID) {
		return nil, &apiError{Status: 404, Code: "not_found", Message: "Could not find domain '" + name + "'"}
	}
	return z, nil
}

func (a *App) handleCompatGetZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !a.can(ctx, PermZonesRead) {
		pdnsFail(w, 403, "Forbidden")
		return
	}
	z, err := a.compatZone(r)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	pz, err := c.GetZone(ctx, z.Name, r.URL.Query().Get("rrsets") != "false")
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	pz.Account = ""
	if actorFrom(ctx).Token.OrgID == nil {
		pz.Account = orgFrom(ctx).Slug
	}
	writeJSON(w, 200, pz)
}

func (a *App) handleCompatCreateZone(w http.ResponseWriter, r *http.Request) {
	var in pdns.Zone
	if err := decode(r, &in); err != nil {
		pdnsFail(w, 400, "Invalid JSON body")
		return
	}
	if orgFrom(r.Context()) == nil {
		org, acc, err := a.compatOrgForCreate(r, in.Account)
		if err != nil {
			a.pdnsFailErr(w, r, err)
			return
		}
		r = r.WithContext(withOrg(r.Context(), org, acc))
	}
	ctx := r.Context()
	if !a.can(ctx, PermZonesCreate) {
		pdnsFail(w, 403, "Forbidden: this token cannot create zones")
		return
	}
	req := createZoneRequest{Name: in.Name, Kind: in.Kind, Masters: in.Masters}
	for _, s := range in.RRSets {
		if s.Type == "SOA" || s.Type == "NS" && strings.EqualFold(s.Name, in.Name) {
			continue
		}
		for _, rec := range s.Records {
			req.Records = append(req.Records, dnsutil.ParsedRR{Name: s.Name, Type: s.Type, TTL: s.TTL, Content: rec.Content})
		}
	}
	if in.DNSSEC {
		t := true
		req.DNSSEC = &t
	}
	res, err := a.createZone(r, req)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	c, err := a.PDNSForZone(ctx, res.Zone)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	pz, err := c.GetZone(ctx, res.Zone.Name, true)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	writeJSON(w, 201, pz)
}

func (a *App) handleCompatDeleteZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !a.can(ctx, PermZonesDelete) {
		pdnsFail(w, 403, "Forbidden: this token cannot delete zones")
		return
	}
	z, err := a.compatZone(r)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	if err := c.DeleteZone(ctx, z.Name); err != nil && !pdns.IsNotFound(err) {
		a.pdnsFailErr(w, r, err)
		return
	}
	if err := a.Store.DeleteZone(ctx, z.ID); err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	a.audit(r, auditEvent{ZoneID: &z.ID, Action: "zone.delete", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"via": "pdns_api"}})
	w.WriteHeader(204)
}

// handleCompatPatchZone applies rrset changes after validating names, types and content.
func (a *App) handleCompatPatchZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !a.can(ctx, PermDNSEdit) {
		pdnsFail(w, 403, "Forbidden: this token cannot edit records")
		return
	}
	z, err := a.compatZone(r)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	if z.Kind == "Slave" || z.Kind == "Consumer" {
		pdnsFail(w, 422, "Records of secondary zones cannot be modified")
		return
	}
	var in struct {
		RRSets []pdns.RRSet `json:"rrsets"`
	}
	if err := decode(r, &in); err != nil {
		pdnsFail(w, 400, "Invalid JSON body")
		return
	}
	settings := a.Settings(ctx)
	allowed := allowedTypes(settings, z.Name)
	changes := make([]map[string]any, 0, len(in.RRSets))
	for i := range in.RRSets {
		s := &in.RRSets[i]
		s.Name = strings.ToLower(dnsFqdn(s.Name))
		s.Type = strings.ToUpper(s.Type)
		s.ChangeType = strings.ToUpper(s.ChangeType)
		if s.Name != z.Name && !strings.HasSuffix(s.Name, "."+z.Name) {
			pdnsFail(w, 422, fmt.Sprintf("Name %q is out of zone", s.Name))
			return
		}
		if s.ChangeType != "REPLACE" && s.ChangeType != "DELETE" {
			pdnsFail(w, 422, "changetype must be REPLACE or DELETE")
			return
		}
		if s.Type == "SOA" && s.ChangeType == "DELETE" {
			pdnsFail(w, 422, "The SOA record cannot be deleted")
			return
		}
		if isApexNS(s.Name, s.Type, z.Name) {
			pdnsFail(w, 422, errApexNS)
			return
		}
		if s.ChangeType == "REPLACE" {
			if !typeAllowed(allowed, s.Type) {
				pdnsFail(w, 422, s.Type+" records are not allowed in this zone")
				return
			}
			ttl := orInt(s.TTL, orInt(settings.DefaultTTL, 3600))
			s.TTL = ttl
			for j := range s.Records {
				if s.Type == "SOA" || !dnsutil.IsSupportedType(s.Type) {
					continue
				}
				norm, err := dnsutil.NormalizeContent(z.Name, s.Name, s.Type, ttl, s.Records[j].Content)
				if err != nil {
					pdnsFail(w, 422, fmt.Sprintf("%s %s: %s", s.Type, s.Name, err.Error()))
					return
				}
				s.Records[j].Content = norm
			}
			if s.Comments == nil {
				s.Comments = []pdns.Comment{}
			}
		}
		changes = append(changes, map[string]any{"name": s.Name, "type": s.Type, "changetype": s.ChangeType, "records": len(s.Records)})
	}
	unlock := lockZone(z.ID)
	defer unlock()
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	if err := c.PatchRRSets(ctx, z.Name, in.RRSets); err != nil {
		a.pdnsFailErr(w, r, err)
		return
	}
	a.audit(r, auditEvent{ZoneID: &z.ID, Action: "record.api_patch", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"changes": capList(changes, 200), "via": "pdns_api"}})
	w.WriteHeader(204)
}

func (a *App) handleCompatZoneAction(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		perm := PermZonesEdit
		if action == "export" {
			perm = PermZonesRead
		}
		if !a.can(ctx, perm) {
			pdnsFail(w, 403, "Forbidden")
			return
		}
		z, err := a.compatZone(r)
		if err != nil {
			a.pdnsFailErr(w, r, err)
			return
		}
		c, err := a.PDNSForZone(ctx, z)
		if err != nil {
			a.pdnsFailErr(w, r, err)
			return
		}
		switch action {
		case "export":
			text, err := c.Export(ctx, z.Name)
			if err != nil {
				a.pdnsFailErr(w, r, err)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte(text))
			return
		case "notify":
			err = c.Notify(ctx, z.Name)
		case "rectify":
			err = c.Rectify(ctx, z.Name)
		case "axfr-retrieve":
			err = c.AXFRRetrieve(ctx, z.Name)
		}
		if err != nil {
			a.pdnsFailErr(w, r, err)
			return
		}
		a.audit(r, auditEvent{ZoneID: &z.ID, Action: "zone." + strings.ReplaceAll(action, "-", "_"), ResourceType: "zone", ResourceID: z.ID.String(),
			ResourceName: z.Name, Metadata: map[string]any{"via": "pdns_api"}})
		writeJSON(w, 200, map[string]string{"result": action + " completed"})
	}
}

func dnsFqdn(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}
