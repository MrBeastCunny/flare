package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func splitHostPortLoose(s string) (string, string, error) {
	if strings.Count(s, ":") > 1 && !strings.HasPrefix(s, "[") {
		return s, "", nil // bare IPv6
	}
	return net.SplitHostPort(s)
}

func parseIP(s string) net.IP { return net.ParseIP(strings.Trim(s, "[]")) }

type soaView struct {
	Primary    string `json:"primary"`
	Hostmaster string `json:"hostmaster"`
	Serial     int64  `json:"serial"`
	Refresh    int    `json:"refresh"`
	Retry      int    `json:"retry"`
	Expire     int    `json:"expire"`
	Minimum    int    `json:"minimum"`
	TTL        int    `json:"ttl"`
}

func parseSOA(content string, ttl int) soaView {
	f := strings.Fields(content)
	v := soaView{TTL: ttl}
	if len(f) >= 7 {
		v.Primary = f[0]
		v.Hostmaster = dnsutil.RNameToEmail(f[1])
		v.Serial, _ = strconv.ParseInt(f[2], 10, 64)
		v.Refresh, _ = strconv.Atoi(f[3])
		v.Retry, _ = strconv.Atoi(f[4])
		v.Expire, _ = strconv.Atoi(f[5])
		v.Minimum, _ = strconv.Atoi(f[6])
	}
	return v
}

func metaValues(meta []pdns.Metadata, kind string) []string {
	for _, m := range meta {
		if m.Kind == kind {
			return m.Metadata
		}
	}
	return []string{}
}

func (a *App) handleGetZoneSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pz, err := c.GetZone(ctx, z.Name, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	meta, err := c.Metadata(ctx, z.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var soa soaView
	if s := findRRSet(pz.RRSets, z.Name, "SOA"); s != nil && len(s.Records) > 0 {
		soa = parseSOA(s.Records[0].Content, s.TTL)
	}
	nsSets, _ := a.Store.ListNameserverSets(ctx)
	writeJSON(w, 200, map[string]any{
		"kind":              pz.Kind,
		"catalog":           pz.Catalog,
		"masters":           orEmpty(pz.Masters),
		"soa":               soa,
		"soa_edit_api":      pz.SOAEditAPI,
		"serial":            pz.Serial,
		"also_notify":       metaValues(meta, "ALSO-NOTIFY"),
		"allow_axfr_from":   metaValues(meta, "ALLOW-AXFR-FROM"),
		"tsig_allow_axfr":   metaValues(meta, "TSIG-ALLOW-AXFR"),
		"axfr_master_tsig":  metaValues(meta, "AXFR-MASTER-TSIG"),
		"nameserver_set_id": z.NameserverSetID,
		"nameservers":       z.AssignedNameservers,
		"nameserver_sets":   nsSets,
	})
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type zoneSettingsInput struct {
	Kind           *string   `json:"kind"`
	Catalog        *string   `json:"catalog"`
	Masters        *[]string `json:"masters"`
	SOA            *soaView  `json:"soa"`
	SOAEditAPI     *string   `json:"soa_edit_api"`
	AlsoNotify     *[]string `json:"also_notify"`
	AllowAXFRFrom  *[]string `json:"allow_axfr_from"`
	TSIGAllowAXFR  *[]string `json:"tsig_allow_axfr"`
	AXFRMasterTSIG *[]string `json:"axfr_master_tsig"`
}

var soaEditValues = map[string]bool{"DEFAULT": true, "INCREASE": true, "EPOCH": true, "OFF": true, "INCEPTION-INCREMENT": true}

func (a *App) handleUpdateZoneSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	var in zoneSettingsInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	unlock := lockZone(z.ID)
	defer unlock()
	pz, err := c.GetZone(ctx, z.Name, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	changes := map[string]any{}
	zoneProps := map[string]any{}
	if in.Kind != nil {
		k, err := normalizeKind(*in.Kind)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if k != pz.Kind {
			zoneProps["kind"] = k
			changes["kind"] = map[string]string{"from": pz.Kind, "to": k}
		}
	}
	if in.Masters != nil {
		list := cleanList(*in.Masters)
		for _, m := range list {
			if err := validateMaster(m); err != nil {
				a.fail(w, r, errField("masters", err.Error()))
				return
			}
		}
		zoneProps["masters"] = list
		changes["masters"] = list
	}
	if in.Catalog != nil {
		cat := strings.TrimSpace(strings.ToLower(*in.Catalog))
		if cat != "" {
			fq, err := dnsutil.CanonicalZone(cat)
			if err != nil {
				a.fail(w, r, errField("catalog", err.Error()))
				return
			}
			cat = fq
		}
		if cat != pz.Catalog {
			zoneProps["catalog"] = cat
			changes["catalog"] = map[string]string{"from": pz.Catalog, "to": cat}
		}
	}
	if in.SOAEditAPI != nil {
		if !soaEditValues[*in.SOAEditAPI] {
			a.fail(w, r, errField("soa_edit_api", "Unsupported SOA-EDIT-API value"))
			return
		}
		zoneProps["soa_edit_api"] = *in.SOAEditAPI
		changes["soa_edit_api"] = *in.SOAEditAPI
	}
	if len(zoneProps) > 0 {
		if err := c.UpdateZone(ctx, z.Name, zoneProps); err != nil {
			a.fail(w, r, err)
			return
		}
		if k, ok := zoneProps["kind"].(string); ok {
			_ = a.Store.SetZoneKind(ctx, z.ID, k)
		}
	}
	if in.SOA != nil {
		s := in.SOA
		fields := map[string]string{}
		primary, err := dnsutil.Hostname(s.Primary)
		if err != nil {
			fields["soa.primary"] = err.Error()
		}
		if _, err := normalizeEmail(s.Hostmaster); err != nil {
			fields["soa.hostmaster"] = "Enter a valid email address"
		}
		check := func(name string, v, min, max int) {
			if v < min || v > max {
				fields["soa."+name] = fmt.Sprintf("Must be between %d and %d", min, max)
			}
		}
		check("refresh", s.Refresh, 60, 86400*7)
		check("retry", s.Retry, 60, 86400*7)
		check("expire", s.Expire, 3600, 86400*365)
		check("minimum", s.Minimum, 30, 86400)
		check("ttl", s.TTL, 30, 86400*7)
		if len(fields) > 0 {
			a.fail(w, r, errValidation(fields))
			return
		}
		current := soaView{}
		if old := findRRSet(pz.RRSets, z.Name, "SOA"); old != nil && len(old.Records) > 0 {
			current = parseSOA(old.Records[0].Content, old.TTL)
		}
		content := dnsutil.SOAContent(primary, s.Hostmaster, current.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
		if err := c.PatchRRSets(ctx, z.Name, []pdns.RRSet{{Name: z.Name, Type: "SOA", TTL: s.TTL, ChangeType: "REPLACE",
			Records: []pdns.Record{{Content: content}}}}); err != nil {
			a.fail(w, r, err)
			return
		}
		changes["soa"] = map[string]any{"from": current, "to": s}
	}
	meta := []struct {
		kind  string
		value *[]string
		check func(string) error
	}{
		{"ALSO-NOTIFY", in.AlsoNotify, validateMaster},
		{"ALLOW-AXFR-FROM", in.AllowAXFRFrom, func(s string) error {
			if s == "AUTO-NS" {
				return nil
			}
			return validateCIDRs([]string{s})
		}},
		{"TSIG-ALLOW-AXFR", in.TSIGAllowAXFR, nil},
		{"AXFR-MASTER-TSIG", in.AXFRMasterTSIG, nil},
	}
	for _, m := range meta {
		if m.value == nil {
			continue
		}
		list := cleanList(*m.value)
		if m.check != nil {
			for _, v := range list {
				if err := m.check(v); err != nil {
					a.fail(w, r, errField(strings.ToLower(strings.ReplaceAll(m.kind, "-", "_")), err.Error()))
					return
				}
			}
		}
		if err := c.SetMetadata(ctx, z.Name, m.kind, list); err != nil {
			a.fail(w, r, err)
			return
		}
		changes[strings.ToLower(m.kind)] = list
	}
	if len(changes) > 0 {
		a.audit(r, auditEvent{Action: "zone.settings_update", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name, Metadata: changes})
	}
	a.handleGetZoneSettings(w, r)
}

func (a *App) handleChangeZoneNameservers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	var in struct {
		NameserverSetID uuid.UUID `json:"nameserver_set_id"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	set, err := a.Store.NameserverSetByID(ctx, in.NameserverSetID)
	if err != nil {
		a.fail(w, r, errField("nameserver_set_id", "Nameserver set not found"))
		return
	}
	if err := a.applyNameservers(ctx, z, set); err != nil {
		a.fail(w, r, err)
		return
	}
	if z.Status == "active" {
		_ = a.Store.SetZoneStatus(ctx, z.ID, "pending")
	}
	a.audit(r, auditEvent{Action: "zone.nameservers_change", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"from": z.AssignedNameservers, "to": set.Nameservers, "set": set.Name}})
	updated, _ := a.Store.ZoneByID(ctx, z.OrgID, z.ID)
	writeJSON(w, 200, updated)
}

// applyNameservers points a zone at a nameserver set: the apex NS records, the SOA primary
// nameserver and (when the set defines one) the SOA hostmaster follow the set.
func (a *App) applyNameservers(ctx context.Context, z *store.Zone, set *store.NameserverSet) error {
	if len(set.Nameservers) == 0 {
		return errBadRequest("The nameserver set has no nameservers.")
	}
	if z.Kind != "Slave" && z.Kind != "Consumer" {
		c, err := a.PDNSForZone(ctx, z)
		if err != nil {
			return err
		}
		unlock := lockZone(z.ID)
		defer unlock()
		pz, err := c.GetZone(ctx, z.Name, true)
		if err != nil {
			return err
		}
		patches := []pdns.RRSet{{Name: z.Name, Type: "NS", TTL: 86400, ChangeType: "REPLACE", Records: nsRecords(set.Nameservers)}}
		if old := findRRSet(pz.RRSets, z.Name, "NS"); old != nil && old.TTL > 0 {
			patches[0].TTL = old.TTL
			patches[0].Comments = old.Comments
		}
		if old := findRRSet(pz.RRSets, z.Name, "SOA"); old != nil && len(old.Records) > 0 {
			f := strings.Fields(old.Records[0].Content)
			if len(f) >= 7 {
				f[0] = dnsFqdn(set.Nameservers[0])
				if set.Hostmaster != "" {
					f[1] = dnsutil.HostmasterToRName(set.Hostmaster)
				}
				patches = append(patches, pdns.RRSet{Name: z.Name, Type: "SOA", TTL: old.TTL, ChangeType: "REPLACE",
					Records: []pdns.Record{{Content: strings.Join(f, " ")}}})
			}
		}
		if err := c.PatchRRSets(ctx, z.Name, patches); err != nil {
			return err
		}
	}
	return a.Store.SetZoneNameservers(ctx, z.ID, &set.ID, set.Nameservers)
}

// ---- DNSSEC ----

func (a *App) handleGetDNSSEC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	pz, err := c.GetZone(ctx, z.Name, false)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	keys, err := c.CryptoKeys(ctx, z.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if keys == nil {
		keys = []pdns.CryptoKey{}
	}
	ds := []string{}
	for _, k := range keys {
		if k.Active && (k.KeyType == "ksk" || k.KeyType == "csk") {
			ds = append(ds, k.DS...)
		}
	}
	writeJSON(w, 200, map[string]any{"enabled": pz.DNSSEC, "nsec3param": pz.NSEC3Param, "nsec3narrow": pz.NSEC3Narrow,
		"keys": keys, "ds": ds, "presigned": pz.Presigned})
}

var dnssecAlgorithms = map[string]bool{"ecdsap256sha256": true, "ecdsap384sha384": true, "ed25519": true, "ed448": true,
	"rsasha256": true, "rsasha512": true}

func (a *App) handleEnableDNSSEC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	if z.Kind == "Slave" {
		a.fail(w, r, errConflict("Secondary zones are signed by their primary server."))
		return
	}
	var in struct {
		Algorithm string `json:"algorithm"`
		NSEC3     bool   `json:"nsec3"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &in); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	if in.Algorithm == "" {
		in.Algorithm = "ecdsap256sha256"
	}
	if !dnssecAlgorithms[in.Algorithm] {
		a.fail(w, r, errField("algorithm", "Unsupported algorithm"))
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	keys, err := c.CryptoKeys(ctx, z.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if len(keys) == 0 {
		k := pdns.CryptoKey{KeyType: "csk", Active: true, Published: true, Algorithm: in.Algorithm}
		if strings.HasPrefix(in.Algorithm, "rsa") {
			k.Bits = 2048
		}
		if _, err := c.CreateCryptoKey(ctx, z.Name, k); err != nil {
			a.fail(w, r, err)
			return
		}
	} else {
		for _, k := range keys {
			if !k.Active {
				_ = c.SetCryptoKeyActive(ctx, z.Name, k.ID, true)
			}
		}
	}
	if in.NSEC3 {
		if err := c.UpdateZone(ctx, z.Name, map[string]any{"nsec3param": "1 0 0 -", "nsec3narrow": false}); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	_ = c.Rectify(ctx, z.Name)
	a.audit(r, auditEvent{Action: "zone.dnssec_enable", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"algorithm": in.Algorithm, "nsec3": in.NSEC3}})
	a.handleGetDNSSEC(w, r)
}

func (a *App) handleDisableDNSSEC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	keys, err := c.CryptoKeys(ctx, z.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	for _, k := range keys {
		if err := c.DeleteCryptoKey(ctx, z.Name, k.ID); err != nil && !pdns.IsNotFound(err) {
			a.fail(w, r, err)
			return
		}
	}
	_ = c.UpdateZone(ctx, z.Name, map[string]any{"nsec3param": ""})
	_ = c.Rectify(ctx, z.Name)
	a.audit(r, auditEvent{Action: "zone.dnssec_disable", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"keys_removed": len(keys)}})
	a.handleGetDNSSEC(w, r)
}

func (a *App) handleAddCryptoKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	var in struct {
		KeyType   string `json:"keytype"`
		Algorithm string `json:"algorithm"`
		Active    bool   `json:"active"`
		Published bool   `json:"published"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.KeyType != "ksk" && in.KeyType != "zsk" && in.KeyType != "csk" {
		a.fail(w, r, errField("keytype", "Key type must be KSK, ZSK or CSK"))
		return
	}
	if !dnssecAlgorithms[in.Algorithm] {
		a.fail(w, r, errField("algorithm", "Unsupported algorithm"))
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	k := pdns.CryptoKey{KeyType: in.KeyType, Algorithm: in.Algorithm, Active: in.Active, Published: in.Published}
	if strings.HasPrefix(in.Algorithm, "rsa") {
		k.Bits = 2048
	}
	created, err := c.CreateCryptoKey(ctx, z.Name, k)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	_ = c.Rectify(ctx, z.Name)
	a.audit(r, auditEvent{Action: "zone.dnssec_key_add", ResourceType: "cryptokey", ResourceID: strconv.Itoa(created.ID), ResourceName: z.Name,
		Metadata: map[string]any{"keytype": in.KeyType, "algorithm": in.Algorithm, "active": in.Active}})
	a.handleGetDNSSEC(w, r)
}

func (a *App) handleUpdateCryptoKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	id, err := strconv.Atoi(chi.URLParam(r, "keyID"))
	if err != nil {
		a.fail(w, r, errNotFound("Key"))
		return
	}
	var in struct {
		Active bool `json:"active"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := c.SetCryptoKeyActive(ctx, z.Name, id, in.Active); err != nil {
		a.fail(w, r, err)
		return
	}
	_ = c.Rectify(ctx, z.Name)
	a.audit(r, auditEvent{Action: "zone.dnssec_key_update", ResourceType: "cryptokey", ResourceID: strconv.Itoa(id), ResourceName: z.Name,
		Metadata: map[string]any{"active": in.Active}})
	a.handleGetDNSSEC(w, r)
}

func (a *App) handleDeleteCryptoKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	id, err := strconv.Atoi(chi.URLParam(r, "keyID"))
	if err != nil {
		a.fail(w, r, errNotFound("Key"))
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := c.DeleteCryptoKey(ctx, z.Name, id); err != nil {
		a.fail(w, r, err)
		return
	}
	_ = c.Rectify(ctx, z.Name)
	a.audit(r, auditEvent{Action: "zone.dnssec_key_delete", ResourceType: "cryptokey", ResourceID: strconv.Itoa(id), ResourceName: z.Name})
	a.handleGetDNSSEC(w, r)
}

// ---- Overview ----

func (a *App) handleZoneOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	out := map[string]any{"zone": z}
	counts := map[string]int{}
	total := 0
	if c, err := a.PDNSForZone(ctx, z); err == nil {
		if pz, err := c.GetZone(ctx, z.Name, true); err == nil {
			for _, s := range pz.RRSets {
				counts[s.Type] += len(s.Records)
				total += len(s.Records)
			}
			out["serial"] = pz.Serial
			out["dnssec"] = pz.DNSSEC
			out["kind"] = pz.Kind
			out["server_reachable"] = true
		} else {
			out["server_reachable"] = false
			out["server_error"] = err.Error()
		}
		out["top_queries"] = a.topQueries(r, c, z.Name)
	}
	out["record_counts"] = counts
	out["record_total"] = total
	if a.can(ctx, PermAuditRead) || a.can(ctx, PermZonesRead) {
		activity, _ := a.Store.AuditActivity(ctx, &z.OrgID, &z.ID, 30)
		recent, _ := a.Store.ListAudit(ctx, store.AuditFilter{OrgID: &z.OrgID, ZoneID: &z.ID, Limit: 8})
		out["activity"] = activity
		out["recent_changes"] = recent
	}
	writeJSON(w, 200, out)
}

type queryStat struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

// topQueries extracts the zone's names from the server-wide query ring.
func (a *App) topQueries(r *http.Request, c *pdns.Client, zone string) []queryStat {
	stats, err := c.Statistics(r.Context())
	out := []queryStat{}
	if err != nil {
		return out
	}
	for _, s := range stats {
		if s.Name != "queries" || s.Type != "RingStatisticItem" {
			continue
		}
		var items []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if json.Unmarshal(s.Value, &items) != nil {
			continue
		}
		for _, it := range items {
			name, typ, _ := strings.Cut(it.Name, "/")
			name = strings.ToLower(name)
			if !strings.HasSuffix(name, ".") {
				name += "."
			}
			if name != zone && !strings.HasSuffix(name, "."+zone) {
				continue
			}
			n, _ := strconv.ParseInt(it.Value, 10, 64)
			out = append(out, queryStat{Name: name, Type: typ, Count: n})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return capList(out, 10)
}

func (a *App) handleOrgOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	acc := accessFrom(ctx)
	zones, err := a.Store.ListZones(ctx, org.ID, acc.ZoneIDs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	statusCounts := map[string]int{}
	for _, z := range zones {
		statusCounts[z.Status]++
	}
	members, _ := a.Store.ListMembers(ctx, org.ID)
	out := map[string]any{
		"zone_count":    len(zones),
		"status_counts": statusCounts,
		"member_count":  len(members),
		"recent_zones":  capList(zones, 0),
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].CreatedAt.After(zones[j].CreatedAt) })
	out["recent_zones"] = capList(zones, 6)
	if a.can(ctx, PermAuditRead) {
		activity, _ := a.Store.AuditActivity(ctx, &org.ID, nil, 30)
		recent, _ := a.Store.ListAudit(ctx, store.AuditFilter{OrgID: &org.ID, Limit: 8})
		out["activity"] = activity
		out["recent_activity"] = recent
	}
	if sso, err := a.Store.SSOConnectionForOrg(ctx, org.ID); err == nil {
		out["sso_enabled"] = sso.Enabled
	} else {
		out["sso_enabled"] = false
	}
	mfaCount := 0
	for _, m := range members {
		if m.UserTOTP {
			mfaCount++
		}
	}
	out["mfa_member_count"] = mfaCount
	writeJSON(w, 200, out)
}
