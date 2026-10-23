package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// zoneLocks serializes read-modify-write cycles against PowerDNS rrsets per zone.
var zoneLocks sync.Map

func lockZone(id uuid.UUID) func() {
	v, _ := zoneLocks.LoadOrStore(id, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	var once sync.Once
	// Safe to call more than once (an early release plus a deferred one).
	return func() { once.Do(m.Unlock) }
}

// ---- Listing ----

func (a *App) handleListZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	zones, err := a.Store.ListZones(ctx, org.ID, accessFrom(ctx).ZoneIDs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, zones)
}

func (a *App) handleGetZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	out := map[string]any{"zone": z}
	if c, err := a.PDNSForZone(ctx, z); err == nil {
		if pz, err := c.GetZone(ctx, z.Name, false); err == nil {
			out["serial"] = pz.Serial
			out["dnssec"] = pz.DNSSEC
			out["kind"] = pz.Kind
			out["masters"] = pz.Masters
			out["notified_serial"] = pz.NotifiedSerial
			out["server_reachable"] = true
		} else {
			out["server_reachable"] = false
			out["server_error"] = err.Error()
		}
	}
	writeJSON(w, 200, out)
}

// ---- Create ----

type createZoneRequest struct {
	Name             string             `json:"name"`
	Kind             string             `json:"kind"`
	Masters          []string           `json:"masters"`
	NameserverSetID  *uuid.UUID         `json:"nameserver_set_id"`
	Records          []dnsutil.ParsedRR `json:"records"`
	DNSSEC           *bool              `json:"dnssec"`
	SkipVerification bool               `json:"skip_verification"`
	TemplateID       *uuid.UUID         `json:"template_id"`
}

func (a *App) handleScanZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	name, err := dnsutil.CanonicalZone(in.Name)
	if err != nil {
		a.fail(w, r, errField("name", err.Error()))
		return
	}
	if !a.limiter.allow("scan:"+orgFrom(ctx).ID.String(), 20, 10) {
		a.fail(w, r, errCode(429, "rate_limited", "Too many scans. Wait a minute and try again."))
		return
	}
	if z, err := a.Store.ZoneByName(ctx, name); err == nil {
		msg := "This domain is already added to another organization."
		if z.OrgID == orgFrom(ctx).ID {
			msg = "This domain is already added to your organization."
		}
		a.fail(w, r, errField("name", msg))
		return
	}
	res := &dnsutil.Resolver{Addr: a.Cfg.DNSResolver, Timeout: 3 * time.Second}
	records, skipped := res.Scan(ctx, name)
	ns, _ := res.LookupNS(ctx, name)
	if records == nil {
		records = []dnsutil.ParsedRR{}
	}
	if skipped > 0 {
		a.Log.Warn("zone scan discarded unroutable answers; DNS on this host is being rewritten", "zone", name, "skipped", skipped, "resolver", a.Cfg.DNSResolver)
	}
	writeJSON(w, 200, map[string]any{"name": name, "records": records, "current_nameservers": ns, "skipped_addresses": skipped})
}

func (a *App) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	var in createZoneRequest
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	res, err := a.createZone(r, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 201, res)
}

type createZoneResult struct {
	Zone            *store.Zone `json:"zone"`
	ImportedRecords int         `json:"imported_records"`
	DNSSECError     string      `json:"dnssec_error"`
}

func normalizeKind(k string) (string, error) {
	switch strings.ToUpper(k) {
	case "", "NATIVE":
		return "Native", nil
	case "MASTER", "PRIMARY":
		return "Master", nil
	case "SLAVE", "SECONDARY":
		return "Slave", nil
	case "PRODUCER":
		return "Producer", nil
	case "CONSUMER":
		return "Consumer", nil
	}
	return "", errField("kind", "Zone type must be Native, Primary, Secondary, Producer or Consumer")
}

// createZone provisions a zone on the organization's PowerDNS server and records it.
// It is shared by the dashboard API, templates and the PowerDNS-compatible API.
func (a *App) createZone(r *http.Request, in createZoneRequest) (*createZoneResult, error) {
	ctx := r.Context()
	org := orgFrom(ctx)
	act := actorFrom(ctx)
	acc := accessFrom(ctx)
	if acc.ZoneIDs != nil {
		return nil, errForbidden("Your access is limited to specific zones, so you cannot add new zones.")
	}
	name, err := dnsutil.CanonicalZone(in.Name)
	if err != nil {
		return nil, errField("name", err.Error())
	}
	kind, err := normalizeKind(in.Kind)
	if err != nil {
		return nil, err
	}
	var masters []string
	if kind == "Slave" || kind == "Consumer" {
		for _, m := range cleanList(in.Masters) {
			if err := validateMaster(m); err != nil {
				return nil, errField("masters", err.Error())
			}
			masters = append(masters, m)
		}
		if len(masters) == 0 {
			return nil, errField("masters", "Secondary zones need at least one primary server address")
		}
	}
	if in.TemplateID != nil {
		t, err := a.Store.TemplateForOrg(ctx, &org.ID, *in.TemplateID)
		if err != nil {
			return nil, errField("template_id", "Template not found")
		}
		for _, rec := range t.Records {
			in.Records = append(in.Records, dnsutil.ParsedRR{Name: rec.Name, Type: rec.Type, TTL: rec.TTL, Content: dnsutil.ExpandRelativeTargets(name, rec.Type, rec.Content)})
		}
	}

	settings := a.Settings(ctx)
	maxZones := settings.DefaultMaxZones
	if org.MaxZones != nil {
		maxZones = *org.MaxZones
	}
	if n, err := a.Store.CountZones(ctx, org.ID); err != nil {
		return nil, err
	} else if maxZones > 0 && n >= maxZones {
		return nil, errCode(403, "quota_exceeded", fmt.Sprintf("This organization has reached its limit of %d zones. Contact your administrator to raise it.", maxZones))
	}
	if err := a.checkZoneOwnership(ctx, org.ID, name); err != nil {
		return nil, err
	}

	var srv *store.PDNSServer
	if org.PDNSServerID != nil {
		srv, err = a.Store.ServerByID(ctx, *org.PDNSServerID)
	} else {
		srv, err = a.Store.DefaultServer(ctx)
	}
	if errors.Is(err, db.ErrNotFound) {
		return nil, errCode(503, "no_server", "No DNS server is configured. An instance administrator must add one.")
	}
	if err != nil {
		return nil, err
	}
	var nsSet *store.NameserverSet
	switch {
	case in.NameserverSetID != nil:
		nsSet, err = a.Store.NameserverSetByID(ctx, *in.NameserverSetID)
	case org.NameserverSetID != nil:
		nsSet, err = a.Store.NameserverSetByID(ctx, *org.NameserverSetID)
	default:
		nsSet, err = a.Store.DefaultNameserverSet(ctx)
	}
	if errors.Is(err, db.ErrNotFound) {
		return nil, errCode(503, "no_nameservers", "No nameserver set is configured. An instance administrator must add one.")
	}
	if err != nil {
		return nil, err
	}

	client, err := a.PDNS(srv)
	if err != nil {
		return nil, err
	}
	pz := &pdns.Zone{Name: name, Kind: kind, Masters: masters, SOAEditAPI: orStr(settings.SOAEditAPI, "DEFAULT"), APIRectify: true,
		Account: truncate(org.Slug, 40)}
	var importedCount int
	if kind != "Slave" && kind != "Consumer" {
		hostmaster := nsSet.Hostmaster
		if hostmaster == "" {
			hostmaster = orStr(settings.SupportEmail, "hostmaster@"+strings.TrimSuffix(name, "."))
		}
		soa := settings.SOA
		serial, _ := strconv.ParseInt(time.Now().UTC().Format("20060102")+"01", 10, 64)
		pz.RRSets = []pdns.RRSet{
			{Name: name, Type: "SOA", TTL: orInt(soa.TTL, 3600), Records: []pdns.Record{{Content: dnsutil.SOAContent(nsSet.Nameservers[0],
				hostmaster, serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum)}}},
			{Name: name, Type: "NS", TTL: 86400, Records: nsRecords(nsSet.Nameservers)},
		}
		imported, err := a.buildImportRRSets(name, in.Records, settings.DefaultTTL, true)
		if err != nil {
			return nil, err
		}
		for _, rs := range imported {
			importedCount += len(rs.Records)
		}
		pz.RRSets = append(pz.RRSets, imported...)
	}
	if _, err := client.CreateZone(ctx, pz); err != nil {
		var pe *pdns.Error
		if errors.As(err, &pe) && pe.Status == 409 {
			return nil, errField("name", "This zone already exists on the DNS server. Ask an administrator to import it.")
		}
		return nil, err
	}
	status := "pending"
	superadmin := act.Type == "user" && act.User.IsSuperadmin
	if in.SkipVerification && (superadmin || acc.Role == "owner" || acc.Role == "admin") {
		status = "active"
	}
	// Reverse zones are delegated by the address holder (RIR or ISP); never block them on a delegation check.
	if dnsutil.IsReverseZone(name) && in.SkipVerification {
		status = "active"
	}
	var createdBy *uuid.UUID
	if act.Type == "user" {
		createdBy = &act.User.ID
	}
	zone, err := a.Store.CreateZone(ctx, store.NewZone{OrgID: org.ID, PDNSServerID: srv.ID, NameserverSetID: &nsSet.ID, Name: name, Kind: kind,
		Status: status, Nameservers: nsSet.Nameservers, CreatedBy: createdBy})
	if err != nil {
		_ = client.DeleteZone(context.WithoutCancel(ctx), name)
		if db.IsUniqueViolation(err) {
			return nil, errField("name", "This domain has already been added.")
		}
		return nil, err
	}
	dnssec := settings.DefaultDNSSEC
	if in.DNSSEC != nil {
		dnssec = *in.DNSSEC
	}
	dnssecErr := ""
	if dnssec && kind != "Slave" && kind != "Consumer" {
		if _, err := client.CreateCryptoKey(ctx, name, pdns.CryptoKey{KeyType: "csk", Active: true, Published: true, Algorithm: "ecdsap256sha256"}); err != nil {
			dnssecErr = err.Error()
		} else {
			_ = client.Rectify(ctx, name)
		}
	}
	a.audit(r, auditEvent{ZoneID: &zone.ID, Action: "zone.create", ResourceType: "zone", ResourceID: zone.ID.String(), ResourceName: zone.Name,
		Metadata: map[string]any{"kind": kind, "server": srv.Name, "nameservers": nsSet.Nameservers, "imported_records": importedCount,
			"dnssec": dnssec && dnssecErr == "", "status": status, "template_id": in.TemplateID}})
	return &createZoneResult{Zone: zone, ImportedRecords: importedCount, DNSSECError: dnssecErr}, nil
}

// checkZoneOwnership prevents claiming a name that overlaps another organization's zone.
func (a *App) checkZoneOwnership(ctx context.Context, orgID uuid.UUID, name string) error {
	if z, err := a.Store.ZoneByName(ctx, name); err == nil {
		if z.OrgID == orgID {
			return errField("name", "This domain is already added to your organization.")
		}
		return errField("name", "This domain is already added to another organization.")
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 1; i < len(labels)-1; i++ {
		parent := strings.Join(labels[i:], ".") + "."
		if z, err := a.Store.ZoneByName(ctx, parent); err == nil && z.OrgID != orgID {
			return errField("name", "A parent domain is managed by another organization.")
		}
	}
	all, err := a.Store.ListAllZones(ctx, strings.TrimSuffix(name, "."))
	if err != nil {
		return err
	}
	for _, z := range all {
		if strings.HasSuffix(z.Name, "."+name) && z.OrgID != orgID {
			return errField("name", "A subdomain of this domain is managed by another organization.")
		}
	}
	return nil
}

func validateMaster(m string) error {
	host := m
	if h, _, err := splitHostPortLoose(m); err == nil {
		host = h
	}
	if net := parseIP(host); net == nil {
		return fmt.Errorf("%q must be an IP address, optionally with :port", m)
	}
	return nil
}

func nsRecords(ns []string) []pdns.Record {
	out := make([]pdns.Record, 0, len(ns))
	for _, n := range ns {
		out = append(out, pdns.Record{Content: n})
	}
	return out
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// buildImportRRSets validates parsed records and groups them into rrsets.
func (a *App) buildImportRRSets(zone string, recs []dnsutil.ParsedRR, defaultTTL int, skipApexNS bool) ([]pdns.RRSet, error) {
	type key struct{ name, typ string }
	sets := map[key]*pdns.RRSet{}
	var order []key
	for i, rr := range recs {
		typ := strings.ToUpper(rr.Type)
		if typ == "SOA" || (skipApexNS && typ == "NS" && strings.EqualFold(rr.Name, zone)) {
			continue
		}
		if !dnsutil.IsSupportedType(typ) || typ == "DNSKEY" {
			continue
		}
		name, err := dnsutil.RecordName(rr.Name, zone)
		if err != nil {
			return nil, errField(fmt.Sprintf("records.%d.name", i), err.Error())
		}
		ttl := rr.TTL
		if ttl <= 0 {
			ttl = defaultTTL
		}
		content, err := dnsutil.NormalizeContent(zone, name, typ, ttl, rr.Content)
		if err != nil {
			return nil, errField(fmt.Sprintf("records.%d.content", i), fmt.Sprintf("%s %s: %s", typ, strings.TrimSuffix(name, "."), err.Error()))
		}
		k := key{name, typ}
		s, ok := sets[k]
		if !ok {
			s = &pdns.RRSet{Name: name, Type: typ, TTL: ttl, ChangeType: "REPLACE"}
			sets[k] = s
			order = append(order, k)
		}
		dup := false
		for _, existing := range s.Records {
			dup = dup || existing.Content == content
		}
		if !dup {
			s.Records = append(s.Records, pdns.Record{Content: content})
		}
		if ttl < s.TTL {
			s.TTL = ttl
		}
	}
	out := make([]pdns.RRSet, 0, len(order))
	for _, k := range order {
		s := sets[k]
		s.Comments = []pdns.Comment{}
		out = append(out, *s)
	}
	return out, nil
}

// ---- Records ----

type recordDTO struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      int    `json:"ttl"`
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
}

func recordID(name, typ, content string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(name + "\x00" + typ + "\x00" + content))
}

func parseRecordID(id string) (name, typ, content string, err error) {
	raw, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil {
		return "", "", "", errNotFound("Record")
	}
	parts := strings.SplitN(string(raw), "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", errNotFound("Record")
	}
	return parts[0], parts[1], parts[2], nil
}

func flattenRRSets(sets []pdns.RRSet) []recordDTO {
	out := []recordDTO{}
	for _, s := range sets {
		comment := ""
		if len(s.Comments) > 0 {
			comment = s.Comments[len(s.Comments)-1].Content
		}
		for _, rec := range s.Records {
			out = append(out, recordDTO{ID: recordID(s.Name, s.Type, rec.Content), Name: s.Name, Type: s.Type, TTL: s.TTL,
				Content: rec.Content, Disabled: rec.Disabled, Comment: comment})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type == "SOA" || out[j].Type == "SOA" {
			return out[i].Type == "SOA" && out[j].Type != "SOA"
		}
		ni, nj := reverseName(out[i].Name), reverseName(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Content < out[j].Content
	})
	return out
}

// reverseName sorts names hierarchically (apex first, then children).
func reverseName(n string) string {
	labels := strings.Split(strings.TrimSuffix(n, "."), ".")
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return strings.Join(labels, "\x01")
}

func (a *App) handleListRecords(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, 200, map[string]any{"records": flattenRRSets(pz.RRSets), "serial": pz.Serial, "dnssec": pz.DNSSEC})
}

type recordInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      int    `json:"ttl"`
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
	// CreatePTR adds or updates the matching PTR record in a reverse zone of the
	// same organization. When omitted the instance auto-PTR setting applies.
	CreatePTR *bool `json:"create_ptr,omitempty"`
}

// allowedTypes returns the record types permitted for a zone (nil = all).
func allowedTypes(s store.InstanceSettings, zone string) []string {
	if dnsutil.IsReverseZone(zone) {
		return s.ReverseRecordTypes
	}
	return s.ForwardRecordTypes
}

func typeAllowed(list []string, typ string) bool {
	if len(list) == 0 {
		return true
	}
	for _, t := range list {
		if strings.EqualFold(t, typ) {
			return true
		}
	}
	return false
}

// syncPTR maintains the reverse record for an A/AAAA record when a matching reverse
// zone exists in the same organization. It returns a short description or an error.
func (a *App) syncPTR(r *http.Request, z *store.Zone, in recordInput, name, typ, content string) map[string]any {
	ctx := r.Context()
	want := a.Settings(ctx).AutoPTR
	if in.CreatePTR != nil {
		want = *in.CreatePTR
	}
	if !want || (typ != "A" && typ != "AAAA") || in.Disabled {
		return nil
	}
	ptr, err := dnsutil.PTRName(content)
	if err != nil {
		return nil
	}
	zones, err := a.Store.ListZones(ctx, z.OrgID, accessFrom(ctx).ZoneIDs)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	var target *store.Zone
	for i := range zones {
		rz := &zones[i]
		if dnsutil.IsReverseZone(rz.Name) && strings.HasSuffix(ptr, "."+rz.Name) && (target == nil || len(rz.Name) > len(target.Name)) {
			target = rz
		}
	}
	if target == nil {
		return map[string]any{"skipped": "No reverse zone for " + content + " exists in this organization."}
	}
	c, err := a.PDNSForZone(ctx, target)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	unlock := lockZone(target.ID)
	defer unlock()
	if err := c.PatchRRSets(ctx, target.Name, []pdns.RRSet{{Name: ptr, Type: "PTR", TTL: orInt(in.TTL, 3600), ChangeType: "REPLACE",
		Records: []pdns.Record{{Content: name}}, Comments: []pdns.Comment{}}}); err != nil {
		return map[string]any{"error": err.Error()}
	}
	a.audit(r, auditEvent{ZoneID: &target.ID, Action: "record.ptr_sync", ResourceType: "record", ResourceName: ptr,
		Metadata: map[string]any{"zone": target.Name, "type": "PTR", "content": name, "source": typ + " " + content}})
	return map[string]any{"zone": target.Name, "name": ptr}
}

func (a *App) normalizeRecord(z *store.Zone, in recordInput) (name, typ, content string, ttl int, err error) {
	typ = strings.ToUpper(strings.TrimSpace(in.Type))
	fields := map[string]string{}
	if !dnsutil.IsSupportedType(typ) || typ == "SOA" {
		fields["type"] = "Unsupported record type"
	}
	name, nerr := dnsutil.RecordName(in.Name, z.Name)
	if nerr != nil {
		fields["name"] = nerr.Error()
	}
	ttl = in.TTL
	if ttl == 1 || ttl == 0 {
		ttl = orInt(a.Settings(context.Background()).DefaultTTL, 3600)
	}
	if ttl < 30 || ttl > 2147483647 {
		fields["ttl"] = "TTL must be between 30 seconds and 68 years"
	}
	if len(in.Comment) > 500 {
		fields["comment"] = "Comment must be 500 characters or fewer"
	}
	if fields["type"] == "" && !typeAllowed(allowedTypes(a.Settings(context.Background()), z.Name), typ) {
		fields["type"] = typ + " records are not allowed in this zone by your administrator"
	}
	if len(fields) > 0 {
		return "", "", "", 0, errValidation(fields)
	}
	if typ == "CNAME" && name == z.Name {
		return "", "", "", 0, errField("name", "A CNAME record cannot be created at the zone apex. Use an ALIAS record instead.")
	}
	if typ == "NS" && name == z.Name {
		return "", "", "", 0, errField("name", errApexNS)
	}
	content, cerr := dnsutil.NormalizeContent(z.Name, name, typ, ttl, in.Content)
	if cerr != nil {
		return "", "", "", 0, errField("content", cerr.Error())
	}
	return name, typ, content, ttl, nil
}

// errApexNS explains why apex NS records cannot be edited as ordinary records.
const errApexNS = "The zone's own NS records are managed through its nameserver set. Change the nameservers in zone settings."

// isApexNS reports whether an RRset is the zone's own NS set, which follows the nameserver set.
func isApexNS(name, typ, zone string) bool {
	return typ == "NS" && strings.EqualFold(name, zone)
}

func findRRSet(sets []pdns.RRSet, name, typ string) *pdns.RRSet {
	for i := range sets {
		if sets[i].Name == name && sets[i].Type == typ {
			return &sets[i]
		}
	}
	return nil
}

func conflictCheck(sets []pdns.RRSet, name, typ string, ignore *pdns.RRSet) error {
	for _, s := range sets {
		if s.Name != name || len(s.Records) == 0 || (ignore != nil && s.Name == ignore.Name && s.Type == ignore.Type) {
			continue
		}
		if typ == "CNAME" && s.Type != "CNAME" && s.Type != "RRSIG" && s.Type != "NSEC" {
			return errField("name", fmt.Sprintf("A CNAME record cannot coexist with the existing %s record at this name.", s.Type))
		}
		if typ != "CNAME" && s.Type == "CNAME" {
			return errField("name", "This name already has a CNAME record, which cannot coexist with other records.")
		}
	}
	return nil
}

func withComment(s *pdns.RRSet, comment string, account string) {
	if comment == "" {
		s.Comments = []pdns.Comment{}
		return
	}
	s.Comments = []pdns.Comment{{Content: comment, Account: account, ModifiedAt: time.Now().Unix()}}
}

func (a *App) commentAccount(ctx context.Context) string {
	if act := actorFrom(ctx); act != nil {
		return truncate(act.Label, 40)
	}
	return ""
}

func (a *App) handleCreateRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	if z.Kind == "Slave" {
		a.fail(w, r, errConflict("Records in secondary zones are transferred from the primary server and cannot be edited here."))
		return
	}
	var in recordInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	name, typ, content, ttl, err := a.normalizeRecord(z, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	unlock := lockZone(z.ID)
	defer unlock()
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
	if err := conflictCheck(pz.RRSets, name, typ, nil); err != nil {
		a.fail(w, r, err)
		return
	}
	set := pdns.RRSet{Name: name, Type: typ, TTL: ttl, ChangeType: "REPLACE"}
	if existing := findRRSet(pz.RRSets, name, typ); existing != nil {
		set.Records = append(set.Records, existing.Records...)
		set.Comments = existing.Comments
		for _, rec := range existing.Records {
			if rec.Content == content {
				a.fail(w, r, errConflict("An identical record already exists."))
				return
			}
		}
	}
	if typ == "CNAME" && len(set.Records) > 0 {
		a.fail(w, r, errField("name", "Only one CNAME record can exist at a name."))
		return
	}
	set.Records = append(set.Records, pdns.Record{Content: content, Disabled: in.Disabled})
	if in.Comment != "" || set.Comments == nil {
		withComment(&set, in.Comment, a.commentAccount(ctx))
	}
	if err := c.PatchRRSets(ctx, z.Name, []pdns.RRSet{set}); err != nil {
		a.fail(w, r, err)
		return
	}
	rec := recordDTO{ID: recordID(name, typ, content), Name: name, Type: typ, TTL: ttl, Content: content, Disabled: in.Disabled, Comment: in.Comment}
	a.audit(r, auditEvent{Action: "record.create", ResourceType: "record", ResourceID: rec.ID, ResourceName: name,
		Metadata: map[string]any{"type": typ, "content": content, "ttl": ttl, "disabled": in.Disabled, "zone": z.Name}})
	unlock()
	ptr := a.syncPTR(r, z, in, name, typ, content)
	writeJSON(w, 201, map[string]any{"record": rec, "ptr": ptr})
}

func (a *App) handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	oldName, oldType, oldContent, err := parseRecordID(chi.URLParam(r, "recordID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in recordInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if oldType == "SOA" {
		a.fail(w, r, errBadRequest("Edit the SOA record from zone settings."))
		return
	}
	if oldType == "NS" && oldName == z.Name {
		a.fail(w, r, errBadRequest(errApexNS))
		return
	}
	name, typ, content, ttl, err := a.normalizeRecord(z, in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	unlock := lockZone(z.ID)
	defer unlock()
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
	oldSet := findRRSet(pz.RRSets, oldName, oldType)
	found := false
	var oldRec pdns.Record
	if oldSet != nil {
		for _, rec := range oldSet.Records {
			if rec.Content == oldContent {
				found, oldRec = true, rec
			}
		}
	}
	if !found {
		a.fail(w, r, errCode(409, "stale_record", "This record was changed or deleted by someone else. Refresh and try again."))
		return
	}
	var patches []pdns.RRSet
	if name == oldName && typ == oldType {
		set := pdns.RRSet{Name: name, Type: typ, TTL: ttl, ChangeType: "REPLACE", Comments: oldSet.Comments}
		for _, rec := range oldSet.Records {
			if rec.Content == oldContent {
				set.Records = append(set.Records, pdns.Record{Content: content, Disabled: in.Disabled})
			} else if rec.Content == content {
				continue
			} else {
				set.Records = append(set.Records, rec)
			}
		}
		withComment(&set, in.Comment, a.commentAccount(ctx))
		patches = append(patches, set)
	} else {
		if err := conflictCheck(pz.RRSets, name, typ, oldSet); err != nil {
			a.fail(w, r, err)
			return
		}
		rest := pdns.RRSet{Name: oldName, Type: oldType, TTL: oldSet.TTL, ChangeType: "REPLACE", Comments: oldSet.Comments}
		for _, rec := range oldSet.Records {
			if rec.Content != oldContent {
				rest.Records = append(rest.Records, rec)
			}
		}
		if len(rest.Records) == 0 {
			rest = pdns.RRSet{Name: oldName, Type: oldType, ChangeType: "DELETE", Records: []pdns.Record{}, Comments: []pdns.Comment{}}
		}
		patches = append(patches, rest)
		set := pdns.RRSet{Name: name, Type: typ, TTL: ttl, ChangeType: "REPLACE"}
		if existing := findRRSet(pz.RRSets, name, typ); existing != nil {
			for _, rec := range existing.Records {
				if rec.Content != content {
					set.Records = append(set.Records, rec)
				}
			}
		}
		if typ == "CNAME" && len(set.Records) > 0 {
			a.fail(w, r, errField("name", "Only one CNAME record can exist at a name."))
			return
		}
		set.Records = append(set.Records, pdns.Record{Content: content, Disabled: in.Disabled})
		withComment(&set, in.Comment, a.commentAccount(ctx))
		patches = append(patches, set)
	}
	if err := c.PatchRRSets(ctx, z.Name, patches); err != nil {
		a.fail(w, r, err)
		return
	}
	rec := recordDTO{ID: recordID(name, typ, content), Name: name, Type: typ, TTL: ttl, Content: content, Disabled: in.Disabled, Comment: in.Comment}
	a.audit(r, auditEvent{Action: "record.update", ResourceType: "record", ResourceID: rec.ID, ResourceName: name,
		Metadata: map[string]any{"zone": z.Name,
			"before": map[string]any{"name": oldName, "type": oldType, "content": oldContent, "ttl": oldSet.TTL, "disabled": oldRec.Disabled},
			"after":  map[string]any{"name": name, "type": typ, "content": content, "ttl": ttl, "disabled": in.Disabled}}})
	unlock()
	ptr := a.syncPTR(r, z, in, name, typ, content)
	writeJSON(w, 200, map[string]any{"record": rec, "ptr": ptr})
}

func (a *App) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	n, err := a.deleteRecords(r, z, []string{chi.URLParam(r, "recordID")})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if n == 0 {
		a.fail(w, r, errNotFound("Record"))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleBulkDeleteRecords(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IDs []string `json:"ids"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 5000 {
		a.fail(w, r, errBadRequest("Select between 1 and 5000 records."))
		return
	}
	n, err := a.deleteRecords(r, zoneFrom(r.Context()), in.IDs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

func (a *App) deleteRecords(r *http.Request, z *store.Zone, ids []string) (int, error) {
	ctx := r.Context()
	type key struct{ name, typ string }
	remove := map[key]map[string]bool{}
	for _, id := range ids {
		name, typ, content, err := parseRecordID(id)
		if err != nil {
			return 0, err
		}
		if typ == "SOA" {
			return 0, errBadRequest("The SOA record cannot be deleted.")
		}
		if typ == "NS" && name == z.Name {
			return 0, errBadRequest(errApexNS)
		}
		k := key{name, typ}
		if remove[k] == nil {
			remove[k] = map[string]bool{}
		}
		remove[k][content] = true
	}
	unlock := lockZone(z.ID)
	defer unlock()
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		return 0, err
	}
	pz, err := c.GetZone(ctx, z.Name, true)
	if err != nil {
		return 0, err
	}
	var patches []pdns.RRSet
	var removed []map[string]any
	for k, contents := range remove {
		set := findRRSet(pz.RRSets, k.name, k.typ)
		if set == nil {
			continue
		}
		next := pdns.RRSet{Name: k.name, Type: k.typ, TTL: set.TTL, ChangeType: "REPLACE", Comments: set.Comments}
		for _, rec := range set.Records {
			if contents[rec.Content] {
				removed = append(removed, map[string]any{"name": k.name, "type": k.typ, "content": rec.Content, "ttl": set.TTL})
				continue
			}
			next.Records = append(next.Records, rec)
		}
		if len(next.Records) == len(set.Records) {
			continue
		}
		if len(next.Records) == 0 {
			if k.typ == "NS" && k.name == z.Name {
				return 0, errBadRequest("The zone must keep at least one apex NS record.")
			}
			next = pdns.RRSet{Name: k.name, Type: k.typ, ChangeType: "DELETE", Records: []pdns.Record{}, Comments: []pdns.Comment{}}
		}
		patches = append(patches, next)
	}
	if len(patches) == 0 {
		return 0, nil
	}
	if err := c.PatchRRSets(ctx, z.Name, patches); err != nil {
		return 0, err
	}
	if len(removed) == 1 {
		rm := removed[0]
		a.audit(r, auditEvent{Action: "record.delete", ResourceType: "record", ResourceName: rm["name"].(string),
			Metadata: map[string]any{"zone": z.Name, "type": rm["type"], "content": rm["content"], "ttl": rm["ttl"]}})
	} else {
		a.audit(r, auditEvent{Action: "record.bulk_delete", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
			Metadata: map[string]any{"count": len(removed), "records": capList(removed, 200)}})
	}
	return len(removed), nil
}

func capList[T any](in []T, n int) []T {
	if len(in) > n {
		return in[:n]
	}
	return in
}

// ---- Import / export ----

func (a *App) handleImportPreview(w http.ResponseWriter, r *http.Request) {
	z := zoneFrom(r.Context())
	var in struct {
		Text string `json:"text"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	recs, warnings, err := dnsutil.ParseZoneFile(in.Text, z.Name, orInt(a.Settings(r.Context()).DefaultTTL, 3600))
	if err != nil {
		a.fail(w, r, errField("text", err.Error()))
		return
	}
	if recs == nil {
		recs = []dnsutil.ParsedRR{}
	}
	if warnings == nil {
		warnings = []string{}
	}
	writeJSON(w, 200, map[string]any{"records": recs, "warnings": warnings})
}

func (a *App) handleImportRecords(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	if z.Kind == "Slave" {
		a.fail(w, r, errConflict("Records cannot be imported into a secondary zone."))
		return
	}
	var in struct {
		Text    string             `json:"text"`
		Records []dnsutil.ParsedRR `json:"records"`
		Mode    string             `json:"mode"` // merge | replace
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	defTTL := orInt(a.Settings(ctx).DefaultTTL, 3600)
	recs := in.Records
	if in.Text != "" {
		var err error
		recs, _, err = dnsutil.ParseZoneFile(in.Text, z.Name, defTTL)
		if err != nil {
			a.fail(w, r, errField("text", err.Error()))
			return
		}
	}
	sets, err := a.buildImportRRSets(z.Name, recs, defTTL, true)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if len(sets) == 0 {
		a.fail(w, r, errField("text", "No importable records were found."))
		return
	}
	unlock := lockZone(z.ID)
	defer unlock()
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
	patches, added := mergeRRSets(pz, sets, in.Mode == "replace", z.Name)
	if err := c.PatchRRSets(ctx, z.Name, patches); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "zone.import", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"added": added, "mode": orStr(in.Mode, "merge"), "rrsets": len(sets)}})
	writeJSON(w, 200, map[string]any{"added": added, "rrsets": len(sets)})
}

func (a *App) handleExportZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	text, err := c.Export(ctx, z.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	header := fmt.Sprintf(";; Zone file for %s\n;; Exported %s by %s\n$ORIGIN %s\n", strings.TrimSuffix(z.Name, "."),
		time.Now().UTC().Format(time.RFC3339), actorFrom(ctx).Label, z.Name)
	a.audit(r, auditEvent{Action: "zone.export", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zone"`, strings.TrimSuffix(z.Name, ".")))
	_, _ = w.Write([]byte(header + text))
}

// ---- Delete / activate / move ----

func (a *App) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Confirm)), ".") != strings.TrimSuffix(z.Name, ".") {
		a.fail(w, r, errField("confirm", "Type the domain name to confirm"))
		return
	}
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := c.DeleteZone(ctx, z.Name); err != nil && !pdns.IsNotFound(err) {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.DeleteZone(ctx, z.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "zone.delete", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleCheckNameservers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	if !a.limiter.allow("nscheck:"+z.ID.String(), 6, 6) {
		a.fail(w, r, errCode(429, "rate_limited", "Nameserver checks are limited. Try again in a minute."))
		return
	}
	updated, err := a.CheckZoneDelegation(ctx, z)
	if err != nil {
		a.fail(w, r, errCode(502, "lookup_failed", "DNS lookup failed: "+err.Error()))
		return
	}
	if updated.Status != z.Status {
		a.audit(r, auditEvent{Action: "zone.status_change", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
			Metadata: map[string]any{"from": z.Status, "to": updated.Status, "observed": updated.ObservedNameservers}})
	}
	writeJSON(w, 200, updated)
}

// CheckZoneDelegation resolves the current delegation and updates the zone status.
func (a *App) CheckZoneDelegation(ctx context.Context, z *store.Zone) (*store.Zone, error) {
	res := &dnsutil.Resolver{Addr: a.Cfg.DNSResolver}
	observed, err := res.LookupNS(ctx, z.Name)
	if err != nil {
		return nil, err
	}
	status := z.Status
	matches := dnsutil.DelegationMatches(z.AssignedNameservers, observed)
	switch {
	case matches:
		status = "active"
	case z.Status == "active" && len(observed) > 0 && z.ActivatedAt != nil:
		// Previously active zones whose delegation moved elsewhere.
		status = "moved"
	case z.Status == "moved" && len(observed) == 0:
		status = "moved"
	case z.Status != "active":
		status = "pending"
	}
	if err := a.Store.UpdateZoneNSCheck(ctx, z.ID, status, observed); err != nil {
		return nil, err
	}
	return a.Store.ZoneByID(ctx, z.OrgID, z.ID)
}

func (a *App) handleActivateZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	if err := a.Store.UpdateZoneNSCheck(ctx, z.ID, "active", z.ObservedNameservers); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "zone.force_activate", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name,
		Metadata: map[string]any{"from": z.Status}})
	updated, _ := a.Store.ZoneByID(ctx, z.OrgID, z.ID)
	writeJSON(w, 200, updated)
}

func (a *App) handleMoveZone(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	act := actorFrom(ctx)
	var in struct {
		TargetOrgID uuid.UUID `json:"target_org_id"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.TargetOrgID == z.OrgID {
		a.fail(w, r, errField("target_org_id", "The zone already belongs to this organization"))
		return
	}
	target, err := a.Store.OrgByID(ctx, in.TargetOrgID)
	if err != nil {
		a.fail(w, r, errField("target_org_id", "Organization not found"))
		return
	}
	switch {
	case act.Type == "api_token":
		// The token needs zone or organization admin access in the destination too, which only a
		// global token can have.
		if acc, err := a.tokenAccess(r, act.Token, target); err != nil || (acc.Role != "admin" && acc.Role != "org_admin") {
			a.fail(w, r, errForbidden("This token needs Zone admin or Organization admin access to the destination organization."))
			return
		}
	case act.Type != "user":
		a.fail(w, r, errForbidden("Zones can only be moved by users and API tokens."))
		return
	case !act.User.IsSuperadmin:
		m, err := a.Store.Membership(ctx, target.ID, act.User.ID)
		if err != nil || (m.Role != "owner" && m.Role != "admin") {
			a.fail(w, r, errForbidden("You must be an owner or administrator of the destination organization."))
			return
		}
	}
	if err := a.Store.MoveZone(ctx, z.ID, target.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	meta := map[string]any{"from_org": orgFrom(ctx).Name, "to_org": target.Name}
	a.audit(r, auditEvent{Action: "zone.move_out", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name, Metadata: meta})
	a.audit(r, auditEvent{OrgID: &target.ID, Action: "zone.move_in", ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name, Metadata: meta})
	writeJSON(w, 200, map[string]any{"ok": true, "org_id": target.ID})
}

// ---- Zone actions ----

func (a *App) handleZoneAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	z := zoneFrom(ctx)
	action := chi.URLParam(r, "action")
	c, err := a.PDNSForZone(ctx, z)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	switch action {
	case "notify":
		if z.Kind == "Native" {
			a.fail(w, r, errBadRequest("NOTIFY is only sent for primary zones. Change the zone type to Primary first."))
			return
		}
		err = c.Notify(ctx, z.Name)
	case "rectify":
		err = c.Rectify(ctx, z.Name)
	case "axfr-retrieve":
		if z.Kind != "Slave" {
			a.fail(w, r, errBadRequest("Only secondary zones can retrieve a transfer."))
			return
		}
		err = c.AXFRRetrieve(ctx, z.Name)
	case "flush-cache":
		err = c.FlushCache(ctx, z.Name)
	default:
		a.fail(w, r, errNotFound("Action"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "zone." + strings.ReplaceAll(action, "-", "_"), ResourceType: "zone", ResourceID: z.ID.String(), ResourceName: z.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Search ----

func (a *App) handleSearch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	acc := accessFrom(ctx)
	q := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("q")))
	if len(q) < 2 {
		writeJSON(w, 200, map[string]any{"zones": []store.Zone{}, "records": []any{}})
		return
	}
	zones, err := a.Store.ListZones(ctx, org.ID, acc.ZoneIDs)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	byName := map[string]store.Zone{}
	servers := map[uuid.UUID]bool{}
	matched := []store.Zone{}
	for _, z := range zones {
		byName[z.Name] = z
		servers[z.PDNSServerID] = true
		if strings.Contains(z.Name, q) && len(matched) < 20 {
			matched = append(matched, z)
		}
	}
	type hit struct {
		ZoneID   uuid.UUID `json:"zone_id"`
		ZoneName string    `json:"zone_name"`
		Name     string    `json:"name"`
		Type     string    `json:"type"`
		Content  string    `json:"content"`
	}
	hits := []hit{}
	for sid := range servers {
		srv, err := a.Store.ServerByID(ctx, sid)
		if err != nil {
			continue
		}
		c, err := a.PDNS(srv)
		if err != nil {
			continue
		}
		res, err := c.Search(ctx, "*"+q+"*", 200)
		if err != nil {
			continue
		}
		for _, s := range res {
			if s.ObjectType != "record" {
				continue
			}
			z, ok := byName[s.Zone]
			if !ok {
				continue
			}
			hits = append(hits, hit{ZoneID: z.ID, ZoneName: z.Name, Name: s.Name, Type: s.Type, Content: s.Content})
			if len(hits) >= 50 {
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{"zones": matched, "records": hits})
}
