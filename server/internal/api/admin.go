package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/mail"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// ---- Overview ----

func (a *App) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := a.Store.ListUsers(ctx, "")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	orgs, err := a.Store.ListOrgs(ctx, "")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	servers, err := a.Store.ListServers(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	statuses, _ := a.Store.ZoneCountsByStatus(ctx, nil)
	zones := 0
	for _, n := range statuses {
		zones += n
	}
	mfa := 0
	for _, u := range users {
		if u.TOTPEnabled {
			mfa++
		}
	}
	activity, _ := a.Store.AuditActivity(ctx, nil, nil, 30)
	recent, _ := a.Store.ListAudit(ctx, store.AuditFilter{Limit: 10})
	healthy := 0
	for _, s := range servers {
		if s.LastStatus == "healthy" {
			healthy++
		}
	}
	writeJSON(w, 200, map[string]any{
		"user_count": len(users), "mfa_user_count": mfa, "org_count": len(orgs), "zone_count": zones, "zone_status_counts": statuses,
		"server_count": len(servers), "healthy_server_count": healthy, "servers": servers, "activity": activity, "recent_activity": recent,
		"version": Version, "email_enabled": a.Mailer.Enabled(ctx),
	})
}

// ---- Servers ----

func (a *App) handleListServers(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListServers(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

type serverInput struct {
	Name        string `json:"name"`
	APIURL      string `json:"api_url"`
	APIKey      string `json:"api_key"`
	ServerID    string `json:"server_id"`
	Description string `json:"description"`
	IsDefault   bool   `json:"is_default"`
	Enabled     bool   `json:"enabled"`
}

func (a *App) validateServer(in *serverInput, requireKey bool) error {
	fields := map[string]string{}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fields["name"] = "Enter a name"
	}
	in.APIURL = strings.TrimRight(strings.TrimSpace(in.APIURL), "/")
	in.APIURL = strings.TrimSuffix(in.APIURL, "/api/v1")
	if u, err := url.Parse(in.APIURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fields["api_url"] = "Enter the PowerDNS API base URL, for example http://pdns:8081"
	}
	if requireKey && in.APIKey == "" {
		fields["api_key"] = "Enter the API key"
	}
	if in.ServerID == "" {
		in.ServerID = "localhost"
	}
	if len(fields) > 0 {
		return errValidation(fields)
	}
	return nil
}

func (a *App) handleTestServer(w http.ResponseWriter, r *http.Request) {
	var in serverInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	key := in.APIKey
	if key == "" {
		if id, err := uuid.Parse(r.URL.Query().Get("id")); err == nil {
			if srv, err := a.Store.ServerByID(r.Context(), id); err == nil {
				key, _ = a.Box.Open(srv.APIKeyEnc)
			}
		}
	}
	if err := a.validateServer(&in, false); err != nil {
		a.fail(w, r, err)
		return
	}
	info, err := pdns.New(in.APIURL, key, in.ServerID).Server(r.Context())
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "version": info.Version, "daemon_type": info.DaemonType})
}

func (a *App) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in serverInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.validateServer(&in, true); err != nil {
		a.fail(w, r, err)
		return
	}
	info, err := pdns.New(in.APIURL, in.APIKey, in.ServerID).Server(ctx)
	if err != nil {
		a.fail(w, r, errField("api_url", "Could not connect: "+err.Error()))
		return
	}
	enc, err := a.Box.Seal(in.APIKey)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	srv, err := a.Store.CreateServer(ctx, store.ServerInput{Name: in.Name, APIURL: in.APIURL, APIKeyEnc: enc, ServerID: in.ServerID,
		Description: in.Description, IsDefault: in.IsDefault, Enabled: true})
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("name", "A server with this name already exists"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	_ = a.Store.SetServerStatus(ctx, srv.ID, "healthy", info.Version)
	a.audit(r, auditEvent{Action: "admin.server_create", ResourceType: "pdns_server", ResourceID: srv.ID.String(), ResourceName: srv.Name,
		Metadata: map[string]any{"api_url": srv.APIURL, "default": srv.IsDefault}})
	srv, _ = a.Store.ServerByID(ctx, srv.ID)
	writeJSON(w, 201, srv)
}

func (a *App) loadServer(r *http.Request) (*store.PDNSServer, error) {
	id, err := uuid.Parse(chi.URLParam(r, "serverID"))
	if err != nil {
		return nil, errNotFound("Server")
	}
	return a.Store.ServerByID(r.Context(), id)
}

func (a *App) handleUpdateServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in serverInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.validateServer(&in, false); err != nil {
		a.fail(w, r, err)
		return
	}
	enc := srv.APIKeyEnc
	key, _ := a.Box.Open(srv.APIKeyEnc)
	if in.APIKey != "" {
		key = in.APIKey
		if enc, err = a.Box.Seal(in.APIKey); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	status, version := "unreachable", ""
	if info, err := pdns.New(in.APIURL, key, in.ServerID).Server(ctx); err == nil {
		status, version = "healthy", info.Version
	} else if in.Enabled {
		a.fail(w, r, errField("api_url", "Could not connect: "+err.Error()))
		return
	}
	if err := a.Store.UpdateServer(ctx, srv.ID, store.ServerInput{Name: in.Name, APIURL: in.APIURL, APIKeyEnc: enc, ServerID: in.ServerID,
		Description: in.Description, IsDefault: in.IsDefault, Enabled: in.Enabled}); err != nil {
		a.fail(w, r, err)
		return
	}
	_ = a.Store.SetServerStatus(ctx, srv.ID, status, version)
	a.audit(r, auditEvent{Action: "admin.server_update", ResourceType: "pdns_server", ResourceID: srv.ID.String(), ResourceName: in.Name,
		Metadata: map[string]any{"api_url": in.APIURL, "default": in.IsDefault, "enabled": in.Enabled, "key_rotated": in.APIKey != ""}})
	srv, _ = a.Store.ServerByID(ctx, srv.ID)
	writeJSON(w, 200, srv)
}

func (a *App) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if srv.ZoneCount > 0 {
		a.fail(w, r, errConflict("This server still hosts zones. Delete or migrate them first."))
		return
	}
	if err := a.Store.DeleteServer(r.Context(), srv.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.server_delete", ResourceType: "pdns_server", ResourceID: srv.ID.String(), ResourceName: srv.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	info, err := c.Server(ctx)
	if err != nil {
		_ = a.Store.SetServerStatus(ctx, srv.ID, "unreachable", "")
		writeJSON(w, 200, map[string]any{"reachable": false, "error": err.Error()})
		return
	}
	_ = a.Store.SetServerStatus(ctx, srv.ID, "healthy", info.Version)
	stats, _ := c.Statistics(ctx)
	wanted := map[string]bool{"uptime": true, "udp-queries": true, "tcp-queries": true, "udp-answers": true, "tcp-answers": true,
		"packetcache-hit": true, "packetcache-miss": true, "query-cache-hit": true, "query-cache-miss": true, "servfail-packets": true,
		"latency": true, "qsize-q": true, "corrupt-packets": true, "timedout-packets": true, "rd-queries": true, "recursing-questions": true,
		"udp4-queries": true, "udp6-queries": true, "security-status": true, "signatures": true, "real-memory-usage": true,
		"incoming-notifications": true, "overload-drops": true, "deferred-cache-inserts": true, "key-cache-size": true}
	out := map[string]any{}
	for _, s := range stats {
		if s.Type == "StatisticItem" && wanted[s.Name] {
			var v string
			if json.Unmarshal(s.Value, &v) == nil {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil {
					out[s.Name] = n
				} else {
					out[s.Name] = v
				}
			}
		}
	}
	zones, _ := c.ListZones(ctx)
	writeJSON(w, 200, map[string]any{"reachable": true, "info": info, "statistics": out, "pdns_zone_count": len(zones)})
}

// handleServerConfig returns the PowerDNS running configuration (read-only).
func (a *App) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cfg, err := c.Config(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sort.Slice(cfg, func(i, j int) bool { return cfg[i].Name < cfg[j].Name })
	for i := range cfg {
		// Never expose secrets through the dashboard.
		n := cfg[i].Name
		if strings.Contains(n, "password") || strings.Contains(n, "api-key") || strings.Contains(n, "secret") {
			cfg[i].Value = "(hidden)"
		}
	}
	writeJSON(w, 200, cfg)
}

// handleUnmanagedZones lists zones on the server that Flare does not manage yet.
func (a *App) handleUnmanagedZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	zones, err := c.ListZones(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	managed, err := a.Store.ListAllZones(ctx, "")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	known := map[string]bool{}
	for _, z := range managed {
		known[z.Name] = true
	}
	type item struct {
		Name    string `json:"name"`
		Kind    string `json:"kind"`
		Serial  int64  `json:"serial"`
		Account string `json:"account"`
	}
	out := []item{}
	for _, z := range zones {
		if !known[z.Name] {
			out = append(out, item{Name: z.Name, Kind: z.Kind, Serial: z.Serial, Account: z.Account})
		}
	}
	writeJSON(w, 200, out)
}

func (a *App) handleAdoptZones(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in struct {
		OrgID           uuid.UUID  `json:"org_id"`
		Zones           []string   `json:"zones"`
		NameserverSetID *uuid.UUID `json:"nameserver_set_id"`
		MarkActive      bool       `json:"mark_active"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	org, err := a.Store.OrgByID(ctx, in.OrgID)
	if err != nil {
		a.fail(w, r, errField("org_id", "Choose an organization"))
		return
	}
	var nsSet *store.NameserverSet
	if in.NameserverSetID != nil {
		nsSet, _ = a.Store.NameserverSetByID(ctx, *in.NameserverSetID)
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	adopted := 0
	var failures []string
	act := actorFrom(ctx)
	for _, name := range in.Zones {
		pz, err := c.GetZone(ctx, name, true)
		if err != nil {
			failures = append(failures, name+": "+err.Error())
			continue
		}
		var ns []string
		var setID *uuid.UUID
		if nsSet != nil {
			ns, setID = nsSet.Nameservers, &nsSet.ID
		} else if s := findRRSet(pz.RRSets, pz.Name, "NS"); s != nil {
			for _, rec := range s.Records {
				ns = append(ns, rec.Content)
			}
		}
		if ns == nil {
			ns = []string{}
		}
		status := "pending"
		if in.MarkActive {
			status = "active"
		}
		z, err := a.Store.CreateZone(ctx, store.NewZone{OrgID: org.ID, PDNSServerID: srv.ID, NameserverSetID: setID, Name: pz.Name,
			Kind: pz.Kind, Status: status, Nameservers: ns, CreatedBy: &act.User.ID})
		if err != nil {
			failures = append(failures, name+": "+err.Error())
			continue
		}
		adopted++
		a.audit(r, auditEvent{OrgID: &org.ID, ZoneID: &z.ID, Action: "zone.adopt", ResourceType: "zone", ResourceID: z.ID.String(),
			ResourceName: z.Name, Metadata: map[string]any{"server": srv.Name}})
	}
	if failures == nil {
		failures = []string{}
	}
	writeJSON(w, 200, map[string]any{"adopted": adopted, "failures": failures})
}

// ---- TSIG keys ----

func (a *App) handleListTSIG(w http.ResponseWriter, r *http.Request) {
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	keys, err := c.TSIGKeys(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if keys == nil {
		keys = []pdns.TSIGKey{}
	}
	writeJSON(w, 200, keys)
}

func (a *App) handleCreateTSIG(w http.ResponseWriter, r *http.Request) {
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in pdns.TSIGKey
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if in.Name == "" {
		a.fail(w, r, errField("name", "Enter a key name"))
		return
	}
	if in.Algorithm == "" {
		in.Algorithm = "hmac-sha256"
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	k, err := c.CreateTSIGKey(r.Context(), pdns.TSIGKey{Name: in.Name, Algorithm: in.Algorithm, Key: in.Key})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.tsig_create", ResourceType: "tsig_key", ResourceID: k.ID, ResourceName: k.Name,
		Metadata: map[string]any{"server": srv.Name, "algorithm": k.Algorithm}})
	writeJSON(w, 201, k)
}

func (a *App) handleDeleteTSIG(w http.ResponseWriter, r *http.Request) {
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id := chi.URLParam(r, "keyID")
	if err := c.DeleteTSIGKey(r.Context(), id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.tsig_delete", ResourceType: "tsig_key", ResourceID: id, ResourceName: id, Metadata: map[string]any{"server": srv.Name}})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleRevealTSIG(w http.ResponseWriter, r *http.Request) {
	srv, err := a.loadServer(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	c, err := a.PDNS(srv)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	id := chi.URLParam(r, "keyID")
	k, err := c.TSIGKey(r.Context(), id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.tsig_reveal", ResourceType: "tsig_key", ResourceID: id, ResourceName: k.Name, Metadata: map[string]any{"server": srv.Name}})
	writeJSON(w, 200, k)
}

// ---- Nameserver sets ----

func (a *App) handleListNameserverSets(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListNameserverSets(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleSaveNameserverSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var id *uuid.UUID
	var previous *store.NameserverSet
	if p := chi.URLParam(r, "setID"); p != "" {
		parsed, err := uuid.Parse(p)
		if err != nil {
			a.fail(w, r, errNotFound("Nameserver set"))
			return
		}
		if previous, err = a.Store.NameserverSetByID(ctx, parsed); err != nil {
			a.fail(w, r, err)
			return
		}
		id = &parsed
	}
	var in struct {
		Name        string   `json:"name"`
		Nameservers []string `json:"nameservers"`
		Hostmaster  string   `json:"hostmaster"`
		IsDefault   bool     `json:"is_default"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	fields := map[string]string{}
	if strings.TrimSpace(in.Name) == "" {
		fields["name"] = "Enter a name"
	}
	ns, err := normalizeNameservers(in.Nameservers)
	if err != nil {
		fields["nameservers"] = err.Error()
	}
	if in.Hostmaster != "" {
		if _, err := normalizeEmail(in.Hostmaster); err != nil {
			fields["hostmaster"] = "Enter a valid email address"
		}
	}
	if len(fields) > 0 {
		a.fail(w, r, errValidation(fields))
		return
	}
	set, err := a.Store.SaveNameserverSet(ctx, id, strings.TrimSpace(in.Name), ns, strings.TrimSpace(in.Hostmaster), in.IsDefault)
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("name", "A nameserver set with this name already exists"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	action := "admin.nameserver_set_update"
	status := 200
	if id == nil {
		action, status = "admin.nameserver_set_create", 201
	}
	result := map[string]any{"zones_updated": 0, "zones_failed": []string{}}
	if previous != nil && (!slices.Equal(previous.Nameservers, set.Nameservers) || previous.Hostmaster != set.Hostmaster) {
		updated, failed := a.propagateNameserverSet(r, set, previous)
		result = map[string]any{"zones_updated": updated, "zones_failed": failed}
	}
	a.audit(r, auditEvent{Action: action, ResourceType: "nameserver_set", ResourceID: set.ID.String(), ResourceName: set.Name,
		Metadata: map[string]any{"nameservers": ns, "default": in.IsDefault, "zones_updated": result["zones_updated"], "zones_failed": result["zones_failed"]}})
	writeJSON(w, status, map[string]any{"set": set, "zones_updated": result["zones_updated"], "zones_failed": result["zones_failed"]})
}

// propagateNameserverSet re-applies an edited nameserver set to every zone that uses it, so apex NS
// and SOA records follow the administrator's change. Each zone change is audited in its organization.
func (a *App) propagateNameserverSet(r *http.Request, set, previous *store.NameserverSet) (int, []string) {
	// Finish even if the administrator closes the page halfway through.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Minute)
	defer cancel()
	zones, err := a.Store.ZonesByNameserverSet(ctx, set.ID)
	if err != nil {
		a.Log.Error("load zones for nameserver set", "set", set.Name, "err", err)
		return 0, []string{"could not load zones: " + err.Error()}
	}
	var (
		mu      sync.Mutex
		updated int
		failed  = []string{}
		wg      sync.WaitGroup
		work    = make(chan *store.Zone)
	)
	for range min(8, len(zones)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for z := range work {
				err := a.applyNameservers(ctx, z, set)
				mu.Lock()
				if err != nil {
					failed = append(failed, strings.TrimSuffix(z.Name, ".")+": "+err.Error())
					a.Log.Warn("apply nameserver set", "zone", z.Name, "err", err)
				} else {
					updated++
				}
				mu.Unlock()
				if err == nil {
					a.audit(r.WithContext(ctx), auditEvent{OrgID: &z.OrgID, ZoneID: &z.ID, Action: "zone.nameservers_change", ResourceType: "zone",
						ResourceID: z.ID.String(), ResourceName: z.Name,
						Metadata: map[string]any{"from": previous.Nameservers, "to": set.Nameservers, "set": set.Name, "via": "nameserver_set_update"}})
				}
			}
		}()
	}
	for i := range zones {
		work <- &zones[i]
	}
	close(work)
	wg.Wait()
	slices.Sort(failed)
	return updated, failed
}

func (a *App) handleDeleteNameserverSet(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "setID"))
	if err != nil {
		a.fail(w, r, errNotFound("Nameserver set"))
		return
	}
	set, err := a.Store.NameserverSetByID(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if set.IsDefault {
		a.fail(w, r, errConflict("Choose another default nameserver set before deleting this one."))
		return
	}
	if err := a.Store.DeleteNameserverSet(ctx, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.nameserver_set_delete", ResourceType: "nameserver_set", ResourceID: id.String(), ResourceName: set.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Settings ----

func (a *App) settingsView(s store.InstanceSettings) map[string]any {
	raw, _ := json.Marshal(s)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if smtp, ok := out["smtp"].(map[string]any); ok {
		smtp["password_set"] = s.SMTP.PasswordEnc != ""
		delete(smtp, "password_enc")
	}
	if l, ok := out["ldap"].(map[string]any); ok {
		l["bind_password_set"] = s.LDAP.BindPasswordEnc != ""
		delete(l, "bind_password_enc")
	}
	out["env_smtp_configured"] = a.Cfg.SMTPHost != ""
	return out
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.settingsView(a.Settings(r.Context())))
}

func (a *App) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cur := a.Settings(ctx)
	var in struct {
		InstanceName       *string            `json:"instance_name"`
		SignupEnabled      *bool              `json:"signup_enabled"`
		AllowOrgCreation   *bool              `json:"allow_org_creation"`
		DefaultMaxZones    *int               `json:"default_max_zones"`
		RequireMFA         *bool              `json:"require_mfa"`
		PasswordMinLength  *int               `json:"password_min_length"`
		AuditRetentionDays *int               `json:"audit_retention_days"`
		SessionTTLHours    *int               `json:"session_ttl_hours"`
		SupportEmail       *string            `json:"support_email"`
		DefaultTTL         *int               `json:"default_ttl"`
		SOA                *store.SOADefaults `json:"soa"`
		DefaultDNSSEC      *bool              `json:"default_dnssec"`
		SOAEditAPI         *string            `json:"soa_edit_api"`
		AnnouncementBanner *string            `json:"announcement_banner"`
		ForwardRecordTypes *[]string          `json:"forward_record_types"`
		ReverseRecordTypes *[]string          `json:"reverse_record_types"`
		AutoPTR            *bool              `json:"auto_ptr"`
		DynDNSTTL          *int               `json:"dyndns_ttl"`
		LDAP               *struct {
			store.LDAPConfig
			BindPassword *string `json:"bind_password"`
		} `json:"ldap"`
		SMTP *struct {
			Host     string  `json:"host"`
			Port     int     `json:"port"`
			Username string  `json:"username"`
			Password *string `json:"password"`
			From     string  `json:"from"`
			TLS      string  `json:"tls"`
		} `json:"smtp"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	fields := map[string]string{}
	next := cur
	if in.InstanceName != nil {
		if strings.TrimSpace(*in.InstanceName) == "" {
			fields["instance_name"] = "Enter a name"
		}
		next.InstanceName = strings.TrimSpace(*in.InstanceName)
	}
	setBool := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	setBool(&next.SignupEnabled, in.SignupEnabled)
	setBool(&next.AllowOrgCreation, in.AllowOrgCreation)
	setBool(&next.RequireMFA, in.RequireMFA)
	setBool(&next.DefaultDNSSEC, in.DefaultDNSSEC)
	rangeInt := func(name string, dst *int, v *int, min, max int) {
		if v == nil {
			return
		}
		if *v < min || *v > max {
			fields[name] = "Must be between " + strconv.Itoa(min) + " and " + strconv.Itoa(max)
		}
		*dst = *v
	}
	rangeInt("default_max_zones", &next.DefaultMaxZones, in.DefaultMaxZones, 0, 1000000)
	rangeInt("password_min_length", &next.PasswordMinLength, in.PasswordMinLength, 8, 128)
	rangeInt("audit_retention_days", &next.AuditRetentionDays, in.AuditRetentionDays, 0, 3650)
	rangeInt("session_ttl_hours", &next.SessionTTLHours, in.SessionTTLHours, 1, 24*90)
	rangeInt("default_ttl", &next.DefaultTTL, in.DefaultTTL, 30, 86400)
	if in.SupportEmail != nil {
		if *in.SupportEmail != "" {
			if _, err := normalizeEmail(*in.SupportEmail); err != nil {
				fields["support_email"] = "Enter a valid email address"
			}
		}
		next.SupportEmail = strings.TrimSpace(*in.SupportEmail)
	}
	if in.SOA != nil {
		next.SOA = *in.SOA
		if in.SOA.Refresh < 60 || in.SOA.Retry < 60 || in.SOA.Expire < 3600 || in.SOA.Minimum < 30 || in.SOA.TTL < 30 {
			fields["soa"] = "SOA timers are below the allowed minimums"
		}
	}
	if in.SOAEditAPI != nil {
		if !soaEditValues[*in.SOAEditAPI] {
			fields["soa_edit_api"] = "Unsupported value"
		}
		next.SOAEditAPI = *in.SOAEditAPI
	}
	if in.AnnouncementBanner != nil {
		next.AnnouncementBanner = truncate(strings.TrimSpace(*in.AnnouncementBanner), 500)
	}
	for _, p := range []struct {
		dst   *[]string
		v     *[]string
		field string
	}{{&next.ForwardRecordTypes, in.ForwardRecordTypes, "forward_record_types"}, {&next.ReverseRecordTypes, in.ReverseRecordTypes, "reverse_record_types"}} {
		if p.v == nil {
			continue
		}
		list := []string{}
		for _, t := range cleanList(*p.v) {
			t = strings.ToUpper(t)
			if !dnsutil.IsSupportedType(t) {
				fields[p.field] = "Unknown record type " + t
			}
			list = append(list, t)
		}
		*p.dst = list
	}
	setBool(&next.AutoPTR, in.AutoPTR)
	rangeInt("dyndns_ttl", &next.DynDNSTTL, in.DynDNSTTL, 30, 86400)
	if in.LDAP != nil {
		l := in.LDAP.LDAPConfig
		l.BindPasswordEnc = cur.LDAP.BindPasswordEnc
		if in.LDAP.BindPassword != nil {
			if *in.LDAP.BindPassword == "" {
				l.BindPasswordEnc = ""
			} else {
				enc, err := a.Box.Seal(*in.LDAP.BindPassword)
				if err != nil {
					a.fail(w, r, err)
					return
				}
				l.BindPasswordEnc = enc
			}
		}
		l.URL = strings.TrimSpace(l.URL)
		if l.Enabled {
			if !strings.HasPrefix(l.URL, "ldap://") && !strings.HasPrefix(l.URL, "ldaps://") {
				fields["ldap.url"] = "Enter an ldap:// or ldaps:// URL"
			}
			if strings.TrimSpace(l.BaseDN) == "" {
				fields["ldap.base_dn"] = "Enter the search base DN"
			}
			if !strings.Contains(l.UserFilter, "{username}") {
				fields["ldap.user_filter"] = "The user filter must contain {username}"
			}
		}
		if l.DefaultRole != "" && (!validRoles[l.DefaultRole] || l.DefaultRole == "owner") {
			fields["ldap.default_role"] = "Choose admin, editor, viewer or auditor"
		}
		if l.DefaultOrgID != nil {
			if _, err := a.Store.OrgByID(ctx, *l.DefaultOrgID); err != nil {
				fields["ldap.default_org_id"] = "Organization not found"
			}
		}
		if l.GroupRoles == nil {
			l.GroupRoles = []store.RoleMapping{}
		}
		next.LDAP = l
	}
	if in.SMTP != nil {
		next.SMTP.Host = strings.TrimSpace(in.SMTP.Host)
		next.SMTP.Port = in.SMTP.Port
		next.SMTP.Username = in.SMTP.Username
		next.SMTP.From = strings.TrimSpace(in.SMTP.From)
		next.SMTP.TLS = in.SMTP.TLS
		if next.SMTP.TLS == "" {
			next.SMTP.TLS = "starttls"
		}
		if in.SMTP.Password != nil {
			if *in.SMTP.Password == "" {
				next.SMTP.PasswordEnc = ""
			} else {
				enc, err := a.Box.Seal(*in.SMTP.Password)
				if err != nil {
					a.fail(w, r, err)
					return
				}
				next.SMTP.PasswordEnc = enc
			}
		}
		if next.SMTP.Host != "" && (next.SMTP.Port <= 0 || next.SMTP.From == "") {
			fields["smtp"] = "SMTP needs a port and a from address"
		}
	}
	if len(fields) > 0 {
		a.fail(w, r, errValidation(fields))
		return
	}
	if err := a.SaveSettings(ctx, next); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.settings_update", ResourceType: "instance", ResourceName: next.InstanceName, Metadata: settingsDiff(cur, next)})
	writeJSON(w, 200, a.settingsView(next))
}

func settingsDiff(before, after store.InstanceSettings) map[string]any {
	b, _ := json.Marshal(before)
	c, _ := json.Marshal(after)
	var bm, am map[string]any
	_ = json.Unmarshal(b, &bm)
	_ = json.Unmarshal(c, &am)
	out := map[string]any{}
	for k, v := range am {
		if k == "smtp" || k == "ldap" {
			bv, _ := json.Marshal(bm[k])
			av, _ := json.Marshal(v)
			if string(bv) != string(av) {
				out[k] = "changed"
			}
			continue
		}
		bv, _ := json.Marshal(bm[k])
		av, _ := json.Marshal(v)
		if string(bv) != string(av) {
			out[k] = map[string]any{"from": bm[k], "to": v}
		}
	}
	return out
}

func (a *App) handleTestEmail(w http.ResponseWriter, r *http.Request) {
	act := actorFrom(r.Context())
	err := a.Mailer.Send(r.Context(), mail.Message{To: act.User.Email, Subject: "Test email", Heading: "Email delivery works",
		Body: []string{"This is a test message sent from your DNS dashboard settings."}})
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "to": act.User.Email})
}

// ---- Users ----

func (a *App) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListUsers(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		a.fail(w, r, errNotFound("User"))
		return
	}
	u, err := a.Store.UserByID(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	orgs, _ := a.Store.OrgsForUser(ctx, id)
	sessions, _ := a.Store.ListSessions(ctx, id)
	writeJSON(w, 200, map[string]any{"user": u, "orgs": orgs, "sessions": sessions, "has_password": u.HasPassword()})
}

func (a *App) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		a.fail(w, r, errNotFound("User"))
		return
	}
	u, err := a.Store.UserByID(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in struct {
		IsSuperadmin *bool   `json:"is_superadmin"`
		Disabled     *bool   `json:"disabled"`
		ResetMFA     bool    `json:"reset_mfa"`
		Logout       bool    `json:"logout"`
		Name         *string `json:"name"`
		Email        *string `json:"email"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	super, disabled := u.IsSuperadmin, u.Disabled
	if in.IsSuperadmin != nil {
		super = *in.IsSuperadmin
	}
	if in.Disabled != nil {
		disabled = *in.Disabled
	}
	if u.ID == act.User.ID && (!super || disabled) {
		a.fail(w, r, errConflict("You cannot remove your own administrator access or disable yourself."))
		return
	}
	if u.IsSuperadmin && (!super || disabled) {
		if n, _ := a.Store.CountSuperadmins(ctx); n <= 1 {
			a.fail(w, r, errConflict("At least one active instance administrator is required."))
			return
		}
	}
	changes := map[string]any{}
	if in.Name != nil || in.Email != nil {
		name, email := u.Name, u.Email
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
		}
		if in.Email != nil {
			e, err := normalizeEmail(*in.Email)
			if err != nil {
				a.fail(w, r, errField("email", err.Error()))
				return
			}
			email = e
		}
		if err := a.Store.UpdateUserIdentity(ctx, u.ID, email, name); err != nil {
			if db.IsUniqueViolation(err) {
				a.fail(w, r, errField("email", "Another user has this email"))
				return
			}
			a.fail(w, r, err)
			return
		}
		changes["name"], changes["email"] = name, email
	}
	if super != u.IsSuperadmin || disabled != u.Disabled {
		if err := a.Store.SetUserAdminFlags(ctx, u.ID, super, disabled); err != nil {
			a.fail(w, r, err)
			return
		}
		changes["is_superadmin"] = super
		changes["disabled"] = disabled
	}
	if disabled || in.Logout {
		_ = a.Store.DeleteUserSessions(ctx, u.ID, nil)
		changes["sessions_revoked"] = true
	}
	if in.ResetMFA {
		if err := a.Store.SetUserTOTP(ctx, u.ID, nil, false, nil); err != nil {
			a.fail(w, r, err)
			return
		}
		changes["mfa_reset"] = true
	}
	a.audit(r, auditEvent{Action: "admin.user_update", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email, Metadata: changes})
	u, _ = a.Store.UserByID(ctx, u.ID)
	writeJSON(w, 200, u)
}

// handleAdminCreateUser creates a local account directly (an alternative to invitations).
func (a *App) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Email        string     `json:"email"`
		Name         string     `json:"name"`
		Password     string     `json:"password"`
		IsSuperadmin bool       `json:"is_superadmin"`
		OrgID        *uuid.UUID `json:"org_id"`
		Role         string     `json:"role"`
		SendEmail    *bool      `json:"send_email"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	email, err := normalizeEmail(in.Email)
	if err != nil {
		a.fail(w, r, errField("email", err.Error()))
		return
	}
	var hash *string
	if in.Password != "" {
		if err := a.checkPassword(in.Password, email, a.Settings(ctx)); err != nil {
			a.fail(w, r, errField("password", err.Error()))
			return
		}
		h, err := secure.HashPassword(in.Password)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		hash = &h
	}
	if in.OrgID != nil {
		if !validRoles[in.Role] {
			a.fail(w, r, errField("role", "Choose a role"))
			return
		}
		if _, err := a.Store.OrgByID(ctx, *in.OrgID); err != nil {
			a.fail(w, r, errField("org_id", "Organization not found"))
			return
		}
	}
	u, err := a.Store.CreateUser(ctx, store.NewUser{Email: email, Name: strings.TrimSpace(in.Name), PasswordHash: hash,
		IsSuperadmin: in.IsSuperadmin, EmailVerified: true, CreatedVia: "admin"})
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("email", "A user with this email already exists"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if in.OrgID != nil {
		if err := a.Store.AddMember(ctx, *in.OrgID, u.ID, in.Role, nil, "manual"); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	// Without a password, give the user a link to choose one.
	setupURL := ""
	emailed := false
	if hash == nil {
		token := secure.RandomToken(32)
		if err := a.Store.CreatePasswordResetFor(ctx, secure.HashToken(token), u.ID, 7*24*time.Hour); err != nil {
			a.fail(w, r, err)
			return
		}
		setupURL = a.Cfg.PublicURL + "/reset-password?token=" + token
		emailed = (in.SendEmail == nil || *in.SendEmail) && a.Mailer.Send(context0(r), mailMessage(email, "Your account is ready", "Set your password",
			[]string{"An administrator created an account for you. Choose a password to sign in.", "This link expires in 7 days."},
			"Set password", setupURL)) == nil
	}
	a.audit(r, auditEvent{OrgID: in.OrgID, Action: "admin.user_create", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: email,
		Metadata: map[string]any{"superadmin": in.IsSuperadmin, "org_id": in.OrgID, "role": in.Role, "password_set": hash != nil}})
	writeJSON(w, 201, map[string]any{"user": u, "setup_url": setupURL, "emailed": emailed})
}

func (a *App) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "userID"))
	if err != nil {
		a.fail(w, r, errNotFound("User"))
		return
	}
	if id == act.User.ID {
		a.fail(w, r, errConflict("Delete your own account from your profile instead."))
		return
	}
	u, err := a.Store.UserByID(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	orgs, _ := a.Store.OrgsForUser(ctx, id)
	for _, o := range orgs {
		if o.Role == "owner" {
			if n, _ := a.Store.CountOwners(ctx, o.ID); n <= 1 {
				a.fail(w, r, errConflict(u.Email+" is the only owner of "+o.Name+". Assign another owner first."))
				return
			}
		}
	}
	if err := a.Store.DeleteUser(ctx, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "admin.user_delete", ResourceType: "user", ResourceID: id.String(), ResourceName: u.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Organizations ----

func (a *App) handleAdminOrgs(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListOrgs(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Name       string `json:"name"`
		OwnerEmail string `json:"owner_email"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		a.fail(w, r, errField("name", "Enter a name"))
		return
	}
	var owner *store.User
	if in.OwnerEmail != "" {
		u, err := a.Store.UserByEmail(ctx, strings.ToLower(strings.TrimSpace(in.OwnerEmail)))
		if errors.Is(err, db.ErrNotFound) {
			a.fail(w, r, errField("owner_email", "No user with this email exists. Invite them after creating the organization."))
			return
		}
		if err != nil {
			a.fail(w, r, err)
			return
		}
		owner = u
	} else {
		owner = actorFrom(ctx).User
	}
	var org *store.Org
	err := a.Store.Tx(ctx, func(tx *store.Store) error {
		var err error
		if org, err = tx.CreateOrg(ctx, strings.TrimSpace(in.Name), slugify(in.Name)); err != nil {
			return err
		}
		return tx.AddMember(ctx, org.ID, owner.ID, "owner", nil, "manual")
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{OrgID: &org.ID, Action: "org.create", ResourceType: "organization", ResourceID: org.ID.String(), ResourceName: org.Name,
		Metadata: map[string]any{"owner": owner.Email, "by_admin": true}})
	writeJSON(w, 201, org)
}

func (a *App) handleAdminUpdateOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		a.fail(w, r, errNotFound("Organization"))
		return
	}
	org, err := a.Store.OrgByID(ctx, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in struct {
		MaxZones        *int       `json:"max_zones"`
		NameserverSetID *uuid.UUID `json:"nameserver_set_id"`
		PDNSServerID    *uuid.UUID `json:"pdns_server_id"`
		Suspended       bool       `json:"suspended"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.MaxZones != nil && *in.MaxZones < 0 {
		a.fail(w, r, errField("max_zones", "Must be zero or more"))
		return
	}
	if in.PDNSServerID != nil {
		if _, err := a.Store.ServerByID(ctx, *in.PDNSServerID); err != nil {
			a.fail(w, r, errField("pdns_server_id", "Server not found"))
			return
		}
	}
	if in.NameserverSetID != nil {
		if _, err := a.Store.NameserverSetByID(ctx, *in.NameserverSetID); err != nil {
			a.fail(w, r, errField("nameserver_set_id", "Nameserver set not found"))
			return
		}
	}
	if err := a.Store.UpdateOrgAdmin(ctx, id, store.OrgAdminUpdate{MaxZones: in.MaxZones, NameserverSetID: in.NameserverSetID,
		PDNSServerID: in.PDNSServerID, Suspended: in.Suspended}); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{OrgID: &org.ID, Action: "admin.org_update", ResourceType: "organization", ResourceID: org.ID.String(), ResourceName: org.Name,
		Metadata: map[string]any{"max_zones": in.MaxZones, "nameserver_set_id": in.NameserverSetID, "pdns_server_id": in.PDNSServerID, "suspended": in.Suspended}})
	org, _ = a.Store.OrgByID(ctx, id)
	writeJSON(w, 200, org)
}

func (a *App) handleAdminZones(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListAllZones(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

// handleNameserverSetsPublic lets zone admins see available nameserver sets.
func (a *App) handleNameserverSetsPublic(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListNameserverSets(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type pub struct {
		ID          uuid.UUID `json:"id"`
		Name        string    `json:"name"`
		Nameservers []string  `json:"nameservers"`
		IsDefault   bool      `json:"is_default"`
	}
	org := orgFrom(r.Context())
	out := []pub{}
	for _, s := range list {
		def := s.IsDefault
		if org.NameserverSetID != nil {
			def = *org.NameserverSetID == s.ID
		}
		out = append(out, pub{ID: s.ID, Name: s.Name, Nameservers: s.Nameservers, IsDefault: def})
	}
	writeJSON(w, 200, out)
}
