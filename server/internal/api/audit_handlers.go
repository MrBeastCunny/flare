package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func parseAuditFilter(r *http.Request) (store.AuditFilter, error) {
	q := r.URL.Query()
	f := store.AuditFilter{
		Action:       q.Get("action"),
		ResourceType: q.Get("resource_type"),
		Outcome:      q.Get("outcome"),
		Query:        strings.TrimSpace(q.Get("q")),
	}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return f, errBadRequest("Invalid cursor")
		}
		f.Before = n
	}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	for _, p := range []struct {
		key string
		dst **uuid.UUID
	}{{"zone_id", &f.ZoneID}, {"actor_id", &f.ActorID}, {"org_id", &f.OrgID}} {
		if v := q.Get(p.key); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				return f, errBadRequest("Invalid " + p.key)
			}
			*p.dst = &id
		}
	}
	for _, p := range []struct {
		key string
		dst **time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if v := q.Get(p.key); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return f, errBadRequest("Invalid " + p.key + " timestamp")
			}
			*p.dst = &t
		}
	}
	return f, nil
}

func (a *App) writeAuditPage(w http.ResponseWriter, r *http.Request, f store.AuditFilter) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	entries, err := a.Store.ListAudit(r.Context(), f)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var next *int64
	if len(entries) == f.Limit {
		n := entries[len(entries)-1].ID
		next = &n
	}
	writeJSON(w, 200, map[string]any{"entries": entries, "next_cursor": next})
}

func (a *App) handleOrgAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f, err := parseAuditFilter(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	org := orgFrom(ctx)
	f.OrgID = &org.ID
	f.IncludeMemberAuth = f.ZoneID == nil
	acc := accessFrom(ctx)
	if acc.ZoneIDs != nil && f.ZoneID == nil {
		a.fail(w, r, errForbidden("Your access is limited to specific zones. Filter the audit log by zone."))
		return
	}
	a.writeAuditPage(w, r, f)
}

func (a *App) handleZoneAudit(w http.ResponseWriter, r *http.Request) {
	f, err := parseAuditFilter(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	z := zoneFrom(r.Context())
	f.OrgID = &z.OrgID
	f.ZoneID = &z.ID
	a.writeAuditPage(w, r, f)
}

func (a *App) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	f, err := parseAuditFilter(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeAuditPage(w, r, f)
}

func (a *App) streamAuditExport(w http.ResponseWriter, r *http.Request, f store.AuditFilter, name string) {
	format := r.URL.Query().Get("format")
	if format != "json" {
		format = "csv"
	}
	filename := fmt.Sprintf("%s-audit-log-%s.%s", name, time.Now().UTC().Format("20060102-150405"), format)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	var cw *csv.Writer
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw = csv.NewWriter(w)
		_ = cw.Write([]string{"id", "timestamp", "organization", "actor_type", "actor", "action", "resource_type", "resource_id",
			"resource_name", "outcome", "ip", "user_agent", "metadata"})
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
	}
	enc := json.NewEncoder(w)
	f.Limit = 1000
	written := 0
	for written < 250000 {
		page, err := a.Store.ListAudit(r.Context(), f)
		if err != nil || len(page) == 0 {
			break
		}
		for _, e := range page {
			if cw != nil {
				_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.CreatedAt.UTC().Format(time.RFC3339), e.OrgName, e.ActorType, e.ActorLabel,
					e.Action, e.ResourceType, e.ResourceID, e.ResourceName, e.Outcome, e.IP, e.UserAgent, string(e.Metadata)})
			} else {
				_ = enc.Encode(e)
			}
		}
		written += len(page)
		f.Before = page[len(page)-1].ID
		if cw != nil {
			cw.Flush()
		}
		if len(page) < f.Limit {
			break
		}
	}
	a.audit(r, auditEvent{Action: "audit.export", ResourceType: "audit_log", ResourceName: name, Metadata: map[string]any{"rows": written, "format": format}})
}

func (a *App) handleOrgAuditExport(w http.ResponseWriter, r *http.Request) {
	f, err := parseAuditFilter(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	org := orgFrom(r.Context())
	f.OrgID = &org.ID
	f.IncludeMemberAuth = f.ZoneID == nil
	if accessFrom(r.Context()).ZoneIDs != nil {
		a.fail(w, r, errForbidden("Exports are not available for zone-scoped members."))
		return
	}
	a.streamAuditExport(w, r, f, org.Slug)
}

func (a *App) handleAdminAuditExport(w http.ResponseWriter, r *http.Request) {
	f, err := parseAuditFilter(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.streamAuditExport(w, r, f, "instance")
}

// ---- Webhooks ----

var webhookEvents = []string{"*", "zone.*", "record.*", "member.*", "token.*", "sso.*", "org.*", "auth.*",
	"zone.create", "zone.delete", "zone.status_change", "zone.settings_update", "zone.dnssec_enable", "zone.dnssec_disable",
	"record.create", "record.update", "record.delete", "record.bulk_delete", "zone.import",
	"member.invite", "member.join", "member.update", "member.remove"}

func (a *App) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListWebhooks(r.Context(), orgFrom(r.Context()).ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"webhooks": list, "events": webhookEvents})
}

type webhookInput struct {
	Name    string   `json:"name"`
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

func (a *App) validateWebhook(in *webhookInput) error {
	fields := map[string]string{}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		fields["name"] = "Enter a name"
	}
	u, err := url.Parse(strings.TrimSpace(in.URL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(a.Cfg.DevMode && u.Scheme == "http")) {
		fields["url"] = "Enter an https URL"
	}
	in.Events = cleanList(in.Events)
	if len(in.Events) == 0 {
		in.Events = []string{"*"}
	}
	if len(fields) > 0 {
		return errValidation(fields)
	}
	in.URL = u.String()
	return nil
}

func (a *App) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	var in webhookInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.validateWebhook(&in); err != nil {
		a.fail(w, r, err)
		return
	}
	secret := "whsec_" + secure.RandomToken(24)
	enc, err := a.Box.Seal(secret)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var by *uuid.UUID
	if act := actorFrom(ctx); act.Type == "user" {
		by = &act.User.ID
	}
	hook, err := a.Store.CreateWebhook(ctx, store.Webhook{OrgID: org.ID, Name: in.Name, URL: in.URL, SecretEnc: enc, Events: in.Events,
		Enabled: in.Enabled, CreatedBy: by})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "webhook.create", ResourceType: "webhook", ResourceID: hook.ID.String(), ResourceName: hook.Name,
		Metadata: map[string]any{"url": hook.URL, "events": hook.Events}})
	writeJSON(w, 201, map[string]any{"webhook": hook, "secret": secret})
}

func (a *App) loadWebhook(r *http.Request) (*store.Webhook, error) {
	id, err := uuid.Parse(chi.URLParam(r, "webhookID"))
	if err != nil {
		return nil, errNotFound("Webhook")
	}
	return a.Store.WebhookByID(r.Context(), orgFrom(r.Context()).ID, id)
}

func (a *App) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.loadWebhook(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in webhookInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.validateWebhook(&in); err != nil {
		a.fail(w, r, err)
		return
	}
	hook.Name, hook.URL, hook.Events, hook.Enabled = in.Name, in.URL, in.Events, in.Enabled
	if err := a.Store.UpdateWebhook(r.Context(), *hook); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "webhook.update", ResourceType: "webhook", ResourceID: hook.ID.String(), ResourceName: hook.Name,
		Metadata: map[string]any{"url": hook.URL, "events": hook.Events, "enabled": hook.Enabled}})
	writeJSON(w, 200, hook)
}

func (a *App) handleRotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
	hook, err := a.loadWebhook(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	secret := "whsec_" + secure.RandomToken(24)
	if hook.SecretEnc, err = a.Box.Seal(secret); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.UpdateWebhook(r.Context(), *hook); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "webhook.rotate_secret", ResourceType: "webhook", ResourceID: hook.ID.String(), ResourceName: hook.Name})
	writeJSON(w, 200, map[string]any{"secret": secret})
}

func (a *App) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.loadWebhook(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.Store.DeleteWebhook(r.Context(), hook.OrgID, hook.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "webhook.delete", ResourceType: "webhook", ResourceID: hook.ID.String(), ResourceName: hook.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	hook, err := a.loadWebhook(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	list, err := a.Store.ListDeliveries(r.Context(), hook.ID, 100)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.loadWebhook(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	payload, _ := json.Marshal(map[string]any{"id": 0, "event": "webhook.test", "created_at": time.Now().UTC(), "org_id": hook.OrgID,
		"actor":    map[string]any{"type": actorFrom(r.Context()).Type, "label": actorFrom(r.Context()).Label},
		"resource": map[string]any{"type": "webhook", "id": hook.ID, "name": hook.Name}, "metadata": map[string]any{}})
	if err := a.Store.EnqueueDelivery(r.Context(), hook.ID, "webhook.test", payload); err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 202, map[string]any{"ok": true})
}

// webhookClient refuses connections to internal addresses unless explicitly allowed.
func (a *App) webhookClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !a.Cfg.WebhookAllowPrivate && !a.Cfg.DevMode {
		dialer.Control = func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
				return fmt.Errorf("webhook destination %s is not a public address", host)
			}
			return nil
		}
	}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 20,
		IdleConnTimeout: 60 * time.Second, Proxy: nil}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// DeliverWebhooks sends due webhook deliveries. Called periodically by the job runner.
func (a *App) DeliverWebhooks(ctx context.Context) {
	due, err := a.Store.DueDeliveries(ctx, 50)
	if err != nil {
		a.Log.Error("load webhook deliveries", "err", err)
		return
	}
	client := a.webhookClient()
	for _, d := range due {
		secret, err := a.Box.Open(d.SecretEnc)
		if err != nil {
			continue
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "." + string(d.Payload)))
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(d.Payload))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Flare-Webhooks/"+Version)
		req.Header.Set("X-Flare-Event", d.Event)
		req.Header.Set("X-Flare-Delivery", strconv.FormatInt(d.ID, 10))
		req.Header.Set("X-Flare-Signature", "t="+ts+",v1="+hex.EncodeToString(mac.Sum(nil)))
		resp, err := client.Do(req)
		attempt := d.Attempts + 1
		var status *int
		body := ""
		ok := false
		if err != nil {
			body = err.Error()
		} else {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			s := resp.StatusCode
			status = &s
			body = string(b)
			ok = s >= 200 && s < 300
		}
		state := "pending"
		next := time.Now().Add(time.Duration(1<<min(attempt, 10)) * 30 * time.Second)
		if ok {
			state = "delivered"
		} else if attempt >= 8 {
			state = "failed"
		}
		if err := a.Store.RecordDeliveryAttempt(ctx, d.ID, state, status, truncate(body, 2000), next); err != nil {
			a.Log.Error("record webhook attempt", "err", err)
		}
	}
}
