package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/flare-dns/flare/internal/store"
	"github.com/google/uuid"
)

type auditEvent struct {
	OrgID        *uuid.UUID
	ZoneID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   string
	ResourceName string
	Outcome      string
	Metadata     map[string]any
	// Actor overrides (used before a session exists, e.g. login).
	ActorUser  *store.User
	ActorType  string
	ActorLabel string
}

// audit records an event. It never fails the request; errors are logged.
func (a *App) audit(r *http.Request, ev auditEvent) {
	ctx := r.Context()
	e := store.AuditEntry{
		OrgID: ev.OrgID, ZoneID: ev.ZoneID, Action: ev.Action, ResourceType: ev.ResourceType,
		ResourceID: ev.ResourceID, ResourceName: ev.ResourceName, Outcome: ev.Outcome,
		IP: a.clientIP(r), UserAgent: truncate(r.UserAgent(), 400),
	}
	if e.Outcome == "" {
		e.Outcome = "success"
	}
	if e.OrgID == nil {
		if org := orgFrom(ctx); org != nil {
			e.OrgID = &org.ID
		}
	}
	if e.ZoneID == nil {
		if z := zoneFrom(ctx); z != nil {
			e.ZoneID = &z.ID
		}
	}
	switch {
	case ev.ActorUser != nil:
		e.ActorType, e.ActorID, e.ActorLabel = "user", &ev.ActorUser.ID, ev.ActorUser.Email
	case ev.ActorType != "":
		e.ActorType, e.ActorLabel = ev.ActorType, ev.ActorLabel
	default:
		if act := actorFrom(ctx); act != nil {
			e.ActorType, e.ActorID, e.ActorLabel = act.Type, act.ID, act.Label
		} else {
			e.ActorType, e.ActorLabel = "anonymous", "Anonymous"
		}
	}
	if ev.Metadata != nil {
		if raw, err := json.Marshal(ev.Metadata); err == nil {
			e.Metadata = raw
		}
	}
	// Use a detached context so the record survives client disconnects.
	bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	id, err := a.Store.InsertAudit(bg, e)
	if err != nil {
		a.Log.Error("write audit log", "err", err, "action", e.Action)
		return
	}
	if e.OrgID != nil && e.Outcome == "success" {
		e.ID = id
		e.CreatedAt = time.Now().UTC()
		a.dispatchWebhooks(bg, *e.OrgID, e)
	}
}

func (a *App) dispatchWebhooks(ctx context.Context, orgID uuid.UUID, e store.AuditEntry) {
	hooks, err := a.Store.EnabledWebhooks(ctx, orgID)
	if err != nil || len(hooks) == 0 {
		return
	}
	payload, _ := json.Marshal(map[string]any{
		"id":         e.ID,
		"event":      e.Action,
		"created_at": e.CreatedAt,
		"org_id":     orgID,
		"zone_id":    e.ZoneID,
		"actor":      map[string]any{"type": e.ActorType, "id": e.ActorID, "label": e.ActorLabel},
		"resource":   map[string]any{"type": e.ResourceType, "id": e.ResourceID, "name": e.ResourceName},
		"metadata":   json.RawMessage(orDefault(e.Metadata, []byte(`{}`))),
	})
	for _, h := range hooks {
		if eventMatches(h.Events, e.Action) {
			if err := a.Store.EnqueueDelivery(ctx, h.ID, e.Action, payload); err != nil {
				a.Log.Error("enqueue webhook", "err", err)
			}
		}
	}
}

func eventMatches(patterns []string, event string) bool {
	for _, p := range patterns {
		if p == "*" || p == event {
			return true
		}
		if strings.HasSuffix(p, ".*") && strings.HasPrefix(event, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}

func orDefault(b, def []byte) []byte {
	if len(b) == 0 {
		return def
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func uuidPtr(u uuid.UUID) *uuid.UUID { return &u }

// systemAudit records an event performed by Flare itself (background jobs).
func (a *App) systemAudit(ctx context.Context, orgID, zoneID uuid.UUID, action, resourceType, name string, meta map[string]any) {
	raw, _ := json.Marshal(meta)
	e := store.AuditEntry{OrgID: &orgID, ZoneID: &zoneID, ActorType: "system", ActorLabel: "System", Action: action,
		ResourceType: resourceType, ResourceID: zoneID.String(), ResourceName: name, Outcome: "success", Metadata: raw}
	id, err := a.Store.InsertAudit(ctx, e)
	if err != nil {
		a.Log.Error("write audit log", "err", err, "action", action)
		return
	}
	e.ID, e.CreatedAt = id, time.Now().UTC()
	a.dispatchWebhooks(ctx, orgID, e)
}
