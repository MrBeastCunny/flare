package api

import (
	"net/http"
	"strings"

	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// Global API tokens belong to the instance rather than one organization. Instance administrators
// create them for automation that spans organizations, such as provisioning tenants or running
// external-dns against several of them. A token works in the organizations it is scoped to
// (all of them when org_ids is empty) with one role, and its instance role optionally opens the
// admin API.

func (a *App) handleListGlobalTokens(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListGlobalAPITokens(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleCreateGlobalToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		Name          string      `json:"name"`
		Role          string      `json:"role"`
		OrgIDs        []uuid.UUID `json:"org_ids"`
		InstanceRole  string      `json:"instance_role"`
		IPAllowlist   []string    `json:"ip_allowlist"`
		ExpiresInDays int         `json:"expires_in_days"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	fields := map[string]string{}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		fields["name"] = "Enter a token name"
	}
	if _, ok := tokenRolePerms[in.Role]; !ok {
		fields["role"] = "Choose org_admin, admin, editor or viewer"
	}
	if in.InstanceRole == "" {
		in.InstanceRole = "none"
	}
	if _, ok := instanceRoleRank[in.InstanceRole]; !ok {
		fields["instance_role"] = "Choose none, orgs or admin"
	}
	in.IPAllowlist = cleanList(in.IPAllowlist)
	if err := validateCIDRs(in.IPAllowlist); err != nil {
		fields["ip_allowlist"] = err.Error()
	}
	if in.ExpiresInDays < 0 || in.ExpiresInDays > 3650 {
		fields["expires_in_days"] = "Expiry must be between 1 and 3650 days"
	}
	if len(in.OrgIDs) == 0 {
		in.OrgIDs = nil
	} else if orgs, err := a.Store.OrgsByIDs(ctx, in.OrgIDs); err != nil {
		a.fail(w, r, err)
		return
	} else if len(orgs) != len(uniqueIDs(in.OrgIDs)) {
		fields["org_ids"] = "One or more organizations no longer exist"
	} else {
		in.OrgIDs = uniqueIDs(in.OrgIDs)
	}
	if len(fields) > 0 {
		a.fail(w, r, errValidation(fields))
		return
	}
	t := store.APIToken{Name: in.Name, Role: in.Role, OrgIDs: in.OrgIDs, InstanceRole: in.InstanceRole, IPAllowlist: in.IPAllowlist,
		CreatedBy: actorUserID(ctx)}
	if in.ExpiresInDays > 0 {
		exp := timeNow().AddDate(0, 0, in.ExpiresInDays)
		t.ExpiresAt = &exp
	}
	secret, prefix := newAPITokenSecret()
	t.Prefix = prefix
	created, err := a.Store.CreateAPIToken(ctx, t, secure.HashToken(secret))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "token.create", ResourceType: "api_token", ResourceID: created.ID.String(), ResourceName: created.Name,
		Metadata: map[string]any{"global": true, "role": in.Role, "org_ids": in.OrgIDs, "instance_role": in.InstanceRole,
			"ip_allowlist": in.IPAllowlist, "expires_at": t.ExpiresAt}})
	writeJSON(w, 201, map[string]any{"token": created, "secret": secret})
}

func (a *App) globalTokenParam(r *http.Request) (*store.APIToken, error) {
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		return nil, errNotFound("Token")
	}
	t, err := a.Store.GlobalAPITokenByID(r.Context(), id)
	if err != nil || t.RevokedAt != nil {
		return nil, errNotFound("Token")
	}
	return t, nil
}

func (a *App) handleRollGlobalToken(w http.ResponseWriter, r *http.Request) {
	t, err := a.globalTokenParam(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	secret, prefix := newAPITokenSecret()
	if err := a.Store.RollAPIToken(r.Context(), t.ID, prefix, secure.HashToken(secret)); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "token.roll", ResourceType: "api_token", ResourceID: t.ID.String(), ResourceName: t.Name,
		Metadata: map[string]any{"global": true}})
	t.Prefix = prefix
	writeJSON(w, 200, map[string]any{"token": t, "secret": secret})
}

func (a *App) handleRevokeGlobalToken(w http.ResponseWriter, r *http.Request) {
	t, err := a.globalTokenParam(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.Store.RevokeGlobalAPIToken(r.Context(), t.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "token.revoke", ResourceType: "api_token", ResourceID: t.ID.String(), ResourceName: t.Name,
		Metadata: map[string]any{"global": true}})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func uniqueIDs(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	out := []uuid.UUID{}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
