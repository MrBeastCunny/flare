package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// SCIM 2.0 (RFC 7643 / 7644) provisioning for users and groups.

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type scimCtxKey struct{}

func scimOrg(ctx context.Context) uuid.UUID { return ctx.Value(scimCtxKey{}).(uuid.UUID) }

func scimError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	body := map[string]any{"schemas": []string{scimErrorSchema}, "status": strconv.Itoa(status), "detail": detail}
	if scimType != "" {
		body["scimType"] = scimType
	}
	_ = json.NewEncoder(w).Encode(body)
}

func scimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *App) SCIMAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if raw == "" {
			scimError(w, 401, "", "Missing bearer token")
			return
		}
		tokID, orgID, err := a.Store.SCIMTokenOrg(r.Context(), secure.HashToken(raw))
		if err != nil {
			scimError(w, 401, "", "Invalid bearer token")
			return
		}
		act := &Actor{Type: "scim", OrgID: &orgID, ID: &tokID, Label: "SCIM provisioning"}
		ctx := context.WithValue(r.Context(), scimCtxKey{}, orgID)
		ctx = context.WithValue(ctx, keyActor, act)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *App) scimBase() string { return a.Cfg.PublicURL + "/scim/v2" }

func (a *App) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, 200, map[string]any{
		"schemas":               []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri":      a.Cfg.PublicURL + "/docs/scim",
		"patch":                 map[string]bool{"supported": true},
		"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":                map[string]any{"supported": true, "maxResults": 200},
		"changePassword":        map[string]bool{"supported": false},
		"sort":                  map[string]bool{"supported": false},
		"etag":                  map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "OAuth Bearer Token", "description": "Authentication using a SCIM token", "primary": true}},
	})
}

func (a *App) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "Resources": []map[string]any{
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "User", "name": "User", "endpoint": "/Users", "schema": scimUserSchema},
		{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": "Group", "name": "Group", "endpoint": "/Groups", "schema": scimGroupSchema},
	}})
}

func (a *App) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	scimJSON(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": 2, "Resources": []map[string]any{
		{"id": scimUserSchema, "name": "User", "attributes": []map[string]any{
			{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
			{"name": "displayName", "type": "string"}, {"name": "active", "type": "boolean"},
			{"name": "emails", "type": "complex", "multiValued": true}, {"name": "name", "type": "complex"}}},
		{"id": scimGroupSchema, "name": "Group", "attributes": []map[string]any{
			{"name": "displayName", "type": "string", "required": true}, {"name": "members", "type": "complex", "multiValued": true}}},
	}})
}

// ---- Users ----

type scimUserIn struct {
	Schemas     []string `json:"schemas"`
	UserName    string   `json:"userName"`
	ExternalID  *string  `json:"externalId"`
	DisplayName string   `json:"displayName"`
	Active      *bool    `json:"active"`
	Name        struct {
		Formatted  string `json:"formatted"`
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

func (in scimUserIn) email() string {
	for _, e := range in.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if strings.Contains(in.UserName, "@") {
		return in.UserName
	}
	if len(in.Emails) > 0 {
		return in.Emails[0].Value
	}
	return in.UserName
}

func (in scimUserIn) fullName() string {
	if in.DisplayName != "" {
		return in.DisplayName
	}
	if in.Name.Formatted != "" {
		return in.Name.Formatted
	}
	return strings.TrimSpace(in.Name.GivenName + " " + in.Name.FamilyName)
}

func (a *App) scimUser(u *store.User, m *store.Membership) map[string]any {
	given, family, _ := strings.Cut(u.Name, " ")
	active := !u.Disabled && (m == nil || !m.Suspended)
	out := map[string]any{
		"schemas":     []string{scimUserSchema},
		"id":          u.ID.String(),
		"userName":    u.Email,
		"displayName": u.Name,
		"name":        map[string]string{"formatted": u.Name, "givenName": given, "familyName": family},
		"emails":      []map[string]any{{"value": u.Email, "primary": true, "type": "work"}},
		"active":      active,
		"meta": map[string]any{"resourceType": "User", "created": u.CreatedAt, "lastModified": u.UpdatedAt,
			"location": a.scimBase() + "/Users/" + u.ID.String()},
	}
	if u.SCIMExternalID != nil {
		out["externalId"] = *u.SCIMExternalID
	}
	return out
}

// parseSimpleFilter supports `attr eq "value"`, which is what IdPs send in practice.
func parseSimpleFilter(f string) (attr, value string) {
	parts := strings.SplitN(strings.TrimSpace(f), " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", ""
	}
	return parts[0], strings.Trim(parts[2], `"`)
}

func pageParams(r *http.Request) (offset, limit int) {
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if start < 1 {
		start = 1
	}
	if err != nil || count < 0 || count > 200 {
		count = 100
	}
	return start - 1, count
}

func (a *App) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	attr, val := parseSimpleFilter(r.URL.Query().Get("filter"))
	email, ext := "", ""
	switch strings.ToLower(attr) {
	case "username", "emails.value", "emails":
		email = val
	case "externalid":
		ext = val
	}
	offset, limit := pageParams(r)
	users, total, err := a.Store.SCIMUsers(ctx, org, email, ext, offset, limit)
	if err != nil {
		scimError(w, 500, "", "Internal error")
		return
	}
	res := make([]map[string]any, 0, len(users))
	for i := range users {
		m, _ := a.Store.Membership(ctx, org, users[i].ID)
		res = append(res, a.scimUser(&users[i], m))
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": offset + 1,
		"itemsPerPage": len(res), "Resources": res})
}

func (a *App) scimLoadUser(w http.ResponseWriter, r *http.Request) (*store.User, *store.Membership, bool) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		scimError(w, 404, "", "User not found")
		return nil, nil, false
	}
	u, err := a.Store.SCIMUser(ctx, scimOrg(ctx), id)
	if err != nil {
		scimError(w, 404, "", "User not found")
		return nil, nil, false
	}
	m, _ := a.Store.Membership(ctx, scimOrg(ctx), u.ID)
	return u, m, true
}

func (a *App) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	if u, m, ok := a.scimLoadUser(w, r); ok {
		scimJSON(w, 200, a.scimUser(u, m))
	}
}

func (a *App) scimDefaultRole(ctx context.Context, org uuid.UUID) string {
	if c, err := a.Store.SSOConnectionForOrg(ctx, org); err == nil && c.DefaultRole != "" {
		return c.DefaultRole
	}
	return "viewer"
}

func (a *App) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	var in scimUserIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		scimError(w, 400, "invalidSyntax", "Invalid JSON")
		return
	}
	email, err := normalizeEmail(in.email())
	if err != nil {
		scimError(w, 400, "invalidValue", "userName must be an email address")
		return
	}
	u, err := a.Store.UserByEmail(ctx, email)
	if errors.Is(err, db.ErrNotFound) {
		u, err = a.Store.CreateUser(ctx, store.NewUser{Email: email, Name: in.fullName(), EmailVerified: true, CreatedVia: "scim", SCIMExternalID: in.ExternalID})
	}
	if err != nil {
		scimError(w, 500, "", "Could not create user")
		return
	}
	if _, err := a.Store.Membership(ctx, org, u.ID); err == nil {
		scimError(w, 409, "uniqueness", "User already exists in this organization")
		return
	}
	if err := a.Store.AddMember(ctx, org, u.ID, a.scimDefaultRole(ctx, org), nil, "scim"); err != nil {
		scimError(w, 500, "", "Could not add member")
		return
	}
	if in.ExternalID != nil || in.fullName() != "" {
		_ = a.Store.SetUserSCIM(ctx, u.ID, in.ExternalID, orStr(in.fullName(), u.Name))
	}
	if in.Active != nil && !*in.Active {
		_ = a.Store.SetMemberSuspended(ctx, org, u.ID, true)
	}
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.user_create", ResourceType: "member", ResourceID: u.ID.String(), ResourceName: email})
	u, _ = a.Store.UserByID(ctx, u.ID)
	m, _ := a.Store.Membership(ctx, org, u.ID)
	scimJSON(w, 201, a.scimUser(u, m))
}

func (a *App) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	u, _, ok := a.scimLoadUser(w, r)
	if !ok {
		return
	}
	var in scimUserIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		scimError(w, 400, "invalidSyntax", "Invalid JSON")
		return
	}
	_ = a.Store.SetUserSCIM(ctx, u.ID, in.ExternalID, orStr(in.fullName(), u.Name))
	if in.Active != nil {
		a.scimSetActive(r, org, u, *in.Active)
	}
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.user_update", ResourceType: "member", ResourceID: u.ID.String(), ResourceName: u.Email})
	u, _ = a.Store.UserByID(ctx, u.ID)
	m, _ := a.Store.Membership(ctx, org, u.ID)
	scimJSON(w, 200, a.scimUser(u, m))
}

func (a *App) scimSetActive(r *http.Request, org uuid.UUID, u *store.User, active bool) {
	ctx := r.Context()
	m, err := a.Store.Membership(ctx, org, u.ID)
	if err != nil || m.Suspended == !active {
		return
	}
	_ = a.Store.SetMemberSuspended(ctx, org, u.ID, !active)
	action := "scim.user_reactivate"
	if !active {
		action = "scim.user_deactivate"
		// End sessions of users provisioned exclusively by this IdP.
		if orgs, err := a.Store.OrgsForUser(ctx, u.ID); err == nil && len(orgs) == 0 {
			_ = a.Store.DeleteUserSessions(ctx, u.ID, nil)
		}
	}
	a.audit(r, auditEvent{OrgID: &org, Action: action, ResourceType: "member", ResourceID: u.ID.String(), ResourceName: u.Email})
}

type scimPatch struct {
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

func scimBool(raw json.RawMessage) (bool, bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, err := strconv.ParseBool(s)
		return v, err == nil
	}
	return false, false
}

func (a *App) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	u, _, ok := a.scimLoadUser(w, r)
	if !ok {
		return
	}
	var p scimPatch
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		scimError(w, 400, "invalidSyntax", "Invalid JSON")
		return
	}
	name := u.Name
	ext := u.SCIMExternalID
	for _, op := range p.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		path := strings.ToLower(op.Path)
		if path == "" {
			// Value is an object of attributes.
			var obj map[string]json.RawMessage
			if json.Unmarshal(op.Value, &obj) != nil {
				continue
			}
			for k, v := range obj {
				switch strings.ToLower(k) {
				case "active":
					if b, ok := scimBool(v); ok {
						a.scimSetActive(r, org, u, b)
					}
				case "displayname":
					_ = json.Unmarshal(v, &name)
				case "externalid":
					var s string
					if json.Unmarshal(v, &s) == nil {
						ext = &s
					}
				}
			}
			continue
		}
		switch path {
		case "active":
			if b, ok := scimBool(op.Value); ok {
				a.scimSetActive(r, org, u, b)
			}
		case "displayname", "name.formatted":
			_ = json.Unmarshal(op.Value, &name)
		case "externalid":
			var s string
			if json.Unmarshal(op.Value, &s) == nil {
				ext = &s
			}
		}
	}
	if name != u.Name || ext != u.SCIMExternalID {
		_ = a.Store.SetUserSCIM(ctx, u.ID, ext, name)
	}
	u, _ = a.Store.UserByID(ctx, u.ID)
	m, _ := a.Store.Membership(ctx, org, u.ID)
	scimJSON(w, 200, a.scimUser(u, m))
}

func (a *App) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	u, m, ok := a.scimLoadUser(w, r)
	if !ok {
		return
	}
	if m != nil && m.Role == "owner" {
		if n, _ := a.Store.CountOwners(ctx, org); n <= 1 {
			scimError(w, 409, "mutability", "Cannot remove the last owner of the organization")
			return
		}
	}
	if err := a.Store.RemoveMember(ctx, org, u.ID); err != nil {
		scimError(w, 500, "", "Could not remove user")
		return
	}
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.user_delete", ResourceType: "member", ResourceID: u.ID.String(), ResourceName: u.Email})
	w.WriteHeader(204)
}

// ---- Groups ----

func (a *App) scimGroup(g *store.SCIMGroup) map[string]any {
	members := make([]map[string]string, 0, len(g.MemberIDs))
	for _, id := range g.MemberIDs {
		members = append(members, map[string]string{"value": id.String(), "$ref": a.scimBase() + "/Users/" + id.String()})
	}
	out := map[string]any{"schemas": []string{scimGroupSchema}, "id": g.ID.String(), "displayName": g.DisplayName, "members": members,
		"meta": map[string]any{"resourceType": "Group", "created": g.CreatedAt, "lastModified": g.UpdatedAt, "location": a.scimBase() + "/Groups/" + g.ID.String()}}
	if g.ExternalID != nil {
		out["externalId"] = *g.ExternalID
	}
	return out
}

func (a *App) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	attr, val := parseSimpleFilter(r.URL.Query().Get("filter"))
	name := ""
	if strings.EqualFold(attr, "displayName") {
		name = val
	}
	offset, limit := pageParams(r)
	groups, total, err := a.Store.SCIMGroups(ctx, scimOrg(ctx), name, offset, limit)
	if err != nil {
		scimError(w, 500, "", "Internal error")
		return
	}
	res := make([]map[string]any, 0, len(groups))
	for i := range groups {
		res = append(res, a.scimGroup(&groups[i]))
	}
	scimJSON(w, 200, map[string]any{"schemas": []string{scimListSchema}, "totalResults": total, "startIndex": offset + 1,
		"itemsPerPage": len(res), "Resources": res})
}

func (a *App) scimLoadGroup(w http.ResponseWriter, r *http.Request) (*store.SCIMGroup, bool) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		scimError(w, 404, "", "Group not found")
		return nil, false
	}
	g, err := a.Store.SCIMGroup(ctx, scimOrg(ctx), id)
	if err != nil {
		scimError(w, 404, "", "Group not found")
		return nil, false
	}
	return g, true
}

func (a *App) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	if g, ok := a.scimLoadGroup(w, r); ok {
		scimJSON(w, 200, a.scimGroup(g))
	}
}

type scimGroupIn struct {
	DisplayName string  `json:"displayName"`
	ExternalID  *string `json:"externalId"`
	Members     []struct {
		Value string `json:"value"`
	} `json:"members"`
}

func (a *App) memberIDs(ctx context.Context, org uuid.UUID, raw []string) []uuid.UUID {
	var out []uuid.UUID
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			continue
		}
		if _, err := a.Store.Membership(ctx, org, id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func (a *App) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	var in scimGroupIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.DisplayName) == "" {
		scimError(w, 400, "invalidValue", "displayName is required")
		return
	}
	g, err := a.Store.CreateSCIMGroup(ctx, org, strings.TrimSpace(in.DisplayName), in.ExternalID)
	if db.IsUniqueViolation(err) {
		scimError(w, 409, "uniqueness", "A group with this name already exists")
		return
	}
	if err != nil {
		scimError(w, 500, "", "Could not create group")
		return
	}
	var raw []string
	for _, m := range in.Members {
		raw = append(raw, m.Value)
	}
	ids := a.memberIDs(ctx, org, raw)
	_ = a.Store.SetSCIMGroupMembers(ctx, g.ID, ids)
	a.syncRoles(r, org, ids)
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.group_create", ResourceType: "group", ResourceID: g.ID.String(), ResourceName: g.DisplayName,
		Metadata: map[string]any{"members": len(ids)}})
	g, _ = a.Store.SCIMGroup(ctx, org, g.ID)
	scimJSON(w, 201, a.scimGroup(g))
}

func (a *App) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	g, ok := a.scimLoadGroup(w, r)
	if !ok {
		return
	}
	var in scimGroupIn
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		scimError(w, 400, "invalidSyntax", "Invalid JSON")
		return
	}
	_ = a.Store.UpdateSCIMGroup(ctx, org, g.ID, orStr(in.DisplayName, g.DisplayName), in.ExternalID)
	var raw []string
	for _, m := range in.Members {
		raw = append(raw, m.Value)
	}
	ids := a.memberIDs(ctx, org, raw)
	_ = a.Store.SetSCIMGroupMembers(ctx, g.ID, ids)
	a.syncRoles(r, org, append(ids, g.MemberIDs...))
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.group_update", ResourceType: "group", ResourceID: g.ID.String(), ResourceName: g.DisplayName})
	g, _ = a.Store.SCIMGroup(ctx, org, g.ID)
	scimJSON(w, 200, a.scimGroup(g))
}

func (a *App) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	g, ok := a.scimLoadGroup(w, r)
	if !ok {
		return
	}
	var p scimPatch
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		scimError(w, 400, "invalidSyntax", "Invalid JSON")
		return
	}
	affected := append([]uuid.UUID{}, g.MemberIDs...)
	for _, op := range p.Operations {
		opName := strings.ToLower(op.Op)
		path := op.Path
		lower := strings.ToLower(path)
		var vals []struct {
			Value string `json:"value"`
		}
		_ = json.Unmarshal(op.Value, &vals)
		raw := make([]string, 0, len(vals))
		for _, v := range vals {
			raw = append(raw, v.Value)
		}
		switch {
		case lower == "members" && opName == "add":
			ids := a.memberIDs(ctx, org, raw)
			_ = a.Store.AddSCIMGroupMembers(ctx, g.ID, ids)
			affected = append(affected, ids...)
		case lower == "members" && opName == "replace":
			ids := a.memberIDs(ctx, org, raw)
			_ = a.Store.SetSCIMGroupMembers(ctx, g.ID, ids)
			affected = append(affected, ids...)
		case lower == "members" && opName == "remove" && len(raw) > 0:
			var ids []uuid.UUID
			for _, s := range raw {
				if id, err := uuid.Parse(s); err == nil {
					ids = append(ids, id)
				}
			}
			_ = a.Store.RemoveSCIMGroupMembers(ctx, g.ID, ids)
		case strings.HasPrefix(lower, "members[") && opName == "remove":
			// members[value eq "id"]
			if i := strings.Index(path, `"`); i >= 0 {
				if j := strings.LastIndex(path, `"`); j > i {
					if id, err := uuid.Parse(path[i+1 : j]); err == nil {
						_ = a.Store.RemoveSCIMGroupMembers(ctx, g.ID, []uuid.UUID{id})
					}
				}
			}
		case lower == "displayname" || (lower == "" && opName == "replace"):
			var name string
			if json.Unmarshal(op.Value, &name) != nil {
				var obj struct {
					DisplayName string `json:"displayName"`
				}
				_ = json.Unmarshal(op.Value, &obj)
				name = obj.DisplayName
			}
			if strings.TrimSpace(name) != "" {
				_ = a.Store.UpdateSCIMGroup(ctx, org, g.ID, strings.TrimSpace(name), g.ExternalID)
			}
		}
	}
	a.syncRoles(r, org, affected)
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.group_update", ResourceType: "group", ResourceID: g.ID.String(), ResourceName: g.DisplayName})
	g, _ = a.Store.SCIMGroup(ctx, org, g.ID)
	scimJSON(w, 200, a.scimGroup(g))
}

func (a *App) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := scimOrg(ctx)
	g, ok := a.scimLoadGroup(w, r)
	if !ok {
		return
	}
	_, _ = a.Store.DeleteSCIMGroup(ctx, org, g.ID)
	a.syncRoles(r, org, g.MemberIDs)
	a.audit(r, auditEvent{OrgID: &org, Action: "scim.group_delete", ResourceType: "group", ResourceID: g.ID.String(), ResourceName: g.DisplayName})
	w.WriteHeader(204)
}

// syncRoles recomputes roles of IdP-managed members from their group memberships.
func (a *App) syncRoles(r *http.Request, org uuid.UUID, userIDs []uuid.UUID) {
	ctx := r.Context()
	conn, _ := a.Store.SSOConnectionForOrg(ctx, org)
	def := "viewer"
	var mappings []store.RoleMapping
	if conn != nil {
		def = orStr(conn.DefaultRole, "viewer")
		mappings = conn.RoleMappings
	}
	seen := map[uuid.UUID]bool{}
	for _, uid := range userIDs {
		if seen[uid] {
			continue
		}
		seen[uid] = true
		m, err := a.Store.Membership(ctx, org, uid)
		if err != nil || m.Role == "owner" || (m.Source != "scim" && m.Source != "sso") {
			continue
		}
		groups, err := a.Store.UserSCIMGroups(ctx, org, uid)
		if err != nil {
			continue
		}
		best := ""
		names := []string{}
		for _, g := range groups {
			names = append(names, g.DisplayName)
			if g.Role != nil && roleRank[*g.Role] > roleRank[best] {
				best = *g.Role
			}
		}
		if mapped := resolveRole(mappings, names, ""); roleRank[mapped] > roleRank[best] {
			best = mapped
		}
		if best == "" {
			best = def
		}
		if best != m.Role {
			_ = a.Store.SetMemberRole(ctx, org, uid, best)
			a.audit(r, auditEvent{OrgID: &org, Action: "member.role_sync", ResourceType: "member", ResourceID: uid.String(), ResourceName: m.UserEmail,
				Metadata: map[string]any{"from": m.Role, "to": best, "source": "scim"}})
		}
	}
}

// ---- Dashboard management of SCIM tokens & group role mapping ----

func (a *App) handleListSCIM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	tokens, err := a.Store.ListSCIMTokens(ctx, org.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	groups, _, err := a.Store.SCIMGroups(ctx, org.ID, "", 0, 1000)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": tokens, "groups": groups, "base_url": a.scimBase()})
}

func (a *App) handleCreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	act := actorFrom(ctx)
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		a.fail(w, r, errField("name", "Enter a name"))
		return
	}
	secret := "scim_" + secure.RandomToken(30)
	t, err := a.Store.CreateSCIMToken(ctx, org.ID, strings.TrimSpace(in.Name), secret[:11], secure.HashToken(secret), act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "scim.token_create", ResourceType: "scim_token", ResourceID: t.ID.String(), ResourceName: t.Name})
	writeJSON(w, 201, map[string]any{"token": t, "secret": secret})
}

func (a *App) handleDeleteSCIMToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		a.fail(w, r, errNotFound("Token"))
		return
	}
	ok, err := a.Store.DeleteSCIMToken(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.fail(w, r, errNotFound("Token"))
		return
	}
	a.audit(r, auditEvent{Action: "scim.token_revoke", ResourceType: "scim_token", ResourceID: id.String()})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleSetGroupRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "groupID"))
	if err != nil {
		a.fail(w, r, errNotFound("Group"))
		return
	}
	var in struct {
		Role *string `json:"role"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Role != nil && (*in.Role == "" || *in.Role == "owner" || !validRoles[*in.Role]) {
		a.fail(w, r, errField("role", "Choose admin, editor, viewer or auditor"))
		return
	}
	g, err := a.Store.SCIMGroup(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.SetSCIMGroupRole(ctx, org.ID, id, in.Role); err != nil {
		a.fail(w, r, err)
		return
	}
	a.syncRoles(r, org.ID, g.MemberIDs)
	a.audit(r, auditEvent{Action: "scim.group_role", ResourceType: "group", ResourceID: id.String(), ResourceName: g.DisplayName,
		Metadata: map[string]any{"role": in.Role}})
	g, _ = a.Store.SCIMGroup(ctx, org.ID, id)
	writeJSON(w, 200, g)
}
