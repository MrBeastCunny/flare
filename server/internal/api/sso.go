package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

var (
	providerMu    sync.Mutex
	providerCache = map[string]*cachedProvider{}
)

type cachedProvider struct {
	p       *oidc.Provider
	fetched time.Time
}

func oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	providerMu.Lock()
	defer providerMu.Unlock()
	if c, ok := providerCache[issuer]; ok && time.Since(c.fetched) < time.Hour {
		return c.p, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	providerCache[issuer] = &cachedProvider{p: p, fetched: time.Now()}
	return p, nil
}

func (a *App) ssoRedirectURL() string { return a.Cfg.PublicURL + "/api/v1/auth/sso/callback" }

func (a *App) oauthConfig(ctx context.Context, c *store.SSOConnection) (*oauth2.Config, *oidc.Provider, error) {
	p, err := oidcProvider(ctx, c.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("discover identity provider: %w", err)
	}
	secret, err := a.Box.Open(c.ClientSecretEnc)
	if err != nil {
		return nil, nil, err
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &oauth2.Config{ClientID: c.ClientID, ClientSecret: secret, Endpoint: p.Endpoint(), RedirectURL: a.ssoRedirectURL(), Scopes: scopes}, p, nil
}

// handleSSODiscover resolves an email address to an SSO connection by verified domain.
func (a *App) handleSSODiscover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Redirect string `json:"redirect"`
	}
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	conn, err := a.Store.SSOConnectionForDomain(r.Context(), emailDomain(strings.ToLower(strings.TrimSpace(req.Email))))
	if errors.Is(err, db.ErrNotFound) {
		writeJSON(w, 200, map[string]any{"sso": false})
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	u := "/api/v1/auth/sso/" + conn.ID.String() + "/start"
	if p := safeRedirect(req.Redirect); p != "/" {
		u += "?redirect=" + url.QueryEscape(p)
	}
	writeJSON(w, 200, map[string]any{"sso": true, "url": u, "enforced": conn.EnforceSSO})
}

func (a *App) handleSSOStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := uuid.Parse(chi.URLParam(r, "connID"))
	if err != nil {
		a.ssoError(w, r, "Unknown SSO connection.")
		return
	}
	conn, err := a.Store.SSOConnectionByID(ctx, id)
	if err != nil || !conn.Enabled {
		a.ssoError(w, r, "Single sign-on is not available for this organization.")
		return
	}
	cfg, _, err := a.oauthConfig(ctx, conn)
	if err != nil {
		a.Log.Error("sso start", "err", err, "connection", conn.ID)
		a.ssoError(w, r, "The identity provider could not be reached.")
		return
	}
	state := secure.RandomToken(24)
	nonce := secure.RandomToken(24)
	verifier := oauth2.GenerateVerifier()
	if err := a.Store.CreateSSOState(ctx, state, conn.ID, nonce, verifier, safeRedirect(r.URL.Query().Get("redirect"))); err != nil {
		a.ssoError(w, r, "Could not start single sign-on.")
		return
	}
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (a *App) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		msg := q.Get("error_description")
		if msg == "" {
			msg = e
		}
		a.ssoError(w, r, "Identity provider returned an error: "+msg)
		return
	}
	connID, nonce, verifier, redirect, err := a.Store.ConsumeSSOState(ctx, q.Get("state"))
	if err != nil {
		a.ssoError(w, r, "Your sign-in attempt expired. Try again.")
		return
	}
	conn, err := a.Store.SSOConnectionByID(ctx, connID)
	if err != nil || !conn.Enabled {
		a.ssoError(w, r, "Single sign-on is not available for this organization.")
		return
	}
	cfg, provider, err := a.oauthConfig(ctx, conn)
	if err != nil {
		a.ssoError(w, r, "The identity provider could not be reached.")
		return
	}
	tok, err := cfg.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		a.Log.Warn("sso exchange", "err", err)
		a.ssoError(w, r, "Could not complete sign-in with your identity provider.")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		a.ssoError(w, r, "The identity provider did not return an ID token.")
		return
	}
	idt, err := provider.Verifier(&oidc.Config{ClientID: conn.ClientID}).Verify(ctx, rawID)
	if err != nil || idt.Nonce != nonce {
		a.ssoError(w, r, "The identity token could not be verified.")
		return
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		a.ssoError(w, r, "The identity token could not be read.")
		return
	}
	// Merge userinfo claims (some IdPs only expose groups there).
	if ui, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
		extra := map[string]any{}
		if ui.Claims(&extra) == nil {
			for k, v := range extra {
				if _, ok := claims[k]; !ok {
					claims[k] = v
				}
			}
		}
	}
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		a.ssoError(w, r, "Your identity provider did not share an email address.")
		return
	}
	if v, ok := claims["email_verified"].(bool); ok && !v {
		a.ssoError(w, r, "Your email address is not verified with your identity provider.")
		return
	}
	// The email domain must be verified by this organization; this prevents an IdP from
	// asserting identities it does not own.
	domains, err := a.Store.ListSSODomains(ctx, conn.OrgID)
	if err != nil {
		a.ssoError(w, r, "Could not complete sign-in.")
		return
	}
	domainOK := false
	for _, d := range domains {
		if d.VerifiedAt != nil && strings.EqualFold(d.Domain, emailDomain(email)) {
			domainOK = true
		}
	}
	if !domainOK {
		a.ssoError(w, r, fmt.Sprintf("The domain %s is not verified for single sign-on in this organization.", emailDomain(email)))
		return
	}
	name, _ := claims["name"].(string)
	groups := claimStrings(claims[conn.GroupsClaim])
	role := resolveRole(conn.RoleMappings, groups, conn.DefaultRole)

	u, err := a.Store.UserByEmail(ctx, email)
	if errors.Is(err, db.ErrNotFound) {
		if !conn.JITProvisioning {
			a.ssoError(w, r, "Your account has not been provisioned. Ask your administrator for access.")
			return
		}
		u, err = a.Store.CreateUser(ctx, store.NewUser{Email: email, Name: name, EmailVerified: true, CreatedVia: "sso"})
	}
	if err != nil {
		a.ssoError(w, r, "Could not complete sign-in.")
		return
	}
	if u.Disabled {
		a.ssoError(w, r, "Your account has been disabled.")
		return
	}
	if u.Name == "" && name != "" {
		_ = a.Store.UpdateUserProfile(ctx, u.ID, name, u.Preferences)
	}
	m, err := a.Store.Membership(ctx, conn.OrgID, u.ID)
	switch {
	case errors.Is(err, db.ErrNotFound):
		if !conn.JITProvisioning {
			a.ssoError(w, r, "You are not a member of this organization. Ask your administrator for access.")
			return
		}
		if err := a.Store.AddMember(ctx, conn.OrgID, u.ID, role, nil, "sso"); err != nil {
			a.ssoError(w, r, "Could not complete sign-in.")
			return
		}
		a.audit(r, auditEvent{OrgID: &conn.OrgID, Action: "member.join", ResourceType: "member", ResourceID: u.ID.String(),
			ResourceName: u.Email, ActorUser: u, Metadata: map[string]any{"role": role, "via": "sso"}})
	case err != nil:
		a.ssoError(w, r, "Could not complete sign-in.")
		return
	default:
		// Keep roles in sync with IdP groups when mappings exist; never demote the last owner.
		if len(conn.RoleMappings) > 0 && m.Role != role && m.Source == "sso" {
			if m.Role != "owner" {
				_ = a.Store.SetMemberRole(ctx, conn.OrgID, u.ID, role)
				a.audit(r, auditEvent{OrgID: &conn.OrgID, Action: "member.role_sync", ResourceType: "member", ResourceID: u.ID.String(),
					ResourceName: u.Email, ActorType: "system", ActorLabel: "SSO", Metadata: map[string]any{"from": m.Role, "to": role}})
			}
		}
	}
	if err := a.startSession(w, r, u, "sso", &conn.ID); err != nil {
		a.ssoError(w, r, "Could not complete sign-in.")
		return
	}
	a.audit(r, auditEvent{OrgID: &conn.OrgID, Action: "auth.login", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email,
		ActorUser: u, Metadata: map[string]any{"method": "sso", "issuer": conn.Issuer}})
	if redirect == "/" || redirect == "" {
		redirect = "/" + conn.OrgID.String()
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (a *App) ssoError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(msg), http.StatusFound)
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// resolveRole picks the highest role granted by any matching group mapping.
func resolveRole(mappings []store.RoleMapping, groups []string, def string) string {
	best := ""
	for _, m := range mappings {
		for _, g := range groups {
			if strings.EqualFold(m.Group, g) && roleRank[m.Role] > roleRank[best] {
				best = m.Role
			}
		}
	}
	if best == "" {
		return def
	}
	return best
}

func safeRedirect(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") || strings.HasPrefix(p, "/api/") {
		return "/"
	}
	return p
}

// ---- Org-level SSO configuration ----

func (a *App) handleGetSSO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	conn, err := a.Store.SSOConnectionForOrg(ctx, org.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	domains, err := a.Store.ListSSODomains(ctx, org.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"connection":   conn,
		"domains":      domains,
		"redirect_uri": a.ssoRedirectURL(),
		"login_url": func() string {
			if conn == nil {
				return ""
			}
			return a.Cfg.PublicURL + "/api/v1/auth/sso/" + conn.ID.String() + "/start"
		}(),
	})
}

type ssoInput struct {
	Name            string              `json:"name"`
	Issuer          string              `json:"issuer"`
	ClientID        string              `json:"client_id"`
	ClientSecret    string              `json:"client_secret"`
	Scopes          []string            `json:"scopes"`
	GroupsClaim     string              `json:"groups_claim"`
	RoleMappings    []store.RoleMapping `json:"role_mappings"`
	DefaultRole     string              `json:"default_role"`
	JITProvisioning bool                `json:"jit_provisioning"`
	EnforceSSO      bool                `json:"enforce_sso"`
	Enabled         bool                `json:"enabled"`
}

func (a *App) handlePutSSO(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	var in ssoInput
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	fields := map[string]string{}
	in.Issuer = strings.TrimRight(strings.TrimSpace(in.Issuer), "/")
	if u, err := url.Parse(in.Issuer); err != nil || u.Scheme != "https" && !(a.Cfg.DevMode && u.Scheme == "http") || u.Host == "" {
		fields["issuer"] = "Issuer must be an https URL"
	}
	if strings.TrimSpace(in.ClientID) == "" {
		fields["client_id"] = "Client ID is required"
	}
	if in.DefaultRole == "" {
		in.DefaultRole = "viewer"
	}
	if !validRoles[in.DefaultRole] || in.DefaultRole == "owner" {
		fields["default_role"] = "Choose admin, editor, viewer or auditor"
	}
	for _, m := range in.RoleMappings {
		if strings.TrimSpace(m.Group) == "" || !validRoles[m.Role] || m.Role == "owner" {
			fields["role_mappings"] = "Each mapping needs a group and a role other than owner"
		}
	}
	existing, err := a.Store.SSOConnectionForOrg(ctx, org.ID)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	secretEnc := ""
	if in.ClientSecret != "" {
		if secretEnc, err = a.Box.Seal(in.ClientSecret); err != nil {
			a.fail(w, r, err)
			return
		}
	} else if existing != nil {
		secretEnc = existing.ClientSecretEnc
	} else {
		fields["client_secret"] = "Client secret is required"
	}
	if len(fields) > 0 {
		a.fail(w, r, errValidation(fields))
		return
	}
	if _, err := oidcProvider(ctx, in.Issuer); err != nil {
		a.fail(w, r, errField("issuer", "Could not load OpenID configuration from this issuer: "+err.Error()))
		return
	}
	if in.EnforceSSO {
		domains, _ := a.Store.ListSSODomains(ctx, org.ID)
		verified := false
		for _, d := range domains {
			verified = verified || d.VerifiedAt != nil
		}
		if !verified {
			a.fail(w, r, errField("enforce_sso", "Verify at least one domain before enforcing SSO"))
			return
		}
	}
	if in.GroupsClaim == "" {
		in.GroupsClaim = "groups"
	}
	if in.RoleMappings == nil {
		in.RoleMappings = []store.RoleMapping{}
	}
	conn, err := a.Store.UpsertSSOConnection(ctx, store.SSOConnection{OrgID: org.ID, Name: orStr(in.Name, "OpenID Connect"), Issuer: in.Issuer,
		ClientID: strings.TrimSpace(in.ClientID), ClientSecretEnc: secretEnc, Scopes: in.Scopes, GroupsClaim: in.GroupsClaim,
		RoleMappings: in.RoleMappings, DefaultRole: in.DefaultRole, JITProvisioning: in.JITProvisioning, EnforceSSO: in.EnforceSSO, Enabled: in.Enabled})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	action := "sso.update"
	if existing == nil {
		action = "sso.create"
	}
	a.audit(r, auditEvent{Action: action, ResourceType: "sso_connection", ResourceID: conn.ID.String(), ResourceName: conn.Issuer,
		Metadata: map[string]any{"enforce_sso": in.EnforceSSO, "enabled": in.Enabled, "jit": in.JITProvisioning, "default_role": in.DefaultRole,
			"role_mappings": in.RoleMappings, "secret_rotated": in.ClientSecret != ""}})
	writeJSON(w, 200, conn)
}

func (a *App) handleDeleteSSO(w http.ResponseWriter, r *http.Request) {
	org := orgFrom(r.Context())
	if err := a.Store.DeleteSSOConnection(r.Context(), org.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "sso.delete", ResourceType: "sso_connection", ResourceName: org.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleAddSSODomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	var in struct {
		Domain string `json:"domain"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	fq, err := dnsutil.CanonicalZone(in.Domain)
	if err != nil {
		a.fail(w, r, errField("domain", err.Error()))
		return
	}
	domain := strings.TrimSuffix(fq, ".")
	// Domains already hosted and active in this org are verified implicitly.
	verified := false
	if z, err := a.Store.ZoneByName(ctx, fq); err == nil && z.OrgID == org.ID && z.Status == "active" {
		verified = true
	}
	d, err := a.Store.CreateSSODomain(ctx, org.ID, domain, "flare-verify="+secure.RandomToken(18), verified)
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("domain", "This domain is already claimed by an organization"))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "sso.domain_add", ResourceType: "sso_domain", ResourceID: d.ID.String(), ResourceName: domain})
	writeJSON(w, 201, d)
}

func (a *App) handleVerifySSODomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		a.fail(w, r, errNotFound("Domain"))
		return
	}
	d, err := a.Store.SSODomainByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if d.VerifiedAt == nil {
		res := &dnsutil.Resolver{Addr: a.Cfg.DNSResolver}
		txts, err := res.LookupTXT(ctx, "_flare-challenge."+d.Domain)
		if err != nil {
			a.fail(w, r, errCode(502, "lookup_failed", "DNS lookup failed: "+err.Error()))
			return
		}
		found := false
		for _, t := range txts {
			if strings.TrimSpace(t) == d.VerificationToken {
				found = true
			}
		}
		if !found {
			a.fail(w, r, errCode(422, "not_verified", fmt.Sprintf("TXT record not found at _flare-challenge.%s yet. DNS changes can take a few minutes to propagate.", d.Domain)))
			return
		}
		if err := a.Store.VerifySSODomain(ctx, d.ID); err != nil {
			a.fail(w, r, err)
			return
		}
		a.audit(r, auditEvent{Action: "sso.domain_verify", ResourceType: "sso_domain", ResourceID: d.ID.String(), ResourceName: d.Domain})
	}
	d, _ = a.Store.SSODomainByID(ctx, org.ID, id)
	writeJSON(w, 200, d)
}

func (a *App) handleDeleteSSODomain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		a.fail(w, r, errNotFound("Domain"))
		return
	}
	d, err := a.Store.SSODomainByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.Store.DeleteSSODomain(ctx, org.ID, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "sso.domain_remove", ResourceType: "sso_domain", ResourceID: d.ID.String(), ResourceName: d.Domain})
	writeJSON(w, 200, map[string]any{"ok": true})
}
