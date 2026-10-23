// Package api implements the Flare HTTP API.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/flare-dns/flare/internal/config"
	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/mail"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/google/uuid"
)

type App struct {
	Cfg    *config.Config
	Store  *store.Store
	Box    *secure.Box
	Log    *slog.Logger
	Mailer *mail.Mailer

	limiter *rateLimiter

	settingsMu     sync.RWMutex
	settingsCache  *store.InstanceSettings
	settingsLoaded time.Time
}

func New(cfg *config.Config, st *store.Store, box *secure.Box, log *slog.Logger) *App {
	a := &App{Cfg: cfg, Store: st, Box: box, Log: log, limiter: newRateLimiter()}
	a.Mailer = mail.New(func(ctx context.Context) (mail.Config, error) { return a.mailConfig(ctx) })
	return a
}

// Settings returns cached instance settings (refreshed every 10s or on save).
func (a *App) Settings(ctx context.Context) store.InstanceSettings {
	a.settingsMu.RLock()
	if a.settingsCache != nil && time.Since(a.settingsLoaded) < 10*time.Second {
		s := *a.settingsCache
		a.settingsMu.RUnlock()
		return s
	}
	a.settingsMu.RUnlock()
	s, err := a.Store.InstanceSettings(ctx)
	if err != nil {
		a.Log.Error("load settings", "err", err)
	}
	a.settingsMu.Lock()
	a.settingsCache = &s
	a.settingsLoaded = time.Now()
	a.settingsMu.Unlock()
	return s
}

func (a *App) SaveSettings(ctx context.Context, s store.InstanceSettings) error {
	if err := a.Store.SaveInstanceSettings(ctx, s); err != nil {
		return err
	}
	a.settingsMu.Lock()
	a.settingsCache = &s
	a.settingsLoaded = time.Now()
	a.settingsMu.Unlock()
	return nil
}

func (a *App) mailConfig(ctx context.Context) (mail.Config, error) {
	s := a.Settings(ctx)
	if s.SMTP.Host != "" {
		pw := ""
		if s.SMTP.PasswordEnc != "" {
			var err error
			if pw, err = a.Box.Open(s.SMTP.PasswordEnc); err != nil {
				return mail.Config{}, err
			}
		}
		return mail.Config{Host: s.SMTP.Host, Port: s.SMTP.Port, Username: s.SMTP.Username, Password: pw,
			From: s.SMTP.From, TLS: s.SMTP.TLS, InstanceName: s.InstanceName}, nil
	}
	return mail.Config{Host: a.Cfg.SMTPHost, Port: a.Cfg.SMTPPort, Username: a.Cfg.SMTPUsername, Password: a.Cfg.SMTPPassword,
		From: a.Cfg.SMTPFrom, TLS: a.Cfg.SMTPTLS, InstanceName: s.InstanceName}, nil
}

// PDNS returns a client for the given server record.
func (a *App) PDNS(srv *store.PDNSServer) (*pdns.Client, error) {
	key, err := a.Box.Open(srv.APIKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt api key for server %s: %w", srv.Name, err)
	}
	return pdns.New(srv.APIURL, key, srv.ServerID), nil
}

func (a *App) PDNSForZone(ctx context.Context, z *store.Zone) (*pdns.Client, error) {
	srv, err := a.Store.ServerByID(ctx, z.PDNSServerID)
	if err != nil {
		return nil, err
	}
	return a.PDNS(srv)
}

// ---- Errors & responses ----

type apiError struct {
	Status  int               `json:"-"`
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

func (e *apiError) Error() string { return e.Message }

func errBadRequest(msg string) *apiError {
	return &apiError{Status: 400, Code: "bad_request", Message: msg}
}
func errValidation(fields map[string]string) *apiError {
	msg := "Validation failed"
	for _, v := range fields {
		msg = v
		break
	}
	return &apiError{Status: 422, Code: "validation_failed", Message: msg, Fields: fields}
}
func errField(field, msg string) *apiError { return errValidation(map[string]string{field: msg}) }
func errUnauthorized(msg string) *apiError {
	return &apiError{Status: 401, Code: "unauthorized", Message: msg}
}
func errForbidden(msg string) *apiError {
	return &apiError{Status: 403, Code: "forbidden", Message: msg}
}
func errNotFound(what string) *apiError {
	return &apiError{Status: 404, Code: "not_found", Message: what + " not found"}
}
func errConflict(msg string) *apiError { return &apiError{Status: 409, Code: "conflict", Message: msg} }
func errCode(status int, code, msg string) *apiError {
	return &apiError{Status: status, Code: code, Message: msg}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func (a *App) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *apiError
	var pe *pdns.Error
	switch {
	case errors.As(err, &ae):
	case errors.Is(err, db.ErrNotFound):
		ae = errNotFound("Resource")
	case errors.As(err, &pe):
		status := http.StatusBadGateway
		if pe.Status == 422 || pe.Status == 400 {
			status = 422
		} else if pe.Status == 409 {
			status = 409
		} else if pe.Status == 404 {
			status = 404
		}
		ae = &apiError{Status: status, Code: "powerdns_error", Message: pe.Message}
	case errors.Is(err, context.Canceled):
		return
	default:
		a.Log.Error("request failed", "err", err, "path", r.URL.Path, "method", r.Method, "request_id", requestID(r.Context()))
		ae = &apiError{Status: 500, Code: "internal_error", Message: "Something went wrong. Please try again."}
		if strings.Contains(err.Error(), "powerdns:") {
			ae = &apiError{Status: 502, Code: "powerdns_unreachable", Message: "The DNS server could not be reached. " + err.Error()}
		}
	}
	writeJSON(w, ae.Status, map[string]any{"error": ae})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errBadRequest("Invalid request body: " + err.Error())
	}
	return nil
}

// ---- Context ----

type ctxKey int

const (
	keyActor ctxKey = iota
	keyOrg
	keyMembership
	keyZone
	keyRequestID
)

// Actor is whoever performs a request.
type Actor struct {
	Type    string // user | api_token | scim | system
	User    *store.User
	Session *store.Session
	Token   *store.APIToken
	OrgID   *uuid.UUID // set for api_token and scim actors
	ID      *uuid.UUID
	Label   string
}

func actorFrom(ctx context.Context) *Actor {
	a, _ := ctx.Value(keyActor).(*Actor)
	return a
}

func orgFrom(ctx context.Context) *store.Org {
	o, _ := ctx.Value(keyOrg).(*store.Org)
	return o
}

// access describes the effective permissions of the actor in the current org.
type access struct {
	Role    string
	ZoneIDs []uuid.UUID // nil = all zones
	// ViaInstance is set when the access comes from instance administration rather than
	// membership: an instance administrator outside the organization, or a global API token.
	ViaInstance bool
}

func accessFrom(ctx context.Context) *access {
	m, _ := ctx.Value(keyMembership).(*access)
	return m
}

func zoneFrom(ctx context.Context) *store.Zone {
	z, _ := ctx.Value(keyZone).(*store.Zone)
	return z
}

func requestID(ctx context.Context) string {
	s, _ := ctx.Value(keyRequestID).(string)
	return s
}

// ---- Roles & permissions ----

type Perm string

const (
	PermOrgRead        Perm = "org.read"
	PermOrgUpdate      Perm = "org.update"
	PermOrgDelete      Perm = "org.delete"
	PermMembersRead    Perm = "members.read"
	PermMembersManage  Perm = "members.manage"
	PermZonesRead      Perm = "zones.read"
	PermZonesCreate    Perm = "zones.create"
	PermZonesEdit      Perm = "zones.edit"
	PermZonesDelete    Perm = "zones.delete"
	PermDNSEdit        Perm = "dns.edit"
	PermAuditRead      Perm = "audit.read"
	PermTokensManage   Perm = "tokens.manage"
	PermSSOManage      Perm = "sso.manage"
	PermWebhooksManage Perm = "webhooks.manage"
)

var rolePerms = map[string][]Perm{
	"owner": {PermOrgRead, PermOrgUpdate, PermOrgDelete, PermMembersRead, PermMembersManage, PermZonesRead, PermZonesCreate,
		PermZonesEdit, PermZonesDelete, PermDNSEdit, PermAuditRead, PermTokensManage, PermSSOManage, PermWebhooksManage},
	"admin": {PermOrgRead, PermOrgUpdate, PermMembersRead, PermMembersManage, PermZonesRead, PermZonesCreate,
		PermZonesEdit, PermZonesDelete, PermDNSEdit, PermAuditRead, PermTokensManage, PermSSOManage, PermWebhooksManage},
	"editor":  {PermOrgRead, PermMembersRead, PermZonesRead, PermZonesCreate, PermZonesEdit, PermDNSEdit},
	"viewer":  {PermOrgRead, PermMembersRead, PermZonesRead},
	"auditor": {PermOrgRead, PermMembersRead, PermZonesRead, PermAuditRead},
}

// Token roles never include creating tokens, SSO or deleting the organization, so a token cannot
// mint credentials or grant itself more access.
var tokenRolePerms = map[string][]Perm{
	"org_admin": {PermOrgRead, PermOrgUpdate, PermMembersRead, PermMembersManage, PermZonesRead, PermZonesCreate, PermZonesEdit,
		PermZonesDelete, PermDNSEdit, PermAuditRead, PermWebhooksManage},
	"admin":  {PermOrgRead, PermMembersRead, PermZonesRead, PermZonesCreate, PermZonesEdit, PermZonesDelete, PermDNSEdit, PermAuditRead},
	"editor": {PermOrgRead, PermZonesRead, PermZonesEdit, PermDNSEdit},
	"viewer": {PermOrgRead, PermZonesRead},
}

// Instance roles give global tokens access to the admin API: "orgs" manages organizations,
// "admin" can use every admin endpoint except creating tokens.
var instanceRoleRank = map[string]int{"none": 0, "orgs": 1, "admin": 2}

var validRoles = map[string]bool{"owner": true, "admin": true, "editor": true, "viewer": true, "auditor": true}
var roleRank = map[string]int{"viewer": 1, "auditor": 1, "editor": 2, "admin": 3, "owner": 4}

func (a *App) can(ctx context.Context, p Perm) bool {
	acc := accessFrom(ctx)
	if acc == nil {
		return false
	}
	table := rolePerms
	if act := actorFrom(ctx); act != nil && act.Type == "api_token" {
		table = tokenRolePerms
	}
	for _, x := range table[acc.Role] {
		if x == p {
			return true
		}
	}
	return false
}

func permsFor(role string, token bool) []Perm {
	if token {
		return tokenRolePerms[role]
	}
	return rolePerms[role]
}

func (a *App) require(ctx context.Context, p Perm) error {
	if !a.can(ctx, p) {
		return errForbidden("You do not have permission to perform this action.")
	}
	return nil
}

// actorUserID returns the signed-in user's ID, or nil for tokens and system actors.
func actorUserID(ctx context.Context) *uuid.UUID {
	if act := actorFrom(ctx); act != nil && act.Type == "user" {
		return &act.User.ID
	}
	return nil
}

// tokenInstanceAdmin reports whether tok is a global token with full instance access. Like an
// instance administrator, it is not blocked by organization suspension or IP rules.
func tokenInstanceAdmin(tok *store.APIToken) bool {
	return tok.OrgID == nil && tok.InstanceRole == "admin"
}

// tokenScope checks that tok may act in org and returns its access there.
func tokenScope(tok *store.APIToken, org *store.Org) (*access, error) {
	switch {
	case tok.OrgID != nil && *tok.OrgID != org.ID:
		return nil, errNotFound("Organization")
	case tok.OrgID == nil && tok.OrgIDs != nil && !slices.Contains(tok.OrgIDs, org.ID):
		return nil, errNotFound("Organization")
	case org.Suspended && !tokenInstanceAdmin(tok):
		return nil, errCode(403, "org_suspended", "This organization has been suspended. Contact your administrator.")
	}
	return &access{Role: tok.Role, ZoneIDs: tok.ZoneIDs, ViaInstance: tok.OrgID == nil}, nil
}

// tokenAccess is tokenScope plus the organization's IP allowlist.
func (a *App) tokenAccess(r *http.Request, tok *store.APIToken, org *store.Org) (*access, error) {
	acc, err := tokenScope(tok, org)
	if err != nil {
		return nil, err
	}
	if len(org.IPAllowlist) > 0 && !tokenInstanceAdmin(tok) && !ipAllowed(a.clientIP(r), org.IPAllowlist) {
		return nil, errCode(403, "ip_not_allowed", "Access to this organization is restricted to approved networks.")
	}
	return acc, nil
}

func zoneAllowed(acc *access, zoneID uuid.UUID) bool {
	if acc == nil {
		return false
	}
	if acc.ZoneIDs == nil {
		return true
	}
	for _, id := range acc.ZoneIDs {
		if id == zoneID {
			return true
		}
	}
	return false
}
