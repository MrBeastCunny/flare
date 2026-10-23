package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

type meOrg struct {
	store.OrgMembership
	Permissions []Perm `json:"permissions"`
	SSOEnforced bool   `json:"sso_enforced"`
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	a.ensureCSRFCookie(w, r)
	u, err := a.Store.UserByID(ctx, act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	orgs, err := a.Store.OrgsForUser(ctx, u.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]meOrg, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, meOrg{OrgMembership: o, Permissions: permsFor(o.Role, false)})
	}
	s := a.Settings(ctx)
	mfaRequired := !u.TOTPEnabled && act.Session.AuthMethod != "sso" && (s.RequireMFA || anyOrgEnforcesMFA(orgs))
	writeJSON(w, 200, map[string]any{
		"user":               u,
		"orgs":               out,
		"has_password":       u.HasPassword(),
		"auth_method":        act.Session.AuthMethod,
		"session_id":         act.Session.ID,
		"mfa_setup_required": mfaRequired,
		"needs_onboarding":   u.OnboardedAt == nil,
		"can_create_org":     s.AllowOrgCreation || u.IsSuperadmin,
		"instance_name":      s.InstanceName,
		"announcement":       s.AnnouncementBanner,
	})
}

func anyOrgEnforcesMFA(orgs []store.OrgMembership) bool {
	for _, o := range orgs {
		if o.EnforceMFA {
			return true
		}
	}
	return false
}

func (a *App) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	var in struct {
		Name        *string          `json:"name"`
		Preferences *json.RawMessage `json:"preferences"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	name := act.User.Name
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
		if len(name) > 120 {
			a.fail(w, r, errField("name", "Name is too long"))
			return
		}
	}
	prefs := act.User.Preferences
	if in.Preferences != nil {
		prefs = *in.Preferences
	}
	if err := a.Store.UpdateUserProfile(ctx, act.User.ID, name, prefs); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Name != nil && name != act.User.Name {
		a.audit(r, auditEvent{Action: "user.update", ResourceType: "user", ResourceID: act.User.ID.String(), ResourceName: act.User.Email,
			Metadata: map[string]any{"name": map[string]string{"from": act.User.Name, "to": name}}})
	}
	u, _ := a.Store.UserByID(ctx, act.User.ID)
	writeJSON(w, 200, u)
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	var in struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	u := act.User
	if u.HasPassword() && !secure.VerifyPassword(in.CurrentPassword, *u.PasswordHash) {
		a.fail(w, r, errField("current_password", "Current password is incorrect"))
		return
	}
	if err := a.checkPassword(in.NewPassword, u.Email, a.Settings(ctx)); err != nil {
		a.fail(w, r, errField("new_password", err.Error()))
		return
	}
	hash, err := secure.HashPassword(in.NewPassword)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.SetUserPassword(ctx, u.ID, hash); err != nil {
		a.fail(w, r, err)
		return
	}
	_ = a.Store.DeleteUserSessions(ctx, u.ID, &act.Session.ID)
	a.audit(r, auditEvent{Action: "user.password_change", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- TOTP ----

func (a *App) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	if act.User.TOTPEnabled {
		a.fail(w, r, errConflict("Two-factor authentication is already enabled."))
		return
	}
	s := a.Settings(ctx)
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.InstanceName, AccountName: act.User.Email})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	enc, err := a.Box.Seal(key.Secret())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.SetUserTOTP(ctx, act.User.ID, &enc, false, nil); err != nil {
		a.fail(w, r, err)
		return
	}
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 240)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"secret":      key.Secret(),
		"otpauth_url": key.URL(),
		"qr_code":     "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
	})
}

func newRecoveryCodes() (plain []string, hashed []string) {
	for i := 0; i < 10; i++ {
		c := secure.RandomCode(8)
		plain = append(plain, c)
		hashed = append(hashed, hashRecovery(c))
	}
	return
}

func (a *App) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.Store.UserByID(ctx, act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if u.TOTPEnabled {
		a.fail(w, r, errConflict("Two-factor authentication is already enabled."))
		return
	}
	if u.TOTPSecret == nil {
		a.fail(w, r, errBadRequest("Start setup first."))
		return
	}
	secret, err := a.Box.Open(*u.TOTPSecret)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !totp.Validate(strings.TrimSpace(in.Code), secret) {
		a.fail(w, r, errField("code", "That code is not valid. Make sure your device clock is correct."))
		return
	}
	plain, hashed := newRecoveryCodes()
	if err := a.Store.SetUserTOTP(ctx, u.ID, u.TOTPSecret, true, hashed); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "user.mfa_enable", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email})
	writeJSON(w, 200, map[string]any{"recovery_codes": plain})
}

func (a *App) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.Store.UserByID(ctx, act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !u.TOTPEnabled {
		a.fail(w, r, errConflict("Two-factor authentication is not enabled."))
		return
	}
	if a.Settings(ctx).RequireMFA {
		a.fail(w, r, errForbidden("Two-factor authentication is required on this instance and cannot be disabled."))
		return
	}
	ok, _, err := a.verifySecondFactor(ctx, u, in.Code)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.fail(w, r, errField("code", "That code is not valid."))
		return
	}
	if err := a.Store.SetUserTOTP(ctx, u.ID, nil, false, nil); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "user.mfa_disable", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	var in struct {
		Code string `json:"code"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.Store.UserByID(ctx, act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ok, _, err := a.verifySecondFactor(ctx, u, in.Code)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.fail(w, r, errField("code", "That code is not valid."))
		return
	}
	plain, hashed := newRecoveryCodes()
	if err := a.Store.SetRecoveryCodes(ctx, u.ID, hashed); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "user.recovery_codes_regenerate", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email})
	writeJSON(w, 200, map[string]any{"recovery_codes": plain})
}

// ---- Sessions ----

func (a *App) handleListSessions(w http.ResponseWriter, r *http.Request) {
	act := actorFrom(r.Context())
	list, err := a.Store.ListSessions(r.Context(), act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type item struct {
		store.Session
		Current bool `json:"current"`
	}
	out := make([]item, 0, len(list))
	for _, s := range list {
		out = append(out, item{Session: s, Current: s.ID == act.Session.ID})
	}
	writeJSON(w, 200, out)
}

func (a *App) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	act := actorFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "sessionID"))
	if err != nil {
		a.fail(w, r, errNotFound("Session"))
		return
	}
	ok, err := a.Store.DeleteSession(r.Context(), act.User.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.fail(w, r, errNotFound("Session"))
		return
	}
	a.audit(r, auditEvent{Action: "user.session_revoke", ResourceType: "session", ResourceID: id.String(), ResourceName: act.User.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	act := actorFrom(r.Context())
	if err := a.Store.DeleteUserSessions(r.Context(), act.User.ID, &act.Session.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "user.session_revoke_all", ResourceType: "user", ResourceID: act.User.ID.String(), ResourceName: act.User.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleCompleteOnboarding(w http.ResponseWriter, r *http.Request) {
	act := actorFrom(r.Context())
	if err := a.Store.MarkOnboarded(r.Context(), act.User.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDeleteMe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(in.Confirm), act.User.Email) {
		a.fail(w, r, errField("confirm", "Type your email address to confirm"))
		return
	}
	orgs, err := a.Store.OrgsForUser(ctx, act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	for _, o := range orgs {
		if o.Role == "owner" {
			n, _ := a.Store.CountOwners(ctx, o.ID)
			if n <= 1 {
				a.fail(w, r, errConflict("You are the only owner of "+o.Name+". Transfer ownership or delete the organization first."))
				return
			}
		}
	}
	if act.User.IsSuperadmin {
		if n, _ := a.Store.CountSuperadmins(ctx); n <= 1 {
			a.fail(w, r, errConflict("You are the only instance administrator. Promote another administrator first."))
			return
		}
	}
	a.audit(r, auditEvent{Action: "user.delete", ResourceType: "user", ResourceID: act.User.ID.String(), ResourceName: act.User.Email})
	if err := a.Store.DeleteUser(ctx, act.User.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.clearSessionCookie(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Organizations ----

func (a *App) handleCreateOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	s := a.Settings(ctx)
	if !s.AllowOrgCreation && !act.User.IsSuperadmin {
		a.fail(w, r, errForbidden("Creating organizations is restricted to instance administrators."))
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		a.fail(w, r, errField("name", "Enter an organization name (up to 100 characters)"))
		return
	}
	var org *store.Org
	err := a.Store.Tx(ctx, func(tx *store.Store) error {
		var err error
		if org, err = tx.CreateOrg(ctx, name, slugify(name)); err != nil {
			return err
		}
		return tx.AddMember(ctx, org.ID, act.User.ID, "owner", nil, "manual")
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{OrgID: &org.ID, Action: "org.create", ResourceType: "organization", ResourceID: org.ID.String(), ResourceName: org.Name})
	writeJSON(w, 201, org)
}

func (a *App) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	acc := accessFrom(ctx)
	act := actorFrom(ctx)
	n, _ := a.Store.CountZones(ctx, org.ID)
	s := a.Settings(ctx)
	max := s.DefaultMaxZones
	if org.MaxZones != nil {
		max = *org.MaxZones
	}
	writeJSON(w, 200, map[string]any{
		"org": org, "role": acc.Role, "zone_ids": acc.ZoneIDs, "zone_count": n, "max_zones": max,
		"permissions":  permsFor(acc.Role, act.Type == "api_token"),
		"record_types": map[string][]string{"forward": orEmpty(s.ForwardRecordTypes), "reverse": orEmpty(s.ReverseRecordTypes)},
		"auto_ptr":     s.AutoPTR,
	})
}

func (a *App) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	var in struct {
		Name              *string   `json:"name"`
		EnforceMFA        *bool     `json:"enforce_mfa"`
		SessionTTLMinutes *int      `json:"session_ttl_minutes"`
		IPAllowlist       *[]string `json:"ip_allowlist"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	u := store.OrgUpdate{Name: org.Name, EnforceMFA: org.EnforceMFA, SessionTTLMinutes: org.SessionTTLMinutes, IPAllowlist: org.IPAllowlist}
	changes := map[string]any{}
	if in.Name != nil {
		n := strings.TrimSpace(*in.Name)
		if n == "" || len(n) > 100 {
			a.fail(w, r, errField("name", "Enter an organization name (up to 100 characters)"))
			return
		}
		if n != org.Name {
			changes["name"] = map[string]string{"from": org.Name, "to": n}
		}
		u.Name = n
	}
	if in.EnforceMFA != nil {
		if *in.EnforceMFA && !org.EnforceMFA {
			if act := actorFrom(ctx); act.Type == "user" && !act.User.TOTPEnabled && act.Session.AuthMethod != "sso" {
				a.fail(w, r, errField("enforce_mfa", "Enable two-factor authentication on your own account first"))
				return
			}
		}
		if *in.EnforceMFA != org.EnforceMFA {
			changes["enforce_mfa"] = *in.EnforceMFA
		}
		u.EnforceMFA = *in.EnforceMFA
	}
	if in.SessionTTLMinutes != nil {
		v := *in.SessionTTLMinutes
		if v < 0 || (v > 0 && v < 15) {
			a.fail(w, r, errField("session_ttl_minutes", "Session length must be at least 15 minutes"))
			return
		}
		if v == 0 {
			u.SessionTTLMinutes = nil
		} else {
			u.SessionTTLMinutes = &v
		}
		changes["session_ttl_minutes"] = v
	}
	if in.IPAllowlist != nil {
		list := cleanList(*in.IPAllowlist)
		if err := validateCIDRs(list); err != nil {
			a.fail(w, r, errField("ip_allowlist", err.Error()))
			return
		}
		if len(list) > 0 && !ipAllowed(a.clientIP(r), list) {
			a.fail(w, r, errField("ip_allowlist", "Your current IP address ("+a.clientIP(r)+") must be included to avoid locking yourself out"))
			return
		}
		u.IPAllowlist = list
		changes["ip_allowlist"] = list
	}
	if err := a.Store.UpdateOrg(ctx, org.ID, u); err != nil {
		a.fail(w, r, err)
		return
	}
	if len(changes) > 0 {
		a.audit(r, auditEvent{Action: "org.update", ResourceType: "organization", ResourceID: org.ID.String(), ResourceName: u.Name, Metadata: changes})
	}
	updated, _ := a.Store.OrgByID(ctx, org.ID)
	writeJSON(w, 200, updated)
}

func (a *App) handleDeleteOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.TrimSpace(in.Confirm) != org.Name {
		a.fail(w, r, errField("confirm", "Type the organization name to confirm"))
		return
	}
	zones, err := a.Store.ListZones(ctx, org.ID, nil)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if len(zones) > 0 {
		a.fail(w, r, errConflict("Delete or move all zones before deleting this organization."))
		return
	}
	a.audit(r, auditEvent{Action: "org.delete", ResourceType: "organization", ResourceID: org.ID.String(), ResourceName: org.Name, OrgID: nil})
	if err := a.Store.DeleteOrg(ctx, org.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Members ----

func (a *App) handleListMembers(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListMembers(r.Context(), orgFrom(r.Context()).ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) actorRole(r *http.Request) string {
	return accessFrom(r.Context()).Role
}

func (a *App) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "memberID"))
	if err != nil {
		a.fail(w, r, errNotFound("Member"))
		return
	}
	m, err := a.Store.MembershipByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	var in struct {
		Role    string       `json:"role"`
		ZoneIDs *[]uuid.UUID `json:"zone_ids"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !validRoles[in.Role] {
		a.fail(w, r, errField("role", "Choose a valid role"))
		return
	}
	myRole := a.actorRole(r)
	if (in.Role == "owner" || m.Role == "owner") && myRole != "owner" {
		a.fail(w, r, errForbidden("Only owners can grant or change the owner role."))
		return
	}
	if m.Role == "owner" && in.Role != "owner" {
		if n, _ := a.Store.CountOwners(ctx, org.ID); n <= 1 {
			a.fail(w, r, errConflict("An organization must have at least one owner."))
			return
		}
	}
	zoneIDs := m.ZoneIDs
	if in.ZoneIDs != nil {
		zoneIDs = *in.ZoneIDs
		if len(zoneIDs) == 0 {
			zoneIDs = nil
		}
	}
	if in.Role == "owner" || in.Role == "admin" {
		zoneIDs = nil
	}
	if err := a.Store.UpdateMember(ctx, org.ID, id, in.Role, zoneIDs); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "member.update", ResourceType: "member", ResourceID: m.UserID.String(), ResourceName: m.UserEmail,
		Metadata: map[string]any{"role": map[string]string{"from": m.Role, "to": in.Role}, "zone_ids": zoneIDs}})
	updated, _ := a.Store.MembershipByID(ctx, org.ID, id)
	writeJSON(w, 200, updated)
}

func (a *App) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "memberID"))
	if err != nil {
		a.fail(w, r, errNotFound("Member"))
		return
	}
	m, err := a.Store.MembershipByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if m.Role == "owner" {
		if a.actorRole(r) != "owner" {
			a.fail(w, r, errForbidden("Only owners can remove another owner."))
			return
		}
		if n, _ := a.Store.CountOwners(ctx, org.ID); n <= 1 {
			a.fail(w, r, errConflict("An organization must have at least one owner."))
			return
		}
	}
	if err := a.Store.RemoveMember(ctx, org.ID, m.UserID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "member.remove", ResourceType: "member", ResourceID: m.UserID.String(), ResourceName: m.UserEmail,
		Metadata: map[string]any{"role": m.Role}})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleLeaveOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	act := actorFrom(ctx)
	m, err := a.Store.Membership(ctx, org.ID, act.User.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if m.Role == "owner" {
		if n, _ := a.Store.CountOwners(ctx, org.ID); n <= 1 {
			a.fail(w, r, errConflict("Transfer ownership to another member before leaving."))
			return
		}
	}
	if err := a.Store.RemoveMember(ctx, org.ID, act.User.ID); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "member.leave", ResourceType: "member", ResourceID: act.User.ID.String(), ResourceName: act.User.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Invitations ----

func (a *App) handleListInvites(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListInvitations(r.Context(), orgFrom(r.Context()).ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func (a *App) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	act := actorFrom(ctx)
	var in struct {
		Emails  []string    `json:"emails"`
		Role    string      `json:"role"`
		ZoneIDs []uuid.UUID `json:"zone_ids"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !validRoles[in.Role] {
		a.fail(w, r, errField("role", "Choose a valid role"))
		return
	}
	if in.Role == "owner" && a.actorRole(r) != "owner" {
		a.fail(w, r, errForbidden("Only owners can invite other owners."))
		return
	}
	if len(in.Emails) == 0 || len(in.Emails) > 50 {
		a.fail(w, r, errField("emails", "Enter between 1 and 50 email addresses"))
		return
	}
	if len(in.ZoneIDs) == 0 || in.Role == "owner" || in.Role == "admin" {
		in.ZoneIDs = nil
	}
	type result struct {
		Email     string `json:"email"`
		Status    string `json:"status"` // invited | member | invalid
		InviteURL string `json:"invite_url,omitempty"`
		Emailed   bool   `json:"emailed"`
		Error     string `json:"error,omitempty"`
	}
	var results []result
	for _, raw := range in.Emails {
		email, err := normalizeEmail(raw)
		if err != nil {
			results = append(results, result{Email: raw, Status: "invalid", Error: err.Error()})
			continue
		}
		if u, err := a.Store.UserByEmail(ctx, email); err == nil {
			if _, err := a.Store.Membership(ctx, org.ID, u.ID); err == nil {
				results = append(results, result{Email: email, Status: "member", Error: "Already a member"})
				continue
			}
		}
		token := secure.RandomToken(32)
		inv, err := a.Store.CreateInvitation(ctx, org.ID, email, in.Role, in.ZoneIDs, secure.HashToken(token), actorUserID(ctx))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		link := a.Cfg.PublicURL + "/invite/" + token
		mailErr := a.Mailer.Send(context0(r), mailMessage(email, "You have been invited to "+org.Name, "Join "+org.Name,
			[]string{inviteLine(act, org, in.Role),
				"This invitation expires in 7 days."}, "Accept invitation", link))
		if mailErr != nil && !errors.Is(mailErr, errMailDisabled()) {
			a.Log.Warn("invite email failed", "err", mailErr, "email", email)
		}
		results = append(results, result{Email: email, Status: "invited", InviteURL: link, Emailed: mailErr == nil})
		a.audit(r, auditEvent{Action: "member.invite", ResourceType: "invitation", ResourceID: inv.ID.String(), ResourceName: email,
			Metadata: map[string]any{"role": in.Role, "zone_ids": in.ZoneIDs}})
	}
	writeJSON(w, 201, map[string]any{"results": results})
}

// inviteLine opens an invitation email, naming the inviter when a person sent it.
func inviteLine(act *Actor, org *store.Org, role string) string {
	if act.Type == "user" {
		return act.User.DisplayName() + " invited you to join " + org.Name + " as " + roleLabel(role) + "."
	}
	return "You have been invited to join " + org.Name + " as " + roleLabel(role) + "."
}

func (a *App) handleResendInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	act := actorFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "inviteID"))
	if err != nil {
		a.fail(w, r, errNotFound("Invitation"))
		return
	}
	inv, err := a.Store.InvitationByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	token := secure.RandomToken(32)
	if err := a.Store.RefreshInvitation(ctx, inv.ID, secure.HashToken(token)); err != nil {
		a.fail(w, r, err)
		return
	}
	link := a.Cfg.PublicURL + "/invite/" + token
	mailErr := a.Mailer.Send(context0(r), mailMessage(inv.Email, "Reminder: join "+org.Name, "Join "+org.Name,
		[]string{inviteLine(act, org, inv.Role)}, "Accept invitation", link))
	a.audit(r, auditEvent{Action: "member.invite_resend", ResourceType: "invitation", ResourceID: inv.ID.String(), ResourceName: inv.Email})
	writeJSON(w, 200, map[string]any{"invite_url": link, "emailed": mailErr == nil})
}

func (a *App) handleDeleteInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "inviteID"))
	if err != nil {
		a.fail(w, r, errNotFound("Invitation"))
		return
	}
	inv, err := a.Store.InvitationByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.Store.DeleteInvitation(ctx, org.ID, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "member.invite_revoke", ResourceType: "invitation", ResourceID: id.String(), ResourceName: inv.Email})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- API tokens ----

func (a *App) handleListTokens(w http.ResponseWriter, r *http.Request) {
	list, err := a.Store.ListAPITokens(r.Context(), orgFrom(r.Context()).ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, 200, list)
}

func newAPITokenSecret() (token, prefix string) {
	raw := secure.RandomToken(30)
	token = "flr_" + raw
	return token, token[:10]
}

func (a *App) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	act := actorFrom(ctx)
	var in struct {
		Name          string      `json:"name"`
		Role          string      `json:"role"`
		ZoneIDs       []uuid.UUID `json:"zone_ids"`
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
	in.IPAllowlist = cleanList(in.IPAllowlist)
	if err := validateCIDRs(in.IPAllowlist); err != nil {
		fields["ip_allowlist"] = err.Error()
	}
	if in.ExpiresInDays < 0 || in.ExpiresInDays > 3650 {
		fields["expires_in_days"] = "Expiry must be between 1 and 3650 days"
	}
	if len(fields) > 0 {
		a.fail(w, r, errValidation(fields))
		return
	}
	if len(in.ZoneIDs) == 0 {
		in.ZoneIDs = nil
	}
	t := store.APIToken{OrgID: &org.ID, Name: in.Name, Role: in.Role, ZoneIDs: in.ZoneIDs, IPAllowlist: in.IPAllowlist, CreatedBy: &act.User.ID}
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
		Metadata: map[string]any{"role": in.Role, "zone_ids": in.ZoneIDs, "ip_allowlist": in.IPAllowlist, "expires_at": t.ExpiresAt}})
	writeJSON(w, 201, map[string]any{"token": created, "secret": secret})
}

func (a *App) handleRollToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		a.fail(w, r, errNotFound("Token"))
		return
	}
	t, err := a.Store.APITokenByID(ctx, org.ID, id)
	if err != nil || t.RevokedAt != nil {
		a.fail(w, r, errNotFound("Token"))
		return
	}
	secret, prefix := newAPITokenSecret()
	if err := a.Store.RollAPIToken(ctx, id, prefix, secure.HashToken(secret)); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "token.roll", ResourceType: "api_token", ResourceID: id.String(), ResourceName: t.Name})
	t.Prefix = prefix
	writeJSON(w, 200, map[string]any{"token": t, "secret": secret})
}

func (a *App) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org := orgFrom(ctx)
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		a.fail(w, r, errNotFound("Token"))
		return
	}
	t, err := a.Store.APITokenByID(ctx, org.ID, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.Store.RevokeAPIToken(ctx, org.ID, id); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "token.revoke", ResourceType: "api_token", ResourceID: id.String(), ResourceName: t.Name})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// handleVerifyToken lets automation check its token (like a whoami).
func (a *App) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	act := actorFrom(r.Context())
	if act.Type != "api_token" {
		a.fail(w, r, errBadRequest("Call this endpoint with an API token."))
		return
	}
	t := act.Token
	writeJSON(w, 200, map[string]any{"id": t.ID, "name": t.Name, "global": t.OrgID == nil, "org_id": t.OrgID, "org_ids": t.OrgIDs,
		"instance_role": t.InstanceRole, "role": t.Role, "zone_ids": t.ZoneIDs, "expires_at": t.ExpiresAt, "status": "active",
		"permissions": permsFor(t.Role, true)})
}

// handleListOrgs lists the organizations the caller can work in, with its role in each. Global
// tokens use it to discover organization IDs.
func (a *App) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	act := actorFrom(ctx)
	type orgEntry struct {
		ID   uuid.UUID `json:"id"`
		Name string    `json:"name"`
		Slug string    `json:"slug"`
		Role string    `json:"role"`
	}
	out := []orgEntry{}
	if act.Type == "user" {
		list, err := a.Store.OrgsForUser(ctx, act.User.ID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		for _, o := range list {
			out = append(out, orgEntry{ID: o.ID, Name: o.Name, Slug: o.Slug, Role: o.Role})
		}
		writeJSON(w, 200, out)
		return
	}
	ids := act.Token.OrgIDs
	if act.Token.OrgID != nil {
		ids = []uuid.UUID{*act.Token.OrgID}
	}
	orgs, err := a.Store.OrgsByIDs(ctx, ids)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	for i := range orgs {
		if _, err := tokenScope(act.Token, &orgs[i]); err == nil {
			out = append(out, orgEntry{ID: orgs[i].ID, Name: orgs[i].Name, Slug: orgs[i].Slug, Role: act.Token.Role})
		}
	}
	writeJSON(w, 200, out)
}

func cleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func roleLabel(role string) string {
	switch role {
	case "owner":
		return "an Owner"
	case "admin":
		return "an Administrator"
	case "editor":
		return "a DNS Editor"
	case "auditor":
		return "an Auditor"
	default:
		return "a Viewer"
	}
}
