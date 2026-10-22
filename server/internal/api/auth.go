package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/dnsutil"
	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/pquerna/otp/totp"
)

// ---- Public configuration & first-run setup ----

func (a *App) handlePublicConfig(w http.ResponseWriter, r *http.Request) {
	a.ensureCSRFCookie(w, r)
	n, err := a.Store.CountUsers(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	s := a.Settings(r.Context())
	writeJSON(w, 200, map[string]any{
		"instance_name":       s.InstanceName,
		"signup_enabled":      s.SignupEnabled,
		"setup_required":      n == 0,
		"password_min_length": s.PasswordMinLength,
		"announcement":        s.AnnouncementBanner,
		"support_email":       s.SupportEmail,
		"bootstrap_server":    a.Cfg.BootstrapPDNSURL != "",
		"email_enabled":       a.Mailer.Enabled(r.Context()),
		"ldap_enabled":        s.LDAP.Enabled,
		"version":             Version,
	})
}

// handleSetupTestServer checks PowerDNS connectivity during first-run setup only.
func (a *App) handleSetupTestServer(w http.ResponseWriter, r *http.Request) {
	n, err := a.Store.CountUsers(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if n > 0 {
		a.fail(w, r, errConflict("Setup has already been completed."))
		return
	}
	var in struct {
		APIURL   string `json:"api_url"`
		APIKey   string `json:"api_key"`
		ServerID string `json:"server_id"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	url, key, sid := in.APIURL, in.APIKey, in.ServerID
	if url == "" {
		url, key, sid = a.Cfg.BootstrapPDNSURL, a.Cfg.BootstrapPDNSKey, a.Cfg.BootstrapPDNSServer
	}
	info, err := pdns.New(strings.TrimSuffix(strings.TrimRight(url, "/"), "/api/v1"), key, orStr(sid, "localhost")).Server(r.Context())
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "version": info.Version})
}

type setupRequest struct {
	InstanceName string `json:"instance_name"`
	Admin        struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	} `json:"admin"`
	OrgName string `json:"org_name"`
	Server  *struct {
		Name     string `json:"name"`
		APIURL   string `json:"api_url"`
		APIKey   string `json:"api_key"`
		ServerID string `json:"server_id"`
	} `json:"server"`
	Nameservers struct {
		Name        string   `json:"name"`
		Nameservers []string `json:"nameservers"`
		Hostmaster  string   `json:"hostmaster"`
	} `json:"nameservers"`
}

func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req setupRequest
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	n, err := a.Store.CountUsers(ctx)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if n > 0 {
		a.fail(w, r, errConflict("Setup has already been completed."))
		return
	}
	settings := a.Settings(ctx)
	fields := map[string]string{}
	email, emailErr := normalizeEmail(req.Admin.Email)
	if emailErr != nil {
		fields["admin.email"] = emailErr.Error()
	}
	if err := a.checkPassword(req.Admin.Password, email, settings); err != nil {
		fields["admin.password"] = err.Error()
	}
	if strings.TrimSpace(req.OrgName) == "" {
		fields["org_name"] = "Organization name is required"
	}
	nsList, nsErr := normalizeNameservers(req.Nameservers.Nameservers)
	if nsErr != nil {
		fields["nameservers.nameservers"] = nsErr.Error()
	}
	if len(fields) > 0 {
		a.fail(w, r, errValidation(fields))
		return
	}

	// Resolve the PowerDNS server (explicit or bootstrapped from environment) and test it.
	srvName, srvURL, srvKey, srvID := "Primary", a.Cfg.BootstrapPDNSURL, a.Cfg.BootstrapPDNSKey, a.Cfg.BootstrapPDNSServer
	if req.Server != nil && req.Server.APIURL != "" {
		srvName, srvURL, srvKey, srvID = req.Server.Name, req.Server.APIURL, req.Server.APIKey, req.Server.ServerID
	}
	if srvName == "" {
		srvName = "Primary"
	}
	if srvURL == "" {
		a.fail(w, r, errField("server.api_url", "A PowerDNS API URL is required"))
		return
	}
	info, err := pdns.New(srvURL, srvKey, srvID).Server(ctx)
	if err != nil {
		a.fail(w, r, errField("server.api_url", "Could not connect to PowerDNS: "+err.Error()))
		return
	}
	keyEnc, err := a.Box.Seal(srvKey)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	hash, err := secure.HashPassword(req.Admin.Password)
	if err != nil {
		a.fail(w, r, err)
		return
	}

	var user *store.User
	var org *store.Org
	err = a.Store.Tx(ctx, func(tx *store.Store) error {
		var err error
		user, err = tx.CreateUser(ctx, store.NewUser{Email: email, Name: strings.TrimSpace(req.Admin.Name), PasswordHash: &hash,
			IsSuperadmin: true, EmailVerified: true, CreatedVia: "setup"})
		if err != nil {
			return err
		}
		org, err = tx.CreateOrg(ctx, strings.TrimSpace(req.OrgName), slugify(req.OrgName))
		if err != nil {
			return err
		}
		if err := tx.AddMember(ctx, org.ID, user.ID, "owner", nil, "manual"); err != nil {
			return err
		}
		srv, err := tx.CreateServer(ctx, store.ServerInput{Name: srvName, APIURL: srvURL, APIKeyEnc: keyEnc, ServerID: orStr(srvID, "localhost"),
			Description: "Configured during setup", IsDefault: true, Enabled: true})
		if err != nil {
			return err
		}
		_ = tx.SetServerStatus(ctx, srv.ID, "healthy", info.Version)
		nsName := orStr(strings.TrimSpace(req.Nameservers.Name), "Default")
		if _, err := tx.SaveNameserverSet(ctx, nil, nsName, nsList, strings.TrimSpace(req.Nameservers.Hostmaster), true); err != nil {
			return err
		}
		now := time.Now()
		settings.SetupCompletedAt = &now
		if name := strings.TrimSpace(req.InstanceName); name != "" {
			settings.InstanceName = name
		}
		if req.Nameservers.Hostmaster != "" && settings.SupportEmail == "" {
			settings.SupportEmail = req.Nameservers.Hostmaster
		}
		return tx.SaveInstanceSettings(ctx, settings)
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.settingsMu.Lock()
	a.settingsCache = nil
	a.settingsMu.Unlock()
	if err := a.startSession(w, r, user, "password", nil); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "instance.setup", ResourceType: "instance", ResourceName: settings.InstanceName, ActorUser: user})
	a.audit(r, auditEvent{OrgID: &org.ID, Action: "org.create", ResourceType: "organization", ResourceID: org.ID.String(),
		ResourceName: org.Name, ActorUser: user})
	writeJSON(w, 201, map[string]any{"user": user, "org": org})
}

// ---- Login ----

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req loginRequest
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	invalid := errCode(401, "invalid_credentials", "Incorrect email or password.")

	if !a.limiter.allow("login-email:"+email, 10, 2) {
		a.fail(w, r, errCode(429, "rate_limited", "Too many sign-in attempts for this account. Wait a few minutes and try again."))
		return
	}
	u, err := a.Store.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, db.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	// Domains that enforce SSO never accept passwords, except for instance
	// administrators (break-glass access).
	if u == nil || !u.IsSuperadmin {
		if enforced, _ := a.Store.SSOEnforcedForDomain(ctx, emailDomain(email)); enforced {
			body := map[string]any{"code": "sso_required", "message": "Your organization requires single sign-on."}
			if conn, err := a.Store.SSOConnectionForDomain(ctx, emailDomain(email)); err == nil {
				body["sso_url"] = "/api/v1/auth/sso/" + conn.ID.String() + "/start"
			}
			writeJSON(w, 403, map[string]any{"error": body})
			return
		}
	}
	method := "password"
	if lu, lerr := a.ldapLogin(ctx, email, req.Password, u); lerr != nil {
		a.audit(r, auditEvent{Action: "auth.login", ResourceType: "user", ResourceName: email, Outcome: "failure",
			ActorType: "anonymous", ActorLabel: email, Metadata: map[string]any{"reason": "ldap_rejected", "method": "ldap"}})
		a.fail(w, r, invalid)
		return
	} else if lu != nil {
		u, method = lu, "ldap"
	} else if u == nil || !u.HasPassword() {
		secure.VerifyDummy(req.Password)
		a.audit(r, auditEvent{Action: "auth.login", ResourceType: "user", ResourceName: email, Outcome: "failure",
			ActorType: "anonymous", ActorLabel: email, Metadata: map[string]any{"reason": "unknown_user"}})
		a.fail(w, r, invalid)
		return
	}
	if method == "password" && (!secure.VerifyPassword(req.Password, *u.PasswordHash) || u.Disabled) {
		reason := "bad_password"
		if u.Disabled {
			reason = "disabled"
		}
		a.audit(r, auditEvent{Action: "auth.login", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email,
			Outcome: "failure", ActorUser: u, Metadata: map[string]any{"reason": reason}})
		a.fail(w, r, invalid)
		return
	}
	if u.TOTPEnabled {
		token := secure.RandomToken(32)
		if err := a.Store.CreateMFAChallenge(ctx, secure.HashToken(token), u.ID); err != nil {
			a.fail(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"mfa_required": true, "mfa_token": token})
		return
	}
	if err := a.startSession(w, r, u, method, nil); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "auth.login", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email,
		ActorUser: u, Metadata: map[string]any{"method": method}})
	writeJSON(w, 200, map[string]any{"mfa_required": false})
}

func (a *App) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		MFAToken string `json:"mfa_token"`
		Code     string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	hash := secure.HashToken(req.MFAToken)
	uid, attempts, err := a.Store.MFAChallenge(ctx, hash)
	if err != nil {
		a.fail(w, r, errCode(401, "mfa_expired", "Your verification session expired. Sign in again."))
		return
	}
	if attempts > 5 {
		_ = a.Store.DeleteMFAChallenge(ctx, hash)
		a.fail(w, r, errCode(429, "mfa_locked", "Too many incorrect codes. Sign in again."))
		return
	}
	u, err := a.Store.UserByID(ctx, uid)
	if err != nil || u.Disabled {
		a.fail(w, r, errUnauthorized("Sign in again."))
		return
	}
	ok, usedRecovery, err := a.verifySecondFactor(ctx, u, req.Code)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !ok {
		a.audit(r, auditEvent{Action: "auth.mfa", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email,
			Outcome: "failure", ActorUser: u})
		a.fail(w, r, errField("code", "That code is not valid. Check your authenticator app and try again."))
		return
	}
	_ = a.Store.DeleteMFAChallenge(ctx, hash)
	if err := a.startSession(w, r, u, "password", nil); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "auth.login", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email,
		ActorUser: u, Metadata: map[string]any{"method": "password", "mfa": true, "recovery_code": usedRecovery}})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// verifySecondFactor checks a TOTP code or a single-use recovery code.
func (a *App) verifySecondFactor(ctx context.Context, u *store.User, code string) (ok bool, recovery bool, err error) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if u.TOTPSecret == nil {
		return false, false, nil
	}
	secret, err := a.Box.Open(*u.TOTPSecret)
	if err != nil {
		return false, false, err
	}
	if len(code) == 6 && totp.Validate(code, secret) {
		return true, false, nil
	}
	h := hashRecovery(code)
	for i, c := range u.RecoveryCodes {
		if c == h {
			rest := append(append([]string{}, u.RecoveryCodes[:i]...), u.RecoveryCodes[i+1:]...)
			return true, true, a.Store.SetRecoveryCodes(ctx, u.ID, rest)
		}
	}
	return false, false, nil
}

func hashRecovery(code string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(code))))
	return hex.EncodeToString(h[:])
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if act := actorFrom(r.Context()); act != nil && act.Session != nil {
		_ = a.Store.DeleteSessionByID(r.Context(), act.Session.ID)
		a.audit(r, auditEvent{Action: "auth.logout", ResourceType: "user", ResourceID: act.User.ID.String(), ResourceName: act.User.Email})
	}
	a.clearSessionCookie(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Signup ----

func (a *App) handleSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s := a.Settings(ctx)
	if !s.SignupEnabled {
		a.fail(w, r, errForbidden("Self-service sign up is disabled. Ask an administrator for an invitation."))
		return
	}
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	email, err := normalizeEmail(req.Email)
	if err != nil {
		a.fail(w, r, errField("email", err.Error()))
		return
	}
	if enforced, _ := a.Store.SSOEnforcedForDomain(ctx, emailDomain(email)); enforced {
		a.fail(w, r, errField("email", "Your organization requires single sign-on. Use Continue with SSO instead."))
		return
	}
	if err := a.checkPassword(req.Password, email, s); err != nil {
		a.fail(w, r, errField("password", err.Error()))
		return
	}
	hash, err := secure.HashPassword(req.Password)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	u, err := a.Store.CreateUser(ctx, store.NewUser{Email: email, Name: strings.TrimSpace(req.Name), PasswordHash: &hash, CreatedVia: "password"})
	if db.IsUniqueViolation(err) {
		a.fail(w, r, errField("email", "An account with this email already exists. Sign in instead."))
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.startSession(w, r, u, "password", nil); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{Action: "user.signup", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email, ActorUser: u})
	writeJSON(w, 201, map[string]any{"user": u})
}

// ---- Password reset ----

func (a *App) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if u, err := a.Store.UserByEmail(ctx, email); err == nil && !u.Disabled {
		token := secure.RandomToken(32)
		if err := a.Store.CreatePasswordReset(ctx, secure.HashToken(token), u.ID); err == nil {
			link := a.Cfg.PublicURL + "/reset-password?token=" + token
			err := a.Mailer.Send(context.WithoutCancel(ctx), mailMessage(u.Email, "Reset your password", "Reset your password",
				[]string{"We received a request to reset the password for your account.",
					"This link expires in one hour. If you did not request a reset, you can ignore this email."},
				"Reset password", link))
			if err != nil {
				a.Log.Warn("password reset email not sent", "err", err, "user", u.Email)
			}
			a.audit(r, auditEvent{Action: "auth.password_reset_requested", ResourceType: "user", ResourceID: u.ID.String(),
				ResourceName: u.Email, ActorUser: u})
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		a.fail(w, r, err)
		return
	}
	uid, err := a.Store.ConsumePasswordReset(ctx, secure.HashToken(req.Token))
	if err != nil {
		a.fail(w, r, errCode(400, "invalid_token", "This reset link is invalid or has expired. Request a new one."))
		return
	}
	u, err := a.Store.UserByID(ctx, uid)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.checkPassword(req.Password, u.Email, a.Settings(ctx)); err != nil {
		a.fail(w, r, errField("password", err.Error()))
		return
	}
	hash, err := secure.HashPassword(req.Password)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.Store.SetUserPassword(ctx, u.ID, hash); err != nil {
		a.fail(w, r, err)
		return
	}
	_ = a.Store.DeleteUserSessions(ctx, u.ID, nil)
	a.audit(r, auditEvent{Action: "auth.password_reset", ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email, ActorUser: u})
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---- Invitations ----

func (a *App) handleGetInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inv, err := a.Store.InvitationByToken(ctx, secure.HashToken(chi.URLParam(r, "token")))
	if err != nil {
		a.fail(w, r, errCode(404, "invalid_invite", "This invitation is invalid or has expired."))
		return
	}
	org, err := a.Store.OrgByID(ctx, inv.OrgID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	_, uerr := a.Store.UserByEmail(ctx, inv.Email)
	enforced, _ := a.Store.SSOEnforcedForDomain(ctx, emailDomain(inv.Email))
	writeJSON(w, 200, map[string]any{
		"org_name": org.Name, "email": inv.Email, "role": inv.Role, "inviter": inv.InviterName,
		"expires_at": inv.ExpiresAt, "user_exists": uerr == nil, "sso_required": enforced,
	})
}

func (a *App) handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	inv, err := a.Store.InvitationByToken(ctx, secure.HashToken(chi.URLParam(r, "token")))
	if err != nil {
		a.fail(w, r, errCode(404, "invalid_invite", "This invitation is invalid or has expired."))
		return
	}
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	act := actorFrom(ctx)
	var u *store.User
	if act != nil && act.Type == "user" {
		if !strings.EqualFold(act.User.Email, inv.Email) {
			a.fail(w, r, errForbidden(fmt.Sprintf("This invitation was sent to %s. Sign in with that account to accept it.", inv.Email)))
			return
		}
		u = act.User
	} else {
		if existing, err := a.Store.UserByEmail(ctx, inv.Email); err == nil {
			_ = existing
			a.fail(w, r, errCode(401, "login_required", "An account already exists for this email. Sign in to accept the invitation."))
			return
		}
		if enforced, _ := a.Store.SSOEnforcedForDomain(ctx, emailDomain(inv.Email)); enforced {
			a.fail(w, r, errCode(403, "sso_required", "Your organization requires single sign-on. Sign in with SSO to accept."))
			return
		}
		s := a.Settings(ctx)
		if err := a.checkPassword(req.Password, inv.Email, s); err != nil {
			a.fail(w, r, errField("password", err.Error()))
			return
		}
		hash, err := secure.HashPassword(req.Password)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		u, err = a.Store.CreateUser(ctx, store.NewUser{Email: inv.Email, Name: strings.TrimSpace(req.Name), PasswordHash: &hash,
			EmailVerified: true, CreatedVia: "invite"})
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if err := a.startSession(w, r, u, "password", nil); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	err = a.Store.Tx(ctx, func(tx *store.Store) error {
		if _, err := tx.Membership(ctx, inv.OrgID, u.ID); err == nil {
			return tx.AcceptInvitation(ctx, inv.ID)
		}
		if err := tx.AddMember(ctx, inv.OrgID, u.ID, inv.Role, inv.ZoneIDs, "invite"); err != nil {
			return err
		}
		return tx.AcceptInvitation(ctx, inv.ID)
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, auditEvent{OrgID: &inv.OrgID, Action: "member.join", ResourceType: "member", ResourceID: u.ID.String(),
		ResourceName: u.Email, ActorUser: u, Metadata: map[string]any{"role": inv.Role, "via": "invitation"}})
	writeJSON(w, 200, map[string]any{"org_id": inv.OrgID})
}

// ---- Helpers ----

func normalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || !strings.Contains(s[strings.LastIndex(s, "@")+1:], ".") {
		return "", errors.New("Enter a valid email address")
	}
	return s, nil
}

func emailDomain(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return strings.ToLower(email[i+1:])
	}
	return ""
}

func (a *App) checkPassword(pw, email string, s store.InstanceSettings) error {
	min := s.PasswordMinLength
	if min < 8 {
		min = 8
	}
	if utf8.RuneCountInString(pw) < min {
		return fmt.Errorf("Password must be at least %d characters", min)
	}
	if len(pw) > 256 {
		return errors.New("Password must be at most 256 characters")
	}
	if local, _, ok := strings.Cut(email, "@"); ok && len(local) >= 4 && strings.Contains(strings.ToLower(pw), local) {
		return errors.New("Password must not contain your email address")
	}
	lower := strings.ToLower(pw)
	for _, weak := range []string{"password", "123456", "qwerty", "letmein", "welcome", "changeme", "admin123"} {
		if strings.Contains(lower, weak) && len(pw) < 20 {
			return errors.New("Password is too easy to guess")
		}
	}
	return nil
}

func normalizeNameservers(in []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, n := range in {
		if strings.TrimSpace(n) == "" {
			continue
		}
		h, err := dnsutil.Hostname(n)
		if err != nil {
			return nil, err
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	if len(out) < 2 {
		return nil, errors.New("Provide at least two nameservers")
	}
	return out, nil
}

func slugify(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteRune('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	if out == "" {
		out = "org"
	}
	return out + "-" + secure.RandomHex(2)
}

func orStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
