package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-ldap/ldap/v3"
)

// LDAP / Active Directory authentication. Directory users sign in with their
// username (or email) and password; accounts are provisioned on first sign-in and
// their organization role follows directory group mappings.

type ldapIdentity struct {
	DN     string
	Email  string
	Name   string
	Groups []string
}

var errLDAPInvalid = errors.New("invalid directory credentials")

func (a *App) ldapConnect(cfg store.LDAPConfig) (*ldap.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify, MinVersion: tls.VersionTLS12} //nolint:gosec // opt-in for lab directories
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsCfg), ldap.DialWithDialer(nil))
	if err != nil {
		return nil, fmt.Errorf("connect to directory: %w", err)
	}
	conn.SetTimeout(10 * time.Second)
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("start TLS: %w", err)
		}
	}
	return conn, nil
}

// ldapAuthenticate finds the user with the service account, then binds as the user.
func (a *App) ldapAuthenticate(cfg store.LDAPConfig, username, password string) (*ldapIdentity, error) {
	if strings.TrimSpace(username) == "" || password == "" {
		return nil, errLDAPInvalid
	}
	conn, err := a.ldapConnect(cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if cfg.BindDN != "" {
		pw := ""
		if cfg.BindPasswordEnc != "" {
			if pw, err = a.Box.Open(cfg.BindPasswordEnc); err != nil {
				return nil, err
			}
		}
		if err := conn.Bind(cfg.BindDN, pw); err != nil {
			return nil, fmt.Errorf("service account bind failed: %w", err)
		}
	}
	filter := strings.ReplaceAll(orStr(cfg.UserFilter, "(uid={username})"), "{username}", ldap.EscapeFilter(username))
	emailAttr, nameAttr, groupAttr := orStr(cfg.EmailAttribute, "mail"), orStr(cfg.NameAttribute, "cn"), orStr(cfg.GroupAttribute, "memberOf")
	res, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 10, false,
		filter, []string{emailAttr, nameAttr, groupAttr, "uid"}, nil))
	if err != nil {
		return nil, fmt.Errorf("directory search failed: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, errLDAPInvalid
	}
	entry := res.Entries[0]
	groups := entry.GetAttributeValues(groupAttr)
	if len(groups) == 0 {
		// Directories without a memberOf overlay (stock OpenLDAP): look the groups up by membership.
		// This runs as the service account, before the user bind replaces its privileges.
		uid := ldap.EscapeFilter(entry.GetAttributeValue("uid"))
		dn := ldap.EscapeFilter(entry.DN)
		gf := "(|(member=" + dn + ")(uniqueMember=" + dn + ")"
		if uid != "" {
			gf += "(memberUid=" + uid + ")"
		}
		gf += ")"
		if gr, err := conn.Search(ldap.NewSearchRequest(cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 500, 10, false,
			gf, []string{"dn"}, nil)); err == nil {
			for _, g := range gr.Entries {
				groups = append(groups, g.DN)
			}
		}
	}
	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, errLDAPInvalid
	}
	id := &ldapIdentity{DN: entry.DN, Email: strings.ToLower(entry.GetAttributeValue(emailAttr)), Name: entry.GetAttributeValue(nameAttr),
		Groups: groups}
	if id.Email == "" && strings.Contains(username, "@") {
		id.Email = strings.ToLower(username)
	}
	if id.Email == "" {
		return nil, errors.New("the directory entry has no email address")
	}
	return id, nil
}

func hasGroup(groups []string, dn string) bool {
	for _, g := range groups {
		if dn != "" && strings.EqualFold(g, dn) {
			return true
		}
	}
	return false
}

// ldapLogin authenticates against the directory and provisions the local account.
// It returns (nil, nil) when LDAP does not apply to this sign-in.
func (a *App) ldapLogin(ctx context.Context, username, password string, existing *store.User) (*store.User, error) {
	s := a.Settings(ctx)
	cfg := s.LDAP
	if !cfg.Enabled || (existing != nil && existing.CreatedVia != "ldap") {
		return nil, nil
	}
	id, err := a.ldapAuthenticate(cfg, username, password)
	if err != nil {
		if !errors.Is(err, errLDAPInvalid) {
			a.Log.Warn("ldap authentication error", "err", err)
		}
		return nil, errLDAPInvalid
	}
	super := hasGroup(id.Groups, cfg.AdminGroupDN)
	u := existing
	if u == nil {
		u, err = a.Store.UserByEmail(ctx, id.Email)
		if errors.Is(err, db.ErrNotFound) {
			u, err = a.Store.CreateUser(ctx, store.NewUser{Email: id.Email, Name: id.Name, EmailVerified: true, CreatedVia: "ldap", IsSuperadmin: super})
		}
		if err != nil {
			return nil, err
		}
		if u.CreatedVia != "ldap" {
			// A local account with this email exists; do not let the directory take it over.
			return nil, errLDAPInvalid
		}
	}
	if u.Disabled {
		return nil, errLDAPInvalid
	}
	if id.Name != "" && id.Name != u.Name || id.Email != u.Email {
		_ = a.Store.UpdateUserIdentity(ctx, u.ID, id.Email, orStr(id.Name, u.Name))
	}
	if cfg.AdminGroupDN != "" && super != u.IsSuperadmin {
		if super || func() bool { n, _ := a.Store.CountSuperadmins(ctx); return n > 1 }() {
			_ = a.Store.SetUserAdminFlags(ctx, u.ID, super, false)
		}
	}
	if cfg.DefaultOrgID != nil {
		role := orStr(cfg.DefaultRole, "viewer")
		best := ""
		for _, m := range cfg.GroupRoles {
			if hasGroup(id.Groups, m.Group) && roleRank[m.Role] > roleRank[best] {
				best = m.Role
			}
		}
		if best != "" {
			role = best
		}
		if m, err := a.Store.Membership(ctx, *cfg.DefaultOrgID, u.ID); errors.Is(err, db.ErrNotFound) {
			_ = a.Store.AddMember(ctx, *cfg.DefaultOrgID, u.ID, role, nil, "ldap")
		} else if err == nil && m.Source == "ldap" && m.Role != role && m.Role != "owner" {
			_ = a.Store.SetMemberRole(ctx, *cfg.DefaultOrgID, u.ID, role)
		}
	}
	return a.Store.UserByID(ctx, u.ID)
}

// handleTestLDAP checks the directory configuration with a real account.
func (a *App) handleTestLDAP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	cfg := a.Settings(r.Context()).LDAP
	if cfg.URL == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "Save a directory URL first."})
		return
	}
	id, err := a.ldapAuthenticate(cfg, in.Username, in.Password)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "dn": id.DN, "email": id.Email, "name": id.Name, "groups": id.Groups,
		"admin": hasGroup(id.Groups, cfg.AdminGroupDN)})
}
