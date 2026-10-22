package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---- API tokens ----

const tokenCols = `t.id, t.org_id, t.name, t.prefix, t.role, t.zone_ids, t.ip_allowlist, t.created_by,
	COALESCE(NULLIF(u.name,''), u.email::text, ''), t.expires_at, t.last_used_at, t.last_used_ip, t.revoked_at, t.created_at`

func scanToken(row pgx.Row) (*APIToken, error) {
	var t APIToken
	err := row.Scan(&t.ID, &t.OrgID, &t.Name, &t.Prefix, &t.Role, &t.ZoneIDs, &t.IPAllowlist, &t.CreatedBy, &t.CreatorName,
		&t.ExpiresAt, &t.LastUsedAt, &t.LastUsedIP, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &t, nil
}

func (s *Store) CreateAPIToken(ctx context.Context, t APIToken, tokenHash []byte) (*APIToken, error) {
	if t.IPAllowlist == nil {
		t.IPAllowlist = []string{}
	}
	var id uuid.UUID
	if err := s.q.QueryRow(ctx, `INSERT INTO api_tokens(org_id, name, prefix, token_hash, role, zone_ids, ip_allowlist, created_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`, t.OrgID, t.Name, t.Prefix, tokenHash, t.Role, t.ZoneIDs, t.IPAllowlist,
		t.CreatedBy, t.ExpiresAt).Scan(&id); err != nil {
		return nil, err
	}
	return scanToken(s.q.QueryRow(ctx, `SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by WHERE t.id = $1`, id))
}

func (s *Store) ListAPITokens(ctx context.Context, orgID uuid.UUID) ([]APIToken, error) {
	rows, err := s.q.Query(ctx, `SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
		WHERE t.org_id = $1 AND t.revoked_at IS NULL ORDER BY t.created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) APITokenByHash(ctx context.Context, hash []byte) (*APIToken, error) {
	return scanToken(s.q.QueryRow(ctx, `SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
		WHERE t.token_hash = $1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())`, hash))
}

func (s *Store) APITokenByID(ctx context.Context, orgID, id uuid.UUID) (*APIToken, error) {
	return scanToken(s.q.QueryRow(ctx, `SELECT `+tokenCols+` FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
		WHERE t.org_id = $1 AND t.id = $2`, orgID, id))
}

func (s *Store) TouchAPIToken(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.q.Exec(ctx, `UPDATE api_tokens SET last_used_at = now(), last_used_ip = $2 WHERE id = $1
		AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute' OR last_used_ip <> $2)`, id, ip)
	return err
}

func (s *Store) RollAPIToken(ctx context.Context, id uuid.UUID, prefix string, hash []byte) error {
	_, err := s.q.Exec(ctx, `UPDATE api_tokens SET prefix = $2, token_hash = $3 WHERE id = $1`, id, prefix, hash)
	return err
}

func (s *Store) RevokeAPIToken(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE org_id = $1 AND id = $2 AND revoked_at IS NULL`, orgID, id)
	return tag.RowsAffected() > 0, err
}

// ---- SSO ----

const ssoCols = `id, org_id, name, issuer, client_id, client_secret_enc, scopes, groups_claim, role_mappings, default_role,
	jit_provisioning, enforce_sso, enabled, created_at, updated_at`

func scanSSO(row pgx.Row) (*SSOConnection, error) {
	var c SSOConnection
	var mappings []byte
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.Issuer, &c.ClientID, &c.ClientSecretEnc, &c.Scopes, &c.GroupsClaim, &mappings,
		&c.DefaultRole, &c.JITProvisioning, &c.EnforceSSO, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	c.RoleMappings = []RoleMapping{}
	_ = json.Unmarshal(mappings, &c.RoleMappings)
	return &c, nil
}

func (s *Store) SSOConnectionForOrg(ctx context.Context, orgID uuid.UUID) (*SSOConnection, error) {
	return scanSSO(s.q.QueryRow(ctx, `SELECT `+ssoCols+` FROM sso_connections WHERE org_id = $1`, orgID))
}

func (s *Store) SSOConnectionByID(ctx context.Context, id uuid.UUID) (*SSOConnection, error) {
	return scanSSO(s.q.QueryRow(ctx, `SELECT `+ssoCols+` FROM sso_connections WHERE id = $1`, id))
}

// SSOConnectionForDomain returns the enabled connection whose org has verified the email domain.
func (s *Store) SSOConnectionForDomain(ctx context.Context, domain string) (*SSOConnection, error) {
	return scanSSO(s.q.QueryRow(ctx, `SELECT `+prefixCols("c", ssoCols)+` FROM sso_connections c
		JOIN sso_domains d ON d.org_id = c.org_id
		WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND c.enabled`, domain))
}

func (s *Store) UpsertSSOConnection(ctx context.Context, c SSOConnection) (*SSOConnection, error) {
	mappings, _ := json.Marshal(c.RoleMappings)
	if c.Scopes == nil {
		c.Scopes = []string{"openid", "email", "profile"}
	}
	return scanSSO(s.q.QueryRow(ctx, `INSERT INTO sso_connections(org_id, name, issuer, client_id, client_secret_enc, scopes, groups_claim,
		role_mappings, default_role, jit_provisioning, enforce_sso, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (org_id) DO UPDATE SET name = EXCLUDED.name, issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
		client_secret_enc = EXCLUDED.client_secret_enc, scopes = EXCLUDED.scopes, groups_claim = EXCLUDED.groups_claim,
		role_mappings = EXCLUDED.role_mappings, default_role = EXCLUDED.default_role, jit_provisioning = EXCLUDED.jit_provisioning,
		enforce_sso = EXCLUDED.enforce_sso, enabled = EXCLUDED.enabled, updated_at = now() RETURNING `+ssoCols,
		c.OrgID, c.Name, c.Issuer, c.ClientID, c.ClientSecretEnc, c.Scopes, c.GroupsClaim, mappings, c.DefaultRole,
		c.JITProvisioning, c.EnforceSSO, c.Enabled))
}

func (s *Store) DeleteSSOConnection(ctx context.Context, orgID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM sso_connections WHERE org_id = $1`, orgID)
	return err
}

// SSOEnforcedForUser reports whether any org the user belongs to enforces SSO for the user's email domain.
func (s *Store) SSOEnforcedForDomain(ctx context.Context, domain string) (bool, error) {
	var ok bool
	err := s.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sso_connections c JOIN sso_domains d ON d.org_id = c.org_id
		WHERE d.domain = $1 AND d.verified_at IS NOT NULL AND c.enabled AND c.enforce_sso)`, domain).Scan(&ok)
	return ok, err
}

func (s *Store) ListSSODomains(ctx context.Context, orgID uuid.UUID) ([]SSODomain, error) {
	rows, err := s.q.Query(ctx, `SELECT id, org_id, domain, verification_token, verified_at, created_at FROM sso_domains
		WHERE org_id = $1 ORDER BY domain`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SSODomain{}
	for rows.Next() {
		var d SSODomain
		if err := rows.Scan(&d.ID, &d.OrgID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) SSODomainByID(ctx context.Context, orgID, id uuid.UUID) (*SSODomain, error) {
	var d SSODomain
	err := s.q.QueryRow(ctx, `SELECT id, org_id, domain, verification_token, verified_at, created_at FROM sso_domains
		WHERE org_id = $1 AND id = $2`, orgID, id).Scan(&d.ID, &d.OrgID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &d, nil
}

func (s *Store) CreateSSODomain(ctx context.Context, orgID uuid.UUID, domain, token string, verified bool) (*SSODomain, error) {
	var d SSODomain
	err := s.q.QueryRow(ctx, `INSERT INTO sso_domains(org_id, domain, verification_token, verified_at)
		VALUES ($1,$2,$3, CASE WHEN $4 THEN now() END)
		RETURNING id, org_id, domain, verification_token, verified_at, created_at`, orgID, domain, token, verified).
		Scan(&d.ID, &d.OrgID, &d.Domain, &d.VerificationToken, &d.VerifiedAt, &d.CreatedAt)
	return &d, err
}

func (s *Store) VerifySSODomain(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `UPDATE sso_domains SET verified_at = now() WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteSSODomain(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM sso_domains WHERE org_id = $1 AND id = $2`, orgID, id)
	return tag.RowsAffected() > 0, err
}

func (s *Store) CreateSSOState(ctx context.Context, state string, connID uuid.UUID, nonce, verifier, redirect string) error {
	_, err := s.q.Exec(ctx, `INSERT INTO sso_states(state, connection_id, nonce, code_verifier, redirect_to, expires_at)
		VALUES ($1,$2,$3,$4,$5, now() + interval '10 minutes')`, state, connID, nonce, verifier, redirect)
	return err
}

func (s *Store) ConsumeSSOState(ctx context.Context, state string) (connID uuid.UUID, nonce, verifier, redirect string, err error) {
	err = s.q.QueryRow(ctx, `DELETE FROM sso_states WHERE state = $1 AND expires_at > now()
		RETURNING connection_id, nonce, code_verifier, redirect_to`, state).Scan(&connID, &nonce, &verifier, &redirect)
	err = db.NotFound(err)
	return
}

// ---- SCIM ----

func (s *Store) CreateSCIMToken(ctx context.Context, orgID uuid.UUID, name, prefix string, hash []byte, by uuid.UUID) (*SCIMToken, error) {
	var t SCIMToken
	err := s.q.QueryRow(ctx, `INSERT INTO scim_tokens(org_id, name, prefix, token_hash, created_by) VALUES ($1,$2,$3,$4,$5)
		RETURNING id, org_id, name, prefix, created_by, last_used_at, created_at`, orgID, name, prefix, hash, by).
		Scan(&t.ID, &t.OrgID, &t.Name, &t.Prefix, &t.CreatedBy, &t.LastUsedAt, &t.CreatedAt)
	return &t, err
}

func (s *Store) ListSCIMTokens(ctx context.Context, orgID uuid.UUID) ([]SCIMToken, error) {
	rows, err := s.q.Query(ctx, `SELECT id, org_id, name, prefix, created_by, last_used_at, created_at FROM scim_tokens
		WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SCIMToken{}
	for rows.Next() {
		var t SCIMToken
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.Prefix, &t.CreatedBy, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) SCIMTokenOrg(ctx context.Context, hash []byte) (uuid.UUID, uuid.UUID, error) {
	var id, org uuid.UUID
	err := s.q.QueryRow(ctx, `UPDATE scim_tokens SET last_used_at = now() WHERE token_hash = $1 RETURNING id, org_id`, hash).Scan(&id, &org)
	return id, org, db.NotFound(err)
}

func (s *Store) DeleteSCIMToken(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM scim_tokens WHERE org_id = $1 AND id = $2`, orgID, id)
	return tag.RowsAffected() > 0, err
}

// SCIMUsers lists users that are members of the org, optionally filtered by email (userName) or externalId.
func (s *Store) SCIMUsers(ctx context.Context, orgID uuid.UUID, email, externalID string, offset, limit int) ([]User, int, error) {
	var total int
	if err := s.q.QueryRow(ctx, `SELECT count(*) FROM users u JOIN memberships m ON m.user_id = u.id AND m.org_id = $1
		WHERE ($2 = '' OR u.email = $2::citext) AND ($3 = '' OR u.scim_external_id = $3)`, orgID, email, externalID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.q.Query(ctx, `SELECT `+prefixCols("u", userCols)+` FROM users u JOIN memberships m ON m.user_id = u.id AND m.org_id = $1
		WHERE ($2 = '' OR u.email = $2::citext) AND ($3 = '' OR u.scim_external_id = $3)
		ORDER BY u.created_at OFFSET $4 LIMIT $5`, orgID, email, externalID, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *u)
	}
	return out, total, rows.Err()
}

func (s *Store) SCIMUser(ctx context.Context, orgID, userID uuid.UUID) (*User, error) {
	return scanUser(s.q.QueryRow(ctx, `SELECT `+prefixCols("u", userCols)+` FROM users u
		JOIN memberships m ON m.user_id = u.id AND m.org_id = $1 WHERE u.id = $2`, orgID, userID))
}

const groupCols = `g.id, g.org_id, g.display_name, g.external_id, g.role,
	COALESCE((SELECT array_agg(gm.user_id) FROM scim_group_members gm WHERE gm.group_id = g.id), '{}'), g.created_at, g.updated_at`

func scanGroup(row pgx.Row) (*SCIMGroup, error) {
	var g SCIMGroup
	err := row.Scan(&g.ID, &g.OrgID, &g.DisplayName, &g.ExternalID, &g.Role, &g.MemberIDs, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &g, nil
}

func (s *Store) SCIMGroups(ctx context.Context, orgID uuid.UUID, displayName string, offset, limit int) ([]SCIMGroup, int, error) {
	var total int
	if err := s.q.QueryRow(ctx, `SELECT count(*) FROM scim_groups WHERE org_id = $1 AND ($2 = '' OR display_name = $2)`,
		orgID, displayName).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.q.Query(ctx, `SELECT `+groupCols+` FROM scim_groups g WHERE g.org_id = $1 AND ($2 = '' OR g.display_name = $2)
		ORDER BY g.created_at OFFSET $3 LIMIT $4`, orgID, displayName, offset, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []SCIMGroup{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *g)
	}
	return out, total, rows.Err()
}

func (s *Store) SCIMGroup(ctx context.Context, orgID, id uuid.UUID) (*SCIMGroup, error) {
	return scanGroup(s.q.QueryRow(ctx, `SELECT `+groupCols+` FROM scim_groups g WHERE g.org_id = $1 AND g.id = $2`, orgID, id))
}

func (s *Store) CreateSCIMGroup(ctx context.Context, orgID uuid.UUID, name string, externalID *string) (*SCIMGroup, error) {
	var id uuid.UUID
	if err := s.q.QueryRow(ctx, `INSERT INTO scim_groups(org_id, display_name, external_id) VALUES ($1,$2,$3) RETURNING id`,
		orgID, name, externalID).Scan(&id); err != nil {
		return nil, err
	}
	return s.SCIMGroup(ctx, orgID, id)
}

func (s *Store) UpdateSCIMGroup(ctx context.Context, orgID, id uuid.UUID, name string, externalID *string) error {
	_, err := s.q.Exec(ctx, `UPDATE scim_groups SET display_name = $3, external_id = $4, updated_at = now() WHERE org_id = $1 AND id = $2`,
		orgID, id, name, externalID)
	return err
}

func (s *Store) SetSCIMGroupRole(ctx context.Context, orgID, id uuid.UUID, role *string) error {
	_, err := s.q.Exec(ctx, `UPDATE scim_groups SET role = $3, updated_at = now() WHERE org_id = $1 AND id = $2`, orgID, id, role)
	return err
}

func (s *Store) SetSCIMGroupMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	if _, err := s.q.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, groupID); err != nil {
		return err
	}
	return s.AddSCIMGroupMembers(ctx, groupID, userIDs)
}

func (s *Store) AddSCIMGroupMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	if len(userIDs) == 0 {
		return nil
	}
	_, err := s.q.Exec(ctx, `INSERT INTO scim_group_members(group_id, user_id) SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`,
		groupID, userIDs)
	return err
}

func (s *Store) RemoveSCIMGroupMembers(ctx context.Context, groupID uuid.UUID, userIDs []uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = ANY($2)`, groupID, userIDs)
	return err
}

func (s *Store) DeleteSCIMGroup(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM scim_groups WHERE org_id = $1 AND id = $2`, orgID, id)
	return tag.RowsAffected() > 0, err
}

// UserSCIMGroupNames returns the display names of SCIM groups the user belongs to in an org.
func (s *Store) UserSCIMGroups(ctx context.Context, orgID, userID uuid.UUID) ([]SCIMGroup, error) {
	rows, err := s.q.Query(ctx, `SELECT `+groupCols+` FROM scim_groups g JOIN scim_group_members gm ON gm.group_id = g.id
		WHERE g.org_id = $1 AND gm.user_id = $2`, orgID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SCIMGroup{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// ---- Audit ----

func (s *Store) InsertAudit(ctx context.Context, e AuditEntry) (int64, error) {
	if e.Metadata == nil {
		e.Metadata = json.RawMessage(`{}`)
	}
	var id int64
	err := s.q.QueryRow(ctx, `INSERT INTO audit_logs(org_id, zone_id, actor_type, actor_id, actor_label, action, resource_type,
		resource_id, resource_name, outcome, metadata, ip, user_agent) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
		e.OrgID, e.ZoneID, e.ActorType, e.ActorID, e.ActorLabel, e.Action, e.ResourceType, e.ResourceID, e.ResourceName,
		e.Outcome, e.Metadata, e.IP, e.UserAgent).Scan(&id)
	return id, err
}

type AuditFilter struct {
	OrgID        *uuid.UUID
	ZoneID       *uuid.UUID
	ActorID      *uuid.UUID
	Action       string // prefix match
	ResourceType string
	Outcome      string
	Query        string
	Since        *time.Time
	Until        *time.Time
	Before       int64 // cursor: id < Before
	Limit        int
	// IncludeMemberAuth adds instance-level sign-in events of the org's members.
	IncludeMemberAuth bool
}

func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	rows, err := s.q.Query(ctx, `SELECT a.id, a.org_id, a.zone_id, a.actor_type, a.actor_id, a.actor_label, a.action, a.resource_type,
		a.resource_id, a.resource_name, a.outcome, a.metadata, a.ip, a.user_agent, a.created_at, COALESCE(o.name, '')
		FROM audit_logs a LEFT JOIN organizations o ON o.id = a.org_id
		WHERE ($1::uuid IS NULL OR a.org_id = $1
		       OR ($12 AND a.org_id IS NULL AND a.action LIKE 'auth.%'
		           AND a.actor_id IN (SELECT user_id FROM memberships WHERE org_id = $1)))
		  AND ($2::uuid IS NULL OR a.zone_id = $2)
		  AND ($3::uuid IS NULL OR a.actor_id = $3)
		  AND ($4 = '' OR a.action LIKE $4 || '%')
		  AND ($5 = '' OR a.resource_type = $5)
		  AND ($6 = '' OR a.outcome = $6)
		  AND ($7 = '' OR a.resource_name ILIKE '%' || $7 || '%' OR a.actor_label ILIKE '%' || $7 || '%' OR a.action ILIKE '%' || $7 || '%' OR a.ip = $7)
		  AND ($8::timestamptz IS NULL OR a.created_at >= $8)
		  AND ($9::timestamptz IS NULL OR a.created_at < $9)
		  AND ($10 = 0 OR a.id < $10)
		ORDER BY a.id DESC LIMIT $11`,
		f.OrgID, f.ZoneID, f.ActorID, f.Action, f.ResourceType, f.Outcome, f.Query, f.Since, f.Until, f.Before, f.Limit, f.IncludeMemberAuth)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.ZoneID, &e.ActorType, &e.ActorID, &e.ActorLabel, &e.Action, &e.ResourceType,
			&e.ResourceID, &e.ResourceName, &e.Outcome, &e.Metadata, &e.IP, &e.UserAgent, &e.CreatedAt, &e.OrgName); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

type DayCount struct {
	Day   time.Time `json:"day"`
	Count int       `json:"count"`
}

// AuditActivity returns per-day counts of change events for charts.
func (s *Store) AuditActivity(ctx context.Context, orgID *uuid.UUID, zoneID *uuid.UUID, days int) ([]DayCount, error) {
	rows, err := s.q.Query(ctx, `SELECT d::date, COALESCE(c.n, 0) FROM generate_series(current_date - ($3::int - 1), current_date, '1 day') d
		LEFT JOIN (SELECT date_trunc('day', created_at)::date AS day, count(*) AS n FROM audit_logs
			WHERE ($1::uuid IS NULL OR org_id = $1) AND ($2::uuid IS NULL OR zone_id = $2)
			  AND created_at >= current_date - ($3::int - 1) GROUP BY 1) c ON c.day = d::date
		ORDER BY 1`, orgID, zoneID, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DayCount{}
	for rows.Next() {
		var d DayCount
		if err := rows.Scan(&d.Day, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- Webhooks ----

const webhookCols = `w.id, w.org_id, w.name, w.url, w.secret_enc, w.events, w.enabled, w.created_by, w.created_at, w.updated_at,
	(SELECT d.status FROM webhook_deliveries d WHERE d.webhook_id = w.id ORDER BY d.id DESC LIMIT 1),
	(SELECT d.created_at FROM webhook_deliveries d WHERE d.webhook_id = w.id ORDER BY d.id DESC LIMIT 1)`

func scanWebhook(row pgx.Row) (*Webhook, error) {
	var w Webhook
	err := row.Scan(&w.ID, &w.OrgID, &w.Name, &w.URL, &w.SecretEnc, &w.Events, &w.Enabled, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt,
		&w.LastDeliveryStatus, &w.LastDeliveryAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &w, nil
}

func (s *Store) ListWebhooks(ctx context.Context, orgID uuid.UUID) ([]Webhook, error) {
	rows, err := s.q.Query(ctx, `SELECT `+webhookCols+` FROM webhooks w WHERE w.org_id = $1 ORDER BY w.created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Webhook{}
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *w)
	}
	return out, rows.Err()
}

func (s *Store) EnabledWebhooks(ctx context.Context, orgID uuid.UUID) ([]Webhook, error) {
	all, err := s.ListWebhooks(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, w := range all {
		if w.Enabled {
			out = append(out, w)
		}
	}
	return out, nil
}

func (s *Store) WebhookByID(ctx context.Context, orgID, id uuid.UUID) (*Webhook, error) {
	return scanWebhook(s.q.QueryRow(ctx, `SELECT `+webhookCols+` FROM webhooks w WHERE w.org_id = $1 AND w.id = $2`, orgID, id))
}

func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (*Webhook, error) {
	var id uuid.UUID
	if err := s.q.QueryRow(ctx, `INSERT INTO webhooks(org_id, name, url, secret_enc, events, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, w.OrgID, w.Name, w.URL, w.SecretEnc, w.Events, w.Enabled, w.CreatedBy).Scan(&id); err != nil {
		return nil, err
	}
	return s.WebhookByID(ctx, w.OrgID, id)
}

func (s *Store) UpdateWebhook(ctx context.Context, w Webhook) error {
	_, err := s.q.Exec(ctx, `UPDATE webhooks SET name = $3, url = $4, events = $5, enabled = $6, secret_enc = $7, updated_at = now()
		WHERE org_id = $1 AND id = $2`, w.OrgID, w.ID, w.Name, w.URL, w.Events, w.Enabled, w.SecretEnc)
	return err
}

func (s *Store) DeleteWebhook(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM webhooks WHERE org_id = $1 AND id = $2`, orgID, id)
	return tag.RowsAffected() > 0, err
}

func (s *Store) EnqueueDelivery(ctx context.Context, webhookID uuid.UUID, event string, payload []byte) error {
	_, err := s.q.Exec(ctx, `INSERT INTO webhook_deliveries(webhook_id, event, payload) VALUES ($1,$2,$3)`, webhookID, event, payload)
	return err
}

func (s *Store) ListDeliveries(ctx context.Context, webhookID uuid.UUID, limit int) ([]WebhookDelivery, error) {
	rows, err := s.q.Query(ctx, `SELECT id, webhook_id, event, payload, status, attempts, response_status, response_body,
		next_attempt_at, delivered_at, created_at FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY id DESC LIMIT $2`, webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookDelivery{}
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.Status, &d.Attempts, &d.ResponseStatus, &d.ResponseBody,
			&d.NextAttemptAt, &d.DeliveredAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ClaimDeliveries locks and returns due deliveries along with their webhook target.
type DueDelivery struct {
	WebhookDelivery
	URL       string
	SecretEnc string
}

func (s *Store) DueDeliveries(ctx context.Context, limit int) ([]DueDelivery, error) {
	rows, err := s.q.Query(ctx, `UPDATE webhook_deliveries d SET next_attempt_at = now() + interval '2 minutes'
		FROM webhooks w WHERE w.id = d.webhook_id AND d.id IN (
			SELECT id FROM webhook_deliveries WHERE status = 'pending' AND next_attempt_at <= now()
			ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED)
		RETURNING d.id, d.webhook_id, d.event, d.payload, d.status, d.attempts, w.url, w.secret_enc`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DueDelivery{}
	for rows.Next() {
		var d DueDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.Status, &d.Attempts, &d.URL, &d.SecretEnc); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RecordDeliveryAttempt(ctx context.Context, id int64, status string, respStatus *int, body string, next time.Time) error {
	_, err := s.q.Exec(ctx, `UPDATE webhook_deliveries SET status = $2, attempts = attempts + 1, response_status = $3,
		response_body = $4, next_attempt_at = $5, delivered_at = CASE WHEN $2 = 'delivered' THEN now() END WHERE id = $1`,
		id, status, respStatus, body, next)
	return err
}
