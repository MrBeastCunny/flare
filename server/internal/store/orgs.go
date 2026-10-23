package store

import (
	"context"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const orgCols = `id, name, slug, max_zones, nameserver_set_id, pdns_server_id, enforce_mfa, session_ttl_minutes,
	ip_allowlist, suspended, created_at, updated_at`

func scanOrgInto(row pgx.Row, o *Org, extra ...any) error {
	dest := []any{&o.ID, &o.Name, &o.Slug, &o.MaxZones, &o.NameserverSetID, &o.PDNSServerID, &o.EnforceMFA,
		&o.SessionTTLMinutes, &o.IPAllowlist, &o.Suspended, &o.CreatedAt, &o.UpdatedAt}
	return row.Scan(append(dest, extra...)...)
}

func (s *Store) OrgByID(ctx context.Context, id uuid.UUID) (*Org, error) {
	var o Org
	if err := scanOrgInto(s.q.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE id = $1`, id), &o); err != nil {
		return nil, db.NotFound(err)
	}
	return &o, nil
}

// OrgsByIDs returns organizations ordered by name; nil ids returns every organization.
func (s *Store) OrgsByIDs(ctx context.Context, ids []uuid.UUID) ([]Org, error) {
	rows, err := s.q.Query(ctx, `SELECT `+orgCols+` FROM organizations WHERE $1::uuid[] IS NULL OR id = ANY($1) ORDER BY lower(name)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Org{}
	for rows.Next() {
		var o Org
		if err := scanOrgInto(rows, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) OrgBySlug(ctx context.Context, slug string) (*Org, error) {
	var o Org
	if err := scanOrgInto(s.q.QueryRow(ctx, `SELECT `+orgCols+` FROM organizations WHERE slug = $1`, slug), &o); err != nil {
		return nil, db.NotFound(err)
	}
	return &o, nil
}

func (s *Store) CreateOrg(ctx context.Context, name, slug string) (*Org, error) {
	var o Org
	err := scanOrgInto(s.q.QueryRow(ctx, `INSERT INTO organizations(name, slug) VALUES ($1,$2) RETURNING `+orgCols, name, slug), &o)
	return &o, err
}

type OrgUpdate struct {
	Name              string
	EnforceMFA        bool
	SessionTTLMinutes *int
	IPAllowlist       []string
}

func (s *Store) UpdateOrg(ctx context.Context, id uuid.UUID, u OrgUpdate) error {
	if u.IPAllowlist == nil {
		u.IPAllowlist = []string{}
	}
	_, err := s.q.Exec(ctx, `UPDATE organizations SET name = $2, enforce_mfa = $3, session_ttl_minutes = $4,
		ip_allowlist = $5, updated_at = now() WHERE id = $1`, id, u.Name, u.EnforceMFA, u.SessionTTLMinutes, u.IPAllowlist)
	return err
}

type OrgAdminUpdate struct {
	MaxZones        *int
	NameserverSetID *uuid.UUID
	PDNSServerID    *uuid.UUID
	Suspended       bool
}

func (s *Store) UpdateOrgAdmin(ctx context.Context, id uuid.UUID, u OrgAdminUpdate) error {
	_, err := s.q.Exec(ctx, `UPDATE organizations SET max_zones = $2, nameserver_set_id = $3, pdns_server_id = $4,
		suspended = $5, updated_at = now() WHERE id = $1`, id, u.MaxZones, u.NameserverSetID, u.PDNSServerID, u.Suspended)
	return err
}

func (s *Store) DeleteOrg(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

func (s *Store) SlugExists(ctx context.Context, slug string) (bool, error) {
	var ok bool
	return ok, s.q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organizations WHERE slug = $1)`, slug).Scan(&ok)
}

func (s *Store) OrgsForUser(ctx context.Context, userID uuid.UUID) ([]OrgMembership, error) {
	rows, err := s.q.Query(ctx, `SELECT `+prefixCols("o", orgCols)+`, m.role, m.zone_ids,
		(SELECT count(*) FROM zones z WHERE z.org_id = o.id)
		FROM memberships m JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id = $1 AND NOT m.suspended ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgMembership{}
	for rows.Next() {
		var om OrgMembership
		if err := scanOrgInto(rows, &om.Org, &om.Role, &om.ZoneIDs, &om.ZoneCount); err != nil {
			return nil, err
		}
		out = append(out, om)
	}
	return out, rows.Err()
}

type AdminOrg struct {
	Org
	MemberCount int `json:"member_count"`
	ZoneCount   int `json:"zone_count"`
}

func (s *Store) ListOrgs(ctx context.Context, q string) ([]AdminOrg, error) {
	rows, err := s.q.Query(ctx, `SELECT `+prefixCols("o", orgCols)+`,
		(SELECT count(*) FROM memberships m WHERE m.org_id = o.id),
		(SELECT count(*) FROM zones z WHERE z.org_id = o.id)
		FROM organizations o WHERE ($1 = '' OR o.name ILIKE '%' || $1 || '%' OR o.slug ILIKE '%' || $1 || '%')
		ORDER BY o.created_at DESC`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminOrg{}
	for rows.Next() {
		var a AdminOrg
		if err := scanOrgInto(rows, &a.Org, &a.MemberCount, &a.ZoneCount); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- Memberships ----

const memberSelect = `SELECT m.id, m.org_id, m.user_id, m.role, m.zone_ids, m.source, m.suspended, m.created_at, m.updated_at,
	u.email, u.name, u.totp_enabled, u.last_login_at, u.disabled
	FROM memberships m JOIN users u ON u.id = m.user_id`

func scanMember(row pgx.Row) (*Membership, error) {
	var m Membership
	err := row.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.ZoneIDs, &m.Source, &m.Suspended, &m.CreatedAt, &m.UpdatedAt,
		&m.UserEmail, &m.UserName, &m.UserTOTP, &m.UserLastLoginAt, &m.UserDisabled)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &m, nil
}

func (s *Store) Membership(ctx context.Context, orgID, userID uuid.UUID) (*Membership, error) {
	return scanMember(s.q.QueryRow(ctx, memberSelect+` WHERE m.org_id = $1 AND m.user_id = $2`, orgID, userID))
}

func (s *Store) MembershipByID(ctx context.Context, orgID, id uuid.UUID) (*Membership, error) {
	return scanMember(s.q.QueryRow(ctx, memberSelect+` WHERE m.org_id = $1 AND m.id = $2`, orgID, id))
}

func (s *Store) ListMembers(ctx context.Context, orgID uuid.UUID) ([]Membership, error) {
	rows, err := s.q.Query(ctx, memberSelect+` WHERE m.org_id = $1 ORDER BY u.email`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Membership{}
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *Store) AddMember(ctx context.Context, orgID, userID uuid.UUID, role string, zoneIDs []uuid.UUID, source string) error {
	_, err := s.q.Exec(ctx, `INSERT INTO memberships(org_id, user_id, role, zone_ids, source) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role, zone_ids = EXCLUDED.zone_ids, updated_at = now()`,
		orgID, userID, role, zoneIDs, source)
	return err
}

// EnsureMember adds a membership only if none exists. Returns true when created.
func (s *Store) EnsureMember(ctx context.Context, orgID, userID uuid.UUID, role, source string) (bool, error) {
	tag, err := s.q.Exec(ctx, `INSERT INTO memberships(org_id, user_id, role, source) VALUES ($1,$2,$3,$4)
		ON CONFLICT (org_id, user_id) DO NOTHING`, orgID, userID, role, source)
	return tag.RowsAffected() > 0, err
}

func (s *Store) UpdateMember(ctx context.Context, orgID, id uuid.UUID, role string, zoneIDs []uuid.UUID) error {
	_, err := s.q.Exec(ctx, `UPDATE memberships SET role = $3, zone_ids = $4, updated_at = now() WHERE org_id = $1 AND id = $2`,
		orgID, id, role, zoneIDs)
	return err
}

func (s *Store) SetMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	_, err := s.q.Exec(ctx, `UPDATE memberships SET role = $3, updated_at = now() WHERE org_id = $1 AND user_id = $2`,
		orgID, userID, role)
	return err
}

func (s *Store) SetMemberSuspended(ctx context.Context, orgID, userID uuid.UUID, suspended bool) error {
	_, err := s.q.Exec(ctx, `UPDATE memberships SET suspended = $3, updated_at = now() WHERE org_id = $1 AND user_id = $2`,
		orgID, userID, suspended)
	return err
}

func (s *Store) RemoveMember(ctx context.Context, orgID, userID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM memberships WHERE org_id = $1 AND user_id = $2`, orgID, userID)
	return err
}

func (s *Store) CountOwners(ctx context.Context, orgID uuid.UUID) (int, error) {
	var n int
	return n, s.q.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner'`, orgID).Scan(&n)
}

// ---- Invitations ----

const inviteCols = `i.id, i.org_id, i.email, i.role, i.zone_ids, i.invited_by, COALESCE(NULLIF(u.name,''), u.email::text, ''),
	i.expires_at, i.accepted_at, i.created_at`

func scanInvite(row pgx.Row) (*Invitation, error) {
	var i Invitation
	err := row.Scan(&i.ID, &i.OrgID, &i.Email, &i.Role, &i.ZoneIDs, &i.InvitedBy, &i.InviterName, &i.ExpiresAt, &i.AcceptedAt, &i.CreatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &i, nil
}

func (s *Store) CreateInvitation(ctx context.Context, orgID uuid.UUID, email, role string, zoneIDs []uuid.UUID,
	tokenHash []byte, invitedBy *uuid.UUID) (*Invitation, error) {
	// Replace any pending invitation for the same address.
	if _, err := s.q.Exec(ctx, `DELETE FROM invitations WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL`, orgID, email); err != nil {
		return nil, err
	}
	var id uuid.UUID
	if err := s.q.QueryRow(ctx, `INSERT INTO invitations(org_id, email, role, zone_ids, token_hash, invited_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6, now() + interval '7 days') RETURNING id`,
		orgID, email, role, zoneIDs, tokenHash, invitedBy).Scan(&id); err != nil {
		return nil, err
	}
	return scanInvite(s.q.QueryRow(ctx, `SELECT `+inviteCols+` FROM invitations i LEFT JOIN users u ON u.id = i.invited_by WHERE i.id = $1`, id))
}

func (s *Store) ListInvitations(ctx context.Context, orgID uuid.UUID) ([]Invitation, error) {
	rows, err := s.q.Query(ctx, `SELECT `+inviteCols+` FROM invitations i LEFT JOIN users u ON u.id = i.invited_by
		WHERE i.org_id = $1 AND i.accepted_at IS NULL ORDER BY i.created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Invitation{}
	for rows.Next() {
		i, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *i)
	}
	return out, rows.Err()
}

func (s *Store) InvitationByToken(ctx context.Context, tokenHash []byte) (*Invitation, error) {
	return scanInvite(s.q.QueryRow(ctx, `SELECT `+inviteCols+` FROM invitations i LEFT JOIN users u ON u.id = i.invited_by
		WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.expires_at > now()`, tokenHash))
}

func (s *Store) InvitationByID(ctx context.Context, orgID, id uuid.UUID) (*Invitation, error) {
	return scanInvite(s.q.QueryRow(ctx, `SELECT `+inviteCols+` FROM invitations i LEFT JOIN users u ON u.id = i.invited_by
		WHERE i.org_id = $1 AND i.id = $2`, orgID, id))
}

func (s *Store) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `UPDATE invitations SET accepted_at = now() WHERE id = $1`, id)
	return err
}

func (s *Store) RefreshInvitation(ctx context.Context, id uuid.UUID, tokenHash []byte) error {
	_, err := s.q.Exec(ctx, `UPDATE invitations SET token_hash = $2, expires_at = now() + interval '7 days' WHERE id = $1`, id, tokenHash)
	return err
}

func (s *Store) DeleteInvitation(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM invitations WHERE org_id = $1 AND id = $2`, orgID, id)
	return tag.RowsAffected() > 0, err
}

// ---- PowerDNS servers ----

const serverCols = `s.id, s.name, s.api_url, s.api_key_enc, s.server_id, s.description, s.is_default, s.enabled,
	s.last_status, s.last_checked_at, s.version, (SELECT count(*) FROM zones z WHERE z.pdns_server_id = s.id),
	s.created_at, s.updated_at`

func scanServer(row pgx.Row) (*PDNSServer, error) {
	var p PDNSServer
	err := row.Scan(&p.ID, &p.Name, &p.APIURL, &p.APIKeyEnc, &p.ServerID, &p.Description, &p.IsDefault, &p.Enabled,
		&p.LastStatus, &p.LastCheckedAt, &p.Version, &p.ZoneCount, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &p, nil
}

func (s *Store) ListServers(ctx context.Context) ([]PDNSServer, error) {
	rows, err := s.q.Query(ctx, `SELECT `+serverCols+` FROM pdns_servers s ORDER BY s.is_default DESC, s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PDNSServer{}
	for rows.Next() {
		p, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) ServerByID(ctx context.Context, id uuid.UUID) (*PDNSServer, error) {
	return scanServer(s.q.QueryRow(ctx, `SELECT `+serverCols+` FROM pdns_servers s WHERE s.id = $1`, id))
}

func (s *Store) DefaultServer(ctx context.Context) (*PDNSServer, error) {
	return scanServer(s.q.QueryRow(ctx, `SELECT `+serverCols+` FROM pdns_servers s WHERE s.enabled
		ORDER BY s.is_default DESC, s.created_at LIMIT 1`))
}

type ServerInput struct {
	Name        string
	APIURL      string
	APIKeyEnc   string
	ServerID    string
	Description string
	IsDefault   bool
	Enabled     bool
}

func (s *Store) CreateServer(ctx context.Context, in ServerInput) (*PDNSServer, error) {
	if in.IsDefault {
		if _, err := s.q.Exec(ctx, `UPDATE pdns_servers SET is_default = false WHERE is_default`); err != nil {
			return nil, err
		}
	}
	var id uuid.UUID
	if err := s.q.QueryRow(ctx, `INSERT INTO pdns_servers(name, api_url, api_key_enc, server_id, description, is_default, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`, in.Name, in.APIURL, in.APIKeyEnc, in.ServerID, in.Description,
		in.IsDefault, in.Enabled).Scan(&id); err != nil {
		return nil, err
	}
	return s.ServerByID(ctx, id)
}

func (s *Store) UpdateServer(ctx context.Context, id uuid.UUID, in ServerInput) error {
	if in.IsDefault {
		if _, err := s.q.Exec(ctx, `UPDATE pdns_servers SET is_default = false WHERE is_default AND id <> $1`, id); err != nil {
			return err
		}
	}
	_, err := s.q.Exec(ctx, `UPDATE pdns_servers SET name = $2, api_url = $3, api_key_enc = $4, server_id = $5,
		description = $6, is_default = $7, enabled = $8, updated_at = now() WHERE id = $1`,
		id, in.Name, in.APIURL, in.APIKeyEnc, in.ServerID, in.Description, in.IsDefault, in.Enabled)
	return err
}

func (s *Store) SetServerStatus(ctx context.Context, id uuid.UUID, status, version string) error {
	_, err := s.q.Exec(ctx, `UPDATE pdns_servers SET last_status = $2, version = CASE WHEN $3 = '' THEN version ELSE $3 END,
		last_checked_at = now() WHERE id = $1`, id, status, version)
	return err
}

func (s *Store) DeleteServer(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM pdns_servers WHERE id = $1`, id)
	return err
}

// ---- Nameserver sets ----

const nsCols = `n.id, n.name, n.nameservers, n.hostmaster, n.is_default,
	(SELECT count(*) FROM zones z WHERE z.nameserver_set_id = n.id), n.created_at, n.updated_at`

func scanNS(row pgx.Row) (*NameserverSet, error) {
	var n NameserverSet
	err := row.Scan(&n.ID, &n.Name, &n.Nameservers, &n.Hostmaster, &n.IsDefault, &n.ZoneCount, &n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &n, nil
}

func (s *Store) ListNameserverSets(ctx context.Context) ([]NameserverSet, error) {
	rows, err := s.q.Query(ctx, `SELECT `+nsCols+` FROM nameserver_sets n ORDER BY n.is_default DESC, n.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []NameserverSet{}
	for rows.Next() {
		n, err := scanNS(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (s *Store) NameserverSetByID(ctx context.Context, id uuid.UUID) (*NameserverSet, error) {
	return scanNS(s.q.QueryRow(ctx, `SELECT `+nsCols+` FROM nameserver_sets n WHERE n.id = $1`, id))
}

func (s *Store) DefaultNameserverSet(ctx context.Context) (*NameserverSet, error) {
	return scanNS(s.q.QueryRow(ctx, `SELECT `+nsCols+` FROM nameserver_sets n ORDER BY n.is_default DESC, n.created_at LIMIT 1`))
}

func (s *Store) SaveNameserverSet(ctx context.Context, id *uuid.UUID, name string, ns []string, hostmaster string, isDefault bool) (*NameserverSet, error) {
	if isDefault {
		if _, err := s.q.Exec(ctx, `UPDATE nameserver_sets SET is_default = false WHERE is_default AND ($1::uuid IS NULL OR id <> $1)`, id); err != nil {
			return nil, err
		}
	}
	var out uuid.UUID
	if id == nil {
		if err := s.q.QueryRow(ctx, `INSERT INTO nameserver_sets(name, nameservers, hostmaster, is_default) VALUES ($1,$2,$3,$4) RETURNING id`,
			name, ns, hostmaster, isDefault).Scan(&out); err != nil {
			return nil, err
		}
	} else {
		out = *id
		if _, err := s.q.Exec(ctx, `UPDATE nameserver_sets SET name = $2, nameservers = $3, hostmaster = $4, is_default = $5,
			updated_at = now() WHERE id = $1`, out, name, ns, hostmaster, isDefault); err != nil {
			return nil, err
		}
	}
	return s.NameserverSetByID(ctx, out)
}

func (s *Store) DeleteNameserverSet(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM nameserver_sets WHERE id = $1`, id)
	return err
}

// ---- Zones ----

const zoneCols = `z.id, z.org_id, z.pdns_server_id, z.nameserver_set_id, z.name, z.kind, z.status, z.assigned_nameservers,
	z.observed_nameservers, z.last_ns_check_at, z.activated_at, z.created_by, z.created_at, z.updated_at, o.name, s.name`

const zoneFrom = ` FROM zones z JOIN organizations o ON o.id = z.org_id JOIN pdns_servers s ON s.id = z.pdns_server_id`

func scanZone(row pgx.Row) (*Zone, error) {
	var z Zone
	err := row.Scan(&z.ID, &z.OrgID, &z.PDNSServerID, &z.NameserverSetID, &z.Name, &z.Kind, &z.Status, &z.AssignedNameservers,
		&z.ObservedNameservers, &z.LastNSCheckAt, &z.ActivatedAt, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt, &z.OrgName, &z.PDNSServerName)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &z, nil
}

func collectZones(rows pgx.Rows, err error) ([]Zone, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Zone{}
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *z)
	}
	return out, rows.Err()
}

// ListZones returns zones for an org. When zoneIDs is non-nil, results are restricted to those IDs.
func (s *Store) ListZones(ctx context.Context, orgID uuid.UUID, zoneIDs []uuid.UUID) ([]Zone, error) {
	return collectZones(s.q.Query(ctx, `SELECT `+zoneCols+zoneFrom+`
		WHERE z.org_id = $1 AND ($2::uuid[] IS NULL OR z.id = ANY($2)) ORDER BY z.name`, orgID, zoneIDs))
}

func (s *Store) ListAllZones(ctx context.Context, q string) ([]Zone, error) {
	return collectZones(s.q.Query(ctx, `SELECT `+zoneCols+zoneFrom+`
		WHERE ($1 = '' OR z.name ILIKE '%' || $1 || '%') ORDER BY z.name`, q))
}

// ZonesByNameserverSet returns every zone assigned to a nameserver set.
func (s *Store) ZonesByNameserverSet(ctx context.Context, setID uuid.UUID) ([]Zone, error) {
	return collectZones(s.q.Query(ctx, `SELECT `+zoneCols+zoneFrom+` WHERE z.nameserver_set_id = $1 ORDER BY z.name`, setID))
}

func (s *Store) ZonesByStatus(ctx context.Context, statuses []string, olderThan time.Duration) ([]Zone, error) {
	return collectZones(s.q.Query(ctx, `SELECT `+zoneCols+zoneFrom+`
		WHERE z.status = ANY($1) AND (z.last_ns_check_at IS NULL OR z.last_ns_check_at < now() - make_interval(secs => $2))
		ORDER BY z.last_ns_check_at NULLS FIRST LIMIT 200`, statuses, olderThan.Seconds()))
}

func (s *Store) ZoneByID(ctx context.Context, orgID, id uuid.UUID) (*Zone, error) {
	return scanZone(s.q.QueryRow(ctx, `SELECT `+zoneCols+zoneFrom+` WHERE z.org_id = $1 AND z.id = $2`, orgID, id))
}

func (s *Store) ZoneByName(ctx context.Context, name string) (*Zone, error) {
	return scanZone(s.q.QueryRow(ctx, `SELECT `+zoneCols+zoneFrom+` WHERE z.name = $1`, name))
}

func (s *Store) CountZones(ctx context.Context, orgID uuid.UUID) (int, error) {
	var n int
	return n, s.q.QueryRow(ctx, `SELECT count(*) FROM zones WHERE org_id = $1`, orgID).Scan(&n)
}

type NewZone struct {
	OrgID           uuid.UUID
	PDNSServerID    uuid.UUID
	NameserverSetID *uuid.UUID
	Name            string
	Kind            string
	Status          string
	Nameservers     []string
	CreatedBy       *uuid.UUID
}

func (s *Store) CreateZone(ctx context.Context, n NewZone) (*Zone, error) {
	var id uuid.UUID
	err := s.q.QueryRow(ctx, `INSERT INTO zones(org_id, pdns_server_id, nameserver_set_id, name, kind, status, assigned_nameservers, created_by,
		activated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, CASE WHEN $6 = 'active' THEN now() END) RETURNING id`,
		n.OrgID, n.PDNSServerID, n.NameserverSetID, n.Name, n.Kind, n.Status, n.Nameservers, n.CreatedBy).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.ZoneByID(ctx, n.OrgID, id)
}

func (s *Store) UpdateZoneNSCheck(ctx context.Context, id uuid.UUID, status string, observed []string) error {
	if observed == nil {
		observed = []string{}
	}
	_, err := s.q.Exec(ctx, `UPDATE zones SET status = $2, observed_nameservers = $3, last_ns_check_at = now(),
		activated_at = CASE WHEN $2 = 'active' AND activated_at IS NULL THEN now() ELSE activated_at END,
		updated_at = now() WHERE id = $1`, id, status, observed)
	return err
}

func (s *Store) SetZoneStatus(ctx context.Context, id uuid.UUID, status string) error {
	_, err := s.q.Exec(ctx, `UPDATE zones SET status = $2, updated_at = now() WHERE id = $1`, id, status)
	return err
}

func (s *Store) SetZoneKind(ctx context.Context, id uuid.UUID, kind string) error {
	_, err := s.q.Exec(ctx, `UPDATE zones SET kind = $2, updated_at = now() WHERE id = $1`, id, kind)
	return err
}

func (s *Store) SetZoneNameservers(ctx context.Context, id uuid.UUID, setID *uuid.UUID, ns []string) error {
	_, err := s.q.Exec(ctx, `UPDATE zones SET nameserver_set_id = $2, assigned_nameservers = $3, updated_at = now() WHERE id = $1`, id, setID, ns)
	return err
}

func (s *Store) MoveZone(ctx context.Context, id, orgID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `UPDATE zones SET org_id = $2, updated_at = now() WHERE id = $1`, id, orgID)
	return err
}

func (s *Store) DeleteZone(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM zones WHERE id = $1`, id)
	return err
}

// ZoneCountsByStatus returns counts of zones per status for an org (nil = whole instance).
func (s *Store) ZoneCountsByStatus(ctx context.Context, orgID *uuid.UUID) (map[string]int, error) {
	rows, err := s.q.Query(ctx, `SELECT status, count(*) FROM zones WHERE ($1::uuid IS NULL OR org_id = $1) GROUP BY status`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}
