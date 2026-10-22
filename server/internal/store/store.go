// Package store implements data access on top of PostgreSQL.
package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is satisfied by both the pool and transactions.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Store struct {
	Pool *pgxpool.Pool
	q    Querier
}

func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool, q: pool} }

// Tx runs fn in a transaction with a Store bound to that transaction.
func (s *Store) Tx(ctx context.Context, fn func(tx *Store) error) error {
	return pgx.BeginFunc(ctx, s.Pool, func(t pgx.Tx) error {
		return fn(&Store{Pool: s.Pool, q: t})
	})
}

// ---- Settings ----

func (s *Store) InstanceSettings(ctx context.Context) (InstanceSettings, error) {
	set := DefaultInstanceSettings()
	var raw []byte
	err := s.q.QueryRow(ctx, `SELECT value FROM settings WHERE key = 'instance'`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return set, nil
	}
	if err != nil {
		return set, err
	}
	return set, json.Unmarshal(raw, &set)
}

func (s *Store) SaveInstanceSettings(ctx context.Context, set InstanceSettings) error {
	raw, err := json.Marshal(set)
	if err != nil {
		return err
	}
	_, err = s.q.Exec(ctx, `INSERT INTO settings(key, value) VALUES ('instance', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, raw)
	return err
}

// ---- Users ----

const userCols = `id, email, name, password_hash, is_superadmin, disabled, email_verified, totp_secret,
	totp_enabled, recovery_codes, onboarded_at, last_login_at, scim_external_id, created_via, preferences,
	created_at, updated_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsSuperadmin, &u.Disabled, &u.EmailVerified,
		&u.TOTPSecret, &u.TOTPEnabled, &u.RecoveryCodes, &u.OnboardedAt, &u.LastLoginAt, &u.SCIMExternalID,
		&u.CreatedVia, &u.Preferences, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &u, nil
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	return n, s.q.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
}

func (s *Store) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.q.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

type NewUser struct {
	Email          string
	Name           string
	PasswordHash   *string
	IsSuperadmin   bool
	EmailVerified  bool
	CreatedVia     string
	SCIMExternalID *string
}

func (s *Store) CreateUser(ctx context.Context, n NewUser) (*User, error) {
	return scanUser(s.q.QueryRow(ctx, `INSERT INTO users(email, name, password_hash, is_superadmin, email_verified,
		created_via, scim_external_id) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+userCols,
		n.Email, n.Name, n.PasswordHash, n.IsSuperadmin, n.EmailVerified, n.CreatedVia, n.SCIMExternalID))
}

func (s *Store) UpdateUserProfile(ctx context.Context, id uuid.UUID, name string, prefs json.RawMessage) error {
	if prefs == nil {
		prefs = json.RawMessage(`{}`)
	}
	_, err := s.q.Exec(ctx, `UPDATE users SET name = $2, preferences = $3, updated_at = now() WHERE id = $1`, id, name, prefs)
	return err
}

func (s *Store) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET email = $2, updated_at = now() WHERE id = $1`, id, email)
	return err
}

func (s *Store) SetUserPassword(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash)
	return err
}

func (s *Store) SetUserTOTP(ctx context.Context, id uuid.UUID, secretEnc *string, enabled bool, codes []string) error {
	if codes == nil {
		codes = []string{}
	}
	_, err := s.q.Exec(ctx, `UPDATE users SET totp_secret = $2, totp_enabled = $3, recovery_codes = $4, updated_at = now()
		WHERE id = $1`, id, secretEnc, enabled, codes)
	return err
}

func (s *Store) SetRecoveryCodes(ctx context.Context, id uuid.UUID, codes []string) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET recovery_codes = $2, updated_at = now() WHERE id = $1`, id, codes)
	return err
}

func (s *Store) MarkOnboarded(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET onboarded_at = COALESCE(onboarded_at, now()) WHERE id = $1`, id)
	return err
}

func (s *Store) TouchLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, id)
	return err
}

func (s *Store) SetUserAdminFlags(ctx context.Context, id uuid.UUID, superadmin, disabled bool) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET is_superadmin = $2, disabled = $3, updated_at = now() WHERE id = $1`,
		id, superadmin, disabled)
	return err
}

func (s *Store) SetUserDisabled(ctx context.Context, id uuid.UUID, disabled bool) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET disabled = $2, updated_at = now() WHERE id = $1`, id, disabled)
	return err
}

func (s *Store) SetUserSCIM(ctx context.Context, id uuid.UUID, externalID *string, name string) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET scim_external_id = $2, name = $3, updated_at = now() WHERE id = $1`,
		id, externalID, name)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func (s *Store) CountSuperadmins(ctx context.Context) (int, error) {
	var n int
	return n, s.q.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_superadmin AND NOT disabled`).Scan(&n)
}

type AdminUser struct {
	User
	OrgCount int `json:"org_count"`
}

func (s *Store) ListUsers(ctx context.Context, q string) ([]AdminUser, error) {
	rows, err := s.q.Query(ctx, `SELECT `+prefixCols("u", userCols)+`,
		(SELECT count(*) FROM memberships m WHERE m.user_id = u.id)
		FROM users u WHERE ($1 = '' OR u.email ILIKE '%' || $1 || '%' OR u.name ILIKE '%' || $1 || '%')
		ORDER BY u.created_at DESC`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminUser{}
	for rows.Next() {
		var a AdminUser
		u := &a.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.IsSuperadmin, &u.Disabled, &u.EmailVerified,
			&u.TOTPSecret, &u.TOTPEnabled, &u.RecoveryCodes, &u.OnboardedAt, &u.LastLoginAt, &u.SCIMExternalID,
			&u.CreatedVia, &u.Preferences, &u.CreatedAt, &u.UpdatedAt, &a.OrgCount); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- Sessions ----

func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID uuid.UUID, method string, ssoConn *uuid.UUID,
	ip, ua string, ttl time.Duration) (*Session, error) {
	var se Session
	err := s.q.QueryRow(ctx, `INSERT INTO sessions(token_hash, user_id, auth_method, sso_connection_id, ip, user_agent, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, user_id, auth_method, sso_connection_id, ip, user_agent, created_at, last_seen_at, expires_at`,
		tokenHash, userID, method, ssoConn, ip, ua, time.Now().Add(ttl)).
		Scan(&se.ID, &se.UserID, &se.AuthMethod, &se.SSOConnectionID, &se.IP, &se.UserAgent, &se.CreatedAt, &se.LastSeenAt, &se.ExpiresAt)
	return &se, err
}

func (s *Store) SessionByToken(ctx context.Context, tokenHash []byte) (*Session, error) {
	var se Session
	err := s.q.QueryRow(ctx, `SELECT id, user_id, auth_method, sso_connection_id, ip, user_agent, created_at, last_seen_at, expires_at
		FROM sessions WHERE token_hash = $1 AND expires_at > now()`, tokenHash).
		Scan(&se.ID, &se.UserID, &se.AuthMethod, &se.SSOConnectionID, &se.IP, &se.UserAgent, &se.CreatedAt, &se.LastSeenAt, &se.ExpiresAt)
	if err != nil {
		return nil, db.NotFound(err)
	}
	return &se, nil
}

func (s *Store) TouchSession(ctx context.Context, id uuid.UUID, ip string) error {
	_, err := s.q.Exec(ctx, `UPDATE sessions SET last_seen_at = now(), ip = $2 WHERE id = $1`, id, ip)
	return err
}

func (s *Store) ListSessions(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := s.q.Query(ctx, `SELECT id, user_id, auth_method, sso_connection_id, ip, user_agent, created_at, last_seen_at, expires_at
		FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		var se Session
		if err := rows.Scan(&se.ID, &se.UserID, &se.AuthMethod, &se.SSOConnectionID, &se.IP, &se.UserAgent, &se.CreatedAt, &se.LastSeenAt, &se.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSession(ctx context.Context, userID, id uuid.UUID) (bool, error) {
	tag, err := s.q.Exec(ctx, `DELETE FROM sessions WHERE id = $1 AND user_id = $2`, id, userID)
	return tag.RowsAffected() > 0, err
}

func (s *Store) DeleteSessionByID(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteUserSessions(ctx context.Context, userID uuid.UUID, except *uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND ($2::uuid IS NULL OR id <> $2)`, userID, except)
	return err
}

// ---- MFA challenges ----

func (s *Store) CreateMFAChallenge(ctx context.Context, tokenHash []byte, userID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `INSERT INTO mfa_challenges(token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '10 minutes')`,
		tokenHash, userID)
	return err
}

// MFAChallenge returns the user for a valid challenge and increments its attempt counter.
func (s *Store) MFAChallenge(ctx context.Context, tokenHash []byte) (uuid.UUID, int, error) {
	var uid uuid.UUID
	var attempts int
	err := s.q.QueryRow(ctx, `UPDATE mfa_challenges SET attempts = attempts + 1
		WHERE token_hash = $1 AND expires_at > now() RETURNING user_id, attempts`, tokenHash).Scan(&uid, &attempts)
	return uid, attempts, db.NotFound(err)
}

func (s *Store) DeleteMFAChallenge(ctx context.Context, tokenHash []byte) error {
	_, err := s.q.Exec(ctx, `DELETE FROM mfa_challenges WHERE token_hash = $1`, tokenHash)
	return err
}

// ---- Password resets ----

func (s *Store) CreatePasswordReset(ctx context.Context, tokenHash []byte, userID uuid.UUID) error {
	_, err := s.q.Exec(ctx, `INSERT INTO password_resets(token_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '1 hour')`,
		tokenHash, userID)
	return err
}

// CreatePasswordResetFor issues a set-password link with a custom lifetime (admin-created accounts).
func (s *Store) CreatePasswordResetFor(ctx context.Context, tokenHash []byte, userID uuid.UUID, ttl time.Duration) error {
	_, err := s.q.Exec(ctx, `INSERT INTO password_resets(token_hash, user_id, expires_at) VALUES ($1,$2,$3)`,
		tokenHash, userID, time.Now().Add(ttl))
	return err
}

func (s *Store) ConsumePasswordReset(ctx context.Context, tokenHash []byte) (uuid.UUID, error) {
	var uid uuid.UUID
	err := s.q.QueryRow(ctx, `UPDATE password_resets SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id`, tokenHash).Scan(&uid)
	return uid, db.NotFound(err)
}

// ---- Housekeeping ----

func (s *Store) PurgeExpired(ctx context.Context) error {
	for _, q := range []string{
		`DELETE FROM sessions WHERE expires_at < now()`,
		`DELETE FROM mfa_challenges WHERE expires_at < now()`,
		`DELETE FROM password_resets WHERE expires_at < now() - interval '1 day'`,
		`DELETE FROM sso_states WHERE expires_at < now()`,
		`DELETE FROM invitations WHERE accepted_at IS NULL AND expires_at < now() - interval '30 days'`,
		`DELETE FROM webhook_deliveries WHERE created_at < now() - interval '30 days'`,
	} {
		if _, err := s.q.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) PurgeAuditLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	tag, err := s.q.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < now() - make_interval(days => $1)`, retentionDays)
	return tag.RowsAffected(), err
}

func prefixCols(alias, cols string) string {
	out := ""
	field := ""
	flush := func() {
		f := trimSpace(field)
		if f != "" {
			if out != "" {
				out += ", "
			}
			out += alias + "." + f
		}
		field = ""
	}
	for _, r := range cols {
		if r == ',' {
			flush()
			continue
		}
		field += string(r)
	}
	flush()
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
