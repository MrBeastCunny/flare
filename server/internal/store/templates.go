package store

import (
	"context"
	"encoding/json"

	"github.com/flare-dns/flare/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const templateCols = `id, org_id, name, description, records, created_by, created_at, updated_at`

func scanTemplate(row pgx.Row) (*ZoneTemplate, error) {
	var t ZoneTemplate
	var raw []byte
	if err := row.Scan(&t.ID, &t.OrgID, &t.Name, &t.Description, &raw, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, db.NotFound(err)
	}
	t.Records = []TemplateRecord{}
	_ = json.Unmarshal(raw, &t.Records)
	return &t, nil
}

// ListTemplates returns org templates plus instance-wide ones. A nil orgID returns only instance templates.
func (s *Store) ListTemplates(ctx context.Context, orgID *uuid.UUID) ([]ZoneTemplate, error) {
	rows, err := s.q.Query(ctx, `SELECT `+templateCols+` FROM zone_templates
		WHERE org_id IS NULL OR ($1::uuid IS NOT NULL AND org_id = $1) ORDER BY org_id NULLS FIRST, lower(name)`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ZoneTemplate{}
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// TemplateForOrg returns a template visible to the org (its own or instance-wide).
func (s *Store) TemplateForOrg(ctx context.Context, orgID *uuid.UUID, id uuid.UUID) (*ZoneTemplate, error) {
	return scanTemplate(s.q.QueryRow(ctx, `SELECT `+templateCols+` FROM zone_templates
		WHERE id = $2 AND (org_id IS NULL OR ($1::uuid IS NOT NULL AND org_id = $1))`, orgID, id))
}

func (s *Store) SaveTemplate(ctx context.Context, t ZoneTemplate) (*ZoneTemplate, error) {
	if t.Records == nil {
		t.Records = []TemplateRecord{}
	}
	raw, _ := json.Marshal(t.Records)
	if t.ID == uuid.Nil {
		return scanTemplate(s.q.QueryRow(ctx, `INSERT INTO zone_templates(org_id, name, description, records, created_by)
			VALUES ($1,$2,$3,$4,$5) RETURNING `+templateCols, t.OrgID, t.Name, t.Description, raw, t.CreatedBy))
	}
	return scanTemplate(s.q.QueryRow(ctx, `UPDATE zone_templates SET name = $2, description = $3, records = $4, updated_at = now()
		WHERE id = $1 RETURNING `+templateCols, t.ID, t.Name, t.Description, raw))
}

func (s *Store) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	_, err := s.q.Exec(ctx, `DELETE FROM zone_templates WHERE id = $1`, id)
	return err
}

// UserBySCIMOrLDAP helpers -------------------------------------------------

func (s *Store) UpdateUserIdentity(ctx context.Context, id uuid.UUID, email, name string) error {
	_, err := s.q.Exec(ctx, `UPDATE users SET email = $2, name = $3, updated_at = now() WHERE id = $1`, id, email, name)
	return err
}
