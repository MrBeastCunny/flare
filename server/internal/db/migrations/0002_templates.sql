-- Zone templates: reusable record sets applied when creating zones or on demand.
-- org_id NULL marks an instance-wide template managed by administrators.
CREATE TABLE zone_templates (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    records     JSONB NOT NULL DEFAULT '[]',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX zone_templates_name ON zone_templates (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));
