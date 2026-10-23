-- Global API tokens are created by instance administrators and are not owned by one organization.
-- org_id NULL marks a global token; org_ids limits it to some organizations (NULL = every
-- organization, including ones created later) and instance_role grants access to the admin API.
ALTER TABLE api_tokens ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE api_tokens ADD COLUMN org_ids UUID[];
ALTER TABLE api_tokens ADD COLUMN instance_role TEXT NOT NULL DEFAULT 'none'
    CHECK (instance_role IN ('none','orgs','admin'));
ALTER TABLE api_tokens DROP CONSTRAINT api_tokens_role_check;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_role_check CHECK (role IN ('org_admin','admin','editor','viewer'));
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_scope_check CHECK (
    (org_id IS NOT NULL AND org_ids IS NULL AND instance_role = 'none') OR (org_id IS NULL AND zone_ids IS NULL));
CREATE INDEX api_tokens_global_idx ON api_tokens(created_at) WHERE org_id IS NULL;
