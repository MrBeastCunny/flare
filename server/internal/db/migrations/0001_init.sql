-- Flare core schema

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               CITEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL DEFAULT '',
    password_hash       TEXT,
    is_superadmin       BOOLEAN NOT NULL DEFAULT false,
    disabled            BOOLEAN NOT NULL DEFAULT false,
    email_verified      BOOLEAN NOT NULL DEFAULT false,
    totp_secret         TEXT,
    totp_enabled        BOOLEAN NOT NULL DEFAULT false,
    recovery_codes      TEXT[] NOT NULL DEFAULT '{}',
    onboarded_at        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    scim_external_id    TEXT,
    created_via         TEXT NOT NULL DEFAULT 'password', -- password | sso | scim | invite | setup
    preferences         JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      BYTEA NOT NULL UNIQUE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_method     TEXT NOT NULL DEFAULT 'password', -- password | sso
    sso_connection_id UUID,
    ip              TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);
CREATE INDEX sessions_expires_idx ON sessions(expires_at);

-- Short-lived pending MFA challenges after password verification
CREATE TABLE mfa_challenges (
    token_hash      BYTEA PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attempts        INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE password_resets (
    token_hash      BYTEA PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ
);

-- PowerDNS authoritative servers managed by the instance administrator
CREATE TABLE pdns_servers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    api_url         TEXT NOT NULL,
    api_key_enc     TEXT NOT NULL,
    server_id       TEXT NOT NULL DEFAULT 'localhost',
    description     TEXT NOT NULL DEFAULT '',
    is_default      BOOLEAN NOT NULL DEFAULT false,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_status     TEXT NOT NULL DEFAULT 'unknown', -- unknown | healthy | unreachable
    last_checked_at TIMESTAMPTZ,
    version         TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX pdns_servers_one_default ON pdns_servers((is_default)) WHERE is_default;

-- Preset nameserver sets assigned to new zones
CREATE TABLE nameserver_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    nameservers     TEXT[] NOT NULL,
    hostmaster      TEXT NOT NULL DEFAULT '',
    is_default      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX nameserver_sets_one_default ON nameserver_sets((is_default)) WHERE is_default;

CREATE TABLE organizations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    slug                TEXT NOT NULL UNIQUE,
    max_zones           INT,               -- NULL = instance default
    nameserver_set_id   UUID REFERENCES nameserver_sets(id) ON DELETE SET NULL,
    pdns_server_id      UUID REFERENCES pdns_servers(id) ON DELETE SET NULL,
    enforce_mfa         BOOLEAN NOT NULL DEFAULT false,
    session_ttl_minutes INT,
    ip_allowlist        TEXT[] NOT NULL DEFAULT '{}',
    suspended           BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (role IN ('owner','admin','editor','viewer','auditor')),
    zone_ids        UUID[],            -- NULL = all zones
    source          TEXT NOT NULL DEFAULT 'manual', -- manual | invite | sso | scim
    suspended       BOOLEAN NOT NULL DEFAULT false, -- deactivated via SCIM
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships(user_id);

CREATE TABLE invitations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           CITEXT NOT NULL,
    role            TEXT NOT NULL,
    zone_ids        UUID[],
    token_hash      BYTEA NOT NULL UNIQUE,
    invited_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX invitations_pending_unique ON invitations(org_id, email) WHERE accepted_at IS NULL;

CREATE TABLE zones (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    pdns_server_id      UUID NOT NULL REFERENCES pdns_servers(id) ON DELETE RESTRICT,
    nameserver_set_id   UUID REFERENCES nameserver_sets(id) ON DELETE SET NULL,
    name                TEXT NOT NULL UNIQUE, -- canonical, trailing dot
    kind                TEXT NOT NULL DEFAULT 'Native',
    status              TEXT NOT NULL DEFAULT 'pending', -- pending | active | moved | paused
    assigned_nameservers TEXT[] NOT NULL DEFAULT '{}',
    observed_nameservers TEXT[] NOT NULL DEFAULT '{}',
    last_ns_check_at    TIMESTAMPTZ,
    activated_at        TIMESTAMPTZ,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX zones_org_idx ON zones(org_id);
CREATE INDEX zones_status_idx ON zones(status);

CREATE TABLE api_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    prefix          TEXT NOT NULL,
    token_hash      BYTEA NOT NULL UNIQUE,
    role            TEXT NOT NULL CHECK (role IN ('admin','editor','viewer')),
    zone_ids        UUID[],
    ip_allowlist    TEXT[] NOT NULL DEFAULT '{}',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    last_used_ip    TEXT NOT NULL DEFAULT '',
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_tokens_org_idx ON api_tokens(org_id);

CREATE TABLE sso_connections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT NOT NULL DEFAULT 'OpenID Connect',
    issuer              TEXT NOT NULL,
    client_id           TEXT NOT NULL,
    client_secret_enc   TEXT NOT NULL,
    scopes              TEXT[] NOT NULL DEFAULT '{openid,email,profile}',
    groups_claim        TEXT NOT NULL DEFAULT 'groups',
    role_mappings       JSONB NOT NULL DEFAULT '[]', -- [{group, role}]
    default_role        TEXT NOT NULL DEFAULT 'viewer',
    jit_provisioning    BOOLEAN NOT NULL DEFAULT true,
    enforce_sso         BOOLEAN NOT NULL DEFAULT false,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sso_domains (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain              CITEXT NOT NULL UNIQUE,
    verification_token  TEXT NOT NULL,
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sso_states (
    state           TEXT PRIMARY KEY,
    connection_id   UUID NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    code_verifier   TEXT NOT NULL,
    redirect_to     TEXT NOT NULL DEFAULT '/',
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE scim_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    prefix          TEXT NOT NULL,
    token_hash      BYTEA NOT NULL UNIQUE,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scim_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    display_name    TEXT NOT NULL,
    external_id     TEXT,
    role            TEXT, -- role granted to members (resolved from SSO role mappings when NULL)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, display_name)
);

CREATE TABLE scim_group_members (
    group_id        UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    -- Audit history outlives the organization it belongs to.
    org_id          UUID REFERENCES organizations(id) ON DELETE SET NULL,
    zone_id         UUID,
    actor_type      TEXT NOT NULL, -- user | api_token | scim | system
    actor_id        UUID,
    actor_label     TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL DEFAULT '',
    resource_id     TEXT NOT NULL DEFAULT '',
    resource_name   TEXT NOT NULL DEFAULT '',
    outcome         TEXT NOT NULL DEFAULT 'success', -- success | failure
    metadata        JSONB NOT NULL DEFAULT '{}',
    ip              TEXT NOT NULL DEFAULT '',
    user_agent      TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_logs_org_idx ON audit_logs(org_id, id DESC);
CREATE INDEX audit_logs_zone_idx ON audit_logs(zone_id, id DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs(actor_id, id DESC);
CREATE INDEX audit_logs_created_idx ON audit_logs(created_at);
CREATE INDEX audit_logs_action_idx ON audit_logs(action);

CREATE TABLE webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    url             TEXT NOT NULL,
    secret_enc      TEXT NOT NULL,
    events          TEXT[] NOT NULL DEFAULT '{*}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webhook_deliveries (
    id              BIGSERIAL PRIMARY KEY,
    webhook_id      UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event           TEXT NOT NULL,
    payload         JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending', -- pending | delivered | failed
    attempts        INT NOT NULL DEFAULT 0,
    response_status INT,
    response_body   TEXT NOT NULL DEFAULT '',
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX webhook_deliveries_pending_idx ON webhook_deliveries(next_attempt_at) WHERE status = 'pending';
CREATE INDEX webhook_deliveries_webhook_idx ON webhook_deliveries(webhook_id, id DESC);
