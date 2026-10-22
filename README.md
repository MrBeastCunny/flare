# Flare

Flare is a multi-tenant DNS management platform for [PowerDNS Authoritative Server](https://doc.powerdns.com/authoritative/). It gives teams a hosted-DNS experience on infrastructure you control: organizations, role-based access, single sign-on, SCIM provisioning, a complete audit trail, DNSSEC, webhooks and an API.

## Features

**DNS**
- Add a domain in three steps: enter the domain, review records found by a quick scan (or import a BIND zone file), then switch to the assigned nameservers
- Preset nameserver sets defined by the administrator; each new zone is told exactly which nameservers to use. A zone's own NS records and SOA primary follow its set: they are not edited as ordinary records, and editing a set updates every zone that uses it
- Automatic delegation checks: zones become *Active* when the registrar points at your nameservers, and *Moved* if they stop
- Record editor for A, AAAA, CNAME, ALIAS, MX, TXT, SRV, CAA, NS, PTR, HTTPS, SVCB, TLSA, SSHFP, DS, NAPTR, DNAME, LOC, URI, CERT, SMIMEA, OPENPGPKEY, HINFO, RP and SPF, with validation, comments, disabled records, bulk delete, and checks for CNAME conflicts
- BIND zone file import (merge or replace) with preview, and export
- Zone templates per organization and instance-wide: create a domain from a template, apply one to an existing zone (merge or replace), or save any zone as a template
- Reverse zones from a CIDR (`192.0.2.0/24`, `2001:db8::/48`), an IP-to-name helper for PTR records, and automatic PTR creation for A and AAAA records
- Allowed record types per forward and reverse zones, set by the administrator
- Catalog zones (RFC 9432): producer and consumer zones, and catalog membership per zone
- Record history: every change to a name, with who made it and from where
- Internationalized domain names shown in Unicode
- DNSSEC: one-click signing (ECDSA, Ed25519, RSA), NSEC or NSEC3, DS records formatted for registrars, key management for rollovers
- Zone settings: SOA timers and serial policy, primary, secondary and native zone types, AXFR ACLs, ALSO-NOTIFY, TSIG, NOTIFY, rectify and cache flush
- Multiple PowerDNS servers, per-organization server placement, adoption of zones that already exist on a server, and TSIG key management

**Organizations and access**
- Multi-tenant organizations with zone quotas
- Roles: Owner, Administrator, DNS Editor, Viewer and Auditor, optionally scoped to specific zones
- Invitations by email, or by shareable link when SMTP is not configured
- Organization security policy: required two-factor authentication, maximum session length, IP allowlists
- Scoped API tokens with zone restrictions, IP filters, expiry and rotation
- PowerDNS-compatible API at `/api/v1/servers/localhost`, so cert-manager, external-dns, octoDNS, Terraform and other PowerDNS tools work unchanged with a scoped Flare token
- Dynamic DNS (dyndns2 `/nic/update`) for routers and ddclient, authenticated with an API token

**Identity**
- Email and password sign-in with Argon2id hashing, TOTP two-factor authentication and recovery codes
- OpenID Connect single sign-on per organization (Okta, Microsoft Entra ID, Google Workspace, Keycloak, Authentik and others), domain verification, just-in-time provisioning, group-to-role mapping, and SSO enforcement
- LDAP and Active Directory sign-in with just-in-time accounts, group-to-role mapping (memberOf or group membership search), and an administrator group
- SCIM 2.0 provisioning for users and groups, with deactivation and group-driven roles
- Session management, including revoking sessions on other devices

**Governance and operations**
- Audit log of every sign-in, DNS change and administrative action, with filters, infinite scroll and CSV or JSON export
- Signed webhooks (HMAC-SHA256) with retries and a delivery log
- Instance administration: servers (statistics, runtime configuration, TSIG keys, zone adoption), nameserver sets, users (create, edit, reset 2FA, disable), organizations, global settings, SMTP, retention, and an announcement banner
- First-run setup wizard and guided user onboarding
- Prometheus metrics, health and readiness endpoints, structured JSON logs
- Light and dark themes; every table, list and dropdown is virtualized

## Compared with PowerDNS-Admin

Flare covers what [PowerDNS-Admin](https://github.com/PowerDNS-Admin/PowerDNS-Admin) does, and in a few places offers a different way to get the same result.

| PowerDNS-Admin | Flare |
| --- | --- |
| Forward and reverse zones, all record types | Same, plus reverse zones from a CIDR, an IP-to-name PTR helper and per-zone-kind type restrictions |
| Domain templates | Organization and instance-wide templates; create, apply (merge or replace) or save a zone as a template |
| Auto-PTR | Per-record option with an instance default; updates the PTR in the matching reverse zone of the same organization |
| Local users, LDAP/AD, SAML, Google/GitHub/Azure/OIDC OAuth | Local accounts with TOTP, LDAP/AD, and OpenID Connect per organization. SAML and GitHub are supported through an OIDC broker such as Keycloak, Authentik or Microsoft Entra ID |
| Administrator, Operator and User roles; per-domain user access | Instance administrators plus per-organization Owner, Administrator, DNS Editor, Viewer and Auditor roles, optionally scoped to individual zones |
| Accounts (grouping domains) | Organizations, with quotas, server placement, nameserver sets and security policy |
| Record change history and activity log | Audit log for every action, per-zone activity, record history, CSV/JSON export, webhooks |
| Dynamic DNS (`/nic/update`) | Same protocol, authenticated with a scoped API token |
| PowerDNS API proxy with API keys | PowerDNS-compatible API with scoped tokens, validation and auditing |
| DNSSEC enable, disable and key display | Same, plus algorithm choice, NSEC3 and key rollover management |
| Server configuration and statistics | Per-server statistics and runtime configuration, across several PowerDNS servers |
| Staged edits applied in one batch | Changes apply immediately; bulk operations use zone file import, templates, or the API |
| Internationalized domain names | Shown in Unicode and stored as punycode |

## Production deployment

### Requirements

- Docker Engine 24 or later with Compose v2.24 or later
- A host with ports **53/udp, 53/tcp, 80 and 443** reachable from the internet
- A DNS name for the dashboard (for example `dns.example.com`) pointing at the host
- Hostnames for your nameservers (for example `ns1.example.net` and `ns2.example.net`) with A or AAAA records, and glue records at the registrar if they are inside a domain you host

### Install

```bash
git clone https://github.com/MrBeastCunny/flare && cd flare
cp .env.example .env
# Fill in FLARE_DOMAIN, ACME_EMAIL and the four secrets:
#   openssl rand -base64 48
$EDITOR .env
docker compose up -d --build
```

Open `https://<FLARE_DOMAIN>`. The setup wizard asks for:

1. Product name and your first organization
2. The administrator account
3. The PowerDNS server (preconfigured by the compose file; just test the connection)
4. The nameserver set that new domains will be told to use
5. A final review

After setup, every user gets a short onboarding flow: profile, two-factor authentication, team invitations, and their first domain.

### What runs

| Service    | Purpose                                         | Exposed            |
| ---------- | ----------------------------------------------- | ------------------ |
| `caddy`    | TLS termination (Let's Encrypt), HTTP to HTTPS  | 80, 443            |
| `flare`    | Dashboard and API (distroless, non-root, read-only filesystem) | internal |
| `pdns`     | PowerDNS Authoritative 5.1 (gpgsql backend)     | 53/udp, 53/tcp     |
| `postgres` | PostgreSQL 17 for Flare and PowerDNS            | internal           |
| `backup`   | `pg_dump` of both databases on a schedule       | writes `./backups` |

The PowerDNS HTTP API and PostgreSQL sit on an internal-only network, so they are never reachable from outside the host.

### Secondary nameservers

For redundancy, run PowerDNS secondaries elsewhere and allow them to transfer zones:

```env
PDNS_ALLOW_AXFR_IPS=198.51.100.10/32,203.0.113.20/32
PDNS_ALSO_NOTIFY=198.51.100.10,203.0.113.20
```

Set zones to the *Primary* type in Zone settings so NOTIFY messages are sent, or add more PowerDNS servers on the **DNS servers** admin page.

### Upgrades

```bash
git pull
docker compose up -d --build
```

Database migrations run automatically at startup and are guarded by a PostgreSQL advisory lock, so several replicas can start at once. To run them explicitly:

```bash
docker compose run --rm flare migrate
```

### Backups and restore

The `backup` service writes custom-format dumps to `BACKUP_DIR` every `BACKUP_INTERVAL_SECONDS` and keeps them for `BACKUP_RETENTION_DAYS`.
To restore:

```bash
docker compose stop flare pdns
docker compose exec -T postgres pg_restore --clean --if-exists -U flare -d flare < backups/flare-<timestamp>.dump
docker compose exec -T postgres pg_restore --clean --if-exists -U flare -d pdns  < backups/pdns-<timestamp>.dump
docker compose start pdns flare
```

Keep `FLARE_SECRET_KEY` with your backups: it encrypts PowerDNS API keys, OIDC client secrets, SMTP passwords and webhook secrets.

### Break-glass access

If every administrator is locked out (lost two-factor device, misconfigured SSO enforcement):

```bash
docker compose exec flare flare reset-admin -email admin@example.com -password 'a-new-long-password'
```

This restores administrator rights, resets the password, disables two-factor authentication for that account and signs out its sessions. The action is written to the audit log.

## Development

```bash
docker compose -f docker-compose.dev.yml up --build
```

| URL                      | What                                              |
| ------------------------ | ------------------------------------------------- |
| http://localhost:5173    | Web UI with hot reload (proxies `/api` and `/scim`) |
| http://localhost:8080    | API with live reload (air)                        |
| http://localhost:8025    | Mailpit inbox for invitations and password resets |
| http://localhost:8081    | PowerDNS API (key `dev-pdns-api-key`)             |
| `dig @127.0.0.1 -p 5300` | DNS                                               |

Host ports can be changed with `DEV_WEB_PORT`, `DEV_API_PORT`, `DEV_PG_PORT`, `DEV_PDNS_API_PORT`, `DEV_DNS_PORT` and `DEV_MAIL_PORT`.

Tests and checks:

```bash
cd server && go test ./... && go vet ./...
cd web && pnpm typecheck && pnpm build
```

## Configuration

All settings are environment variables. Values marked as runtime can also be changed in **Instance settings**.

| Variable | Default | Description |
| --- | --- | --- |
| `FLARE_DATABASE_URL` | required | PostgreSQL connection string |
| `FLARE_SECRET_KEY` | required | 32 or more characters; encrypts stored secrets |
| `FLARE_PUBLIC_URL` | `http://localhost:8080` | External URL, used for links, cookies and the OIDC redirect URI |
| `FLARE_LISTEN_ADDR` | `:8080` | HTTP listen address |
| `FLARE_TRUST_PROXY` | `false` | Trust `X-Real-IP` and `X-Forwarded-For` from a reverse proxy |
| `FLARE_COOKIE_SECURE` | auto | Secure cookies; on when the public URL is https |
| `FLARE_DB_MAX_CONNS` | `20` | Connection pool size |
| `FLARE_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `FLARE_LOG_FORMAT` | `json` | `json` or `text` |
| `FLARE_DNS_RESOLVER` | `8.8.8.8:53` | Resolver for delegation and domain verification checks |
| `FLARE_NS_CHECK_INTERVAL` | `5m` | How often pending zones are re-checked |
| `FLARE_SESSION_TTL` | `168h` | Default session lifetime (runtime setting takes precedence) |
| `FLARE_METRICS_TOKEN` | empty | Bearer token required for `/metrics` |
| `FLARE_WEBHOOK_ALLOW_PRIVATE` | `false` | Allow webhooks to private and loopback addresses |
| `FLARE_BOOTSTRAP_PDNS_URL` | empty | PowerDNS API offered by the setup wizard |
| `FLARE_BOOTSTRAP_PDNS_API_KEY` | empty | Its API key |
| `FLARE_BOOTSTRAP_PDNS_SERVER_ID` | `localhost` | Its server ID |
| `FLARE_SMTP_HOST`, `_PORT`, `_USERNAME`, `_PASSWORD`, `_FROM`, `_TLS` | empty | SMTP (runtime setting takes precedence) |
| `FLARE_DEV` | `false` | Development mode: allows http OIDC issuers and webhooks and a default secret |

---

## Roles

| Permission | Owner | Administrator | DNS Editor | Viewer | Auditor |
| --- | :-: | :-: | :-: | :-: | :-: |
| View zones and records | yes | yes | yes | yes | yes |
| Edit records, DNSSEC, zone settings | yes | yes | yes | | |
| Add zones | yes | yes | yes | | |
| Delete or move zones | yes | yes | | | |
| Read the audit log | yes | yes | | | yes |
| Manage members, SSO, SCIM, API tokens, webhooks | yes | yes | | | |
| Organization security policy | yes | yes | | | |
| Delete the organization | yes | | | | |

Editors, viewers and auditors can be restricted to a subset of zones. Instance administrators manage servers, nameserver sets, global settings, all users and all organizations.

API tokens have their own roles: **Read only**, **DNS edit** and **Zone admin**. A token can never manage members, SSO, tokens or organization settings.


## Single sign-on (OpenID Connect)

1. In **Single sign-on > Domains**, add your email domain and publish the TXT record shown:
   `_flare-challenge.example.com TXT "flare-verify=..."`, then click **Verify**. Domains already active in the organization are verified automatically.
2. Create an OIDC web application in your identity provider with the **Redirect URI** shown on the page (`https://<FLARE_DOMAIN>/api/v1/auth/sso/callback`).
3. Enter the issuer URL, client ID and client secret. Add a `groups` scope or claim if your provider needs one.
4. Optionally map IdP groups to roles, turn on just-in-time provisioning, and enforce SSO.

Users then choose **Continue with single sign-on** and enter their work email. Only emails on verified domains are accepted from the identity provider. When SSO is enforced, password sign-in is blocked for that domain, except for instance administrators (break-glass).

| Provider | Issuer URL |
| --- | --- |
| Okta | `https://<org>.okta.com` |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| Google Workspace | `https://accounts.google.com` |
| Keycloak | `https://<host>/realms/<realm>` |
| Authentik | `https://<host>/application/o/<slug>/` |

## LDAP and Active Directory

In **Administration > Settings > Directory (LDAP)**, enter the server URL (`ldaps://` or `ldap://` with StartTLS), a service account and the search base.
Users sign in with their username or email address; Flare searches for them with the user filter, verifies the password by binding as that user, and creates the account on first sign-in.

- **Groups:** read from `memberOf` when present, otherwise found by searching for `member`, `uniqueMember` or `memberUid`.
- **Roles:** new users join the default organization with the default role; group mappings raise it, and members of the administrator group become instance administrators.
- Use **Test sign-in** to check the configuration before enabling it.

## SCIM provisioning

In **Single sign-on > SCIM provisioning**, generate a token and configure your identity provider with:

- **Base URL:** `https://<FLARE_DOMAIN>/scim/v2`
- **Authentication:** HTTP header, Bearer token

Supported: Users (create, update, deactivate, delete, `userName` and `externalId` filters) and Groups (create, membership changes, delete).
Deactivating a user suspends their access to that organization only. Group membership drives roles through SSO group mappings, or through a role assigned to the group on the SCIM page.

## API

Every dashboard action is available over the REST API at `/api/v1`. Authenticate with an API token:

```bash
export FLARE_TOKEN=flr_...
ORG=<organization id>

# List zones
curl -H "Authorization: Bearer $FLARE_TOKEN" https://dns.example.com/api/v1/orgs/$ORG/zones

# Create a record (TTL 1 means Auto)
curl -X POST -H "Authorization: Bearer $FLARE_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"www","type":"A","ttl":300,"content":"192.0.2.10","comment":"Web frontend"}' \
  https://dns.example.com/api/v1/orgs/$ORG/zones/$ZONE/records

# Check which token you are using
curl -H "Authorization: Bearer $FLARE_TOKEN" https://dns.example.com/api/v1/tokens/verify
```

### PowerDNS-compatible API

Tools written for the PowerDNS HTTP API can use Flare directly. Point them at `https://<FLARE_DOMAIN>` with server ID `localhost` and a Flare API token as the API key:

```bash
curl -H "X-API-Key: $FLARE_TOKEN" https://dns.example.com/api/v1/servers/localhost/zones
```

Supported: server info, zone list, create, get, PATCH of RRsets, delete, export, notify, rectify and axfr-retrieve.
Requests only see zones the token is scoped to, record content is validated, and every change is audited.

### Dynamic DNS

```bash
curl -u "flare:$FLARE_TOKEN" "https://dns.example.com/nic/update?hostname=home.example.com&myip=203.0.113.7"
```

Replies follow the dyndns2 protocol (`good`, `nochg`, `badauth`, `nohost`, `notfqdn`). Omit `myip` to use the client address; pass an IPv4 and an IPv6 address separated by a comma to update both.

Errors use a consistent shape: `{"error": {"code": "validation_failed", "message": "...", "fields": {"content": "..."}}}`.
See [docs/API.md](docs/API.md) for the endpoint reference.

## Webhooks

Webhooks receive a JSON event for every audited action that matches their filters (`*`, `zone.*`, `record.create`, and so on).
Each request carries `X-Flare-Event`, `X-Flare-Delivery` and `X-Flare-Signature: t=<unix>,v1=<hex>`, where `v1` is the HMAC-SHA256 of `"<t>.<raw body>"` with the webhook's signing secret.
Failed deliveries are retried with exponential backoff, up to 8 attempts.

## Operations

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Liveness |
| `GET /readyz` | Readiness (database reachable) |
| `GET /metrics` | Prometheus metrics: request rate and latency, zones by status, PowerDNS server health |

Background jobs (webhook delivery, delegation checks, server health, cleanup and audit retention) take PostgreSQL advisory locks, so you can run several `flare` replicas behind a load balancer.

## Security

- Passwords use Argon2id; sessions use random 256-bit tokens stored as SHA-256 hashes in HttpOnly, SameSite cookies
- CSRF protection uses a double-submit token on every state-changing request
- PowerDNS API keys, OIDC client secrets, SMTP passwords and webhook secrets are encrypted with AES-256-GCM
- Sign-in, two-factor, password reset, setup and SCIM endpoints are rate limited
- Strict security headers and a Content-Security-Policy are set on every response
- Webhooks cannot reach private networks by default (SSRF protection)
- OIDC uses PKCE, state and nonce validation, and only accepts emails on verified domains
- Containers run as non-root with dropped capabilities; the application container has a read-only filesystem
