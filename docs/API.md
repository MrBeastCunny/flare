# Flare API reference

Base path: `/api/v1`. Request and response bodies are JSON.

**Authentication**
- Browser sessions use the `flare_session` cookie. State-changing requests must send the `X-CSRF-Token` header with the value of the `flare_csrf` cookie.
- Automation uses `Authorization: Bearer <api token>`. Organization tokens are bound to one organization. Global tokens, created by instance administrators, work in all or selected organizations and can be given access to the admin API.

**Errors**: `{"error": {"code": "...", "message": "...", "fields": {"field": "message"}}}`

| Status | Code examples |
| --- | --- |
| 400 | `bad_request` |
| 401 | `unauthorized`, `invalid_credentials`, `session_expired` |
| 403 | `forbidden`, `mfa_required`, `sso_required`, `ip_not_allowed`, `org_suspended`, `quota_exceeded` |
| 404 | `not_found` |
| 409 | `conflict`, `stale_record` |
| 422 | `validation_failed`, `powerdns_error` |
| 429 | `rate_limited` |
| 502 | `powerdns_unreachable`, `lookup_failed` |

Requests are rate limited per token or session (600 burst, 1200 per minute).

---

## Public

| Method | Path | Description |
| --- | --- | --- |
| GET | `/config` | Instance name, sign-up policy, setup state |
| POST | `/setup` | First-run setup (only when no users exist) |
| POST | `/setup/test-server` | Test a PowerDNS connection during setup |
| POST | `/auth/login` | `{email, password}` returns `{mfa_required, mfa_token?}` |
| POST | `/auth/login/mfa` | `{mfa_token, code}` (TOTP or recovery code) |
| POST | `/auth/logout` | End the current session |
| POST | `/auth/signup` | Self-service sign-up, when enabled |
| POST | `/auth/password/forgot` | Email a reset link |
| POST | `/auth/password/reset` | `{token, password}` |
| POST | `/auth/sso/discover` | `{email}` returns the SSO start URL for verified domains |
| GET | `/auth/sso/{connectionID}/start` | Redirect to the identity provider |
| GET | `/auth/sso/callback` | OIDC redirect URI |
| GET | `/invites/{token}` | Invitation details |
| POST | `/invites/{token}/accept` | Accept (signed in), or create an account `{name, password}` |

## Current user (session only)

| Method | Path | Description |
| --- | --- | --- |
| GET | `/me` | Profile, organizations and permissions |
| PATCH | `/me` | `{name?, preferences?}` |
| DELETE | `/me` | `{confirm: email}` |
| POST | `/me/password` | `{current_password, new_password}` |
| POST | `/me/mfa/setup` | Start TOTP enrollment (secret and QR code) |
| POST | `/me/mfa/enable` | `{code}` returns recovery codes |
| POST | `/me/mfa/disable` | `{code}` |
| POST | `/me/mfa/recovery-codes` | `{code}` regenerates recovery codes |
| GET | `/me/sessions` | Active sessions |
| DELETE | `/me/sessions/{id}` | Revoke a session |
| POST | `/me/sessions/revoke-others` | Sign out every other session |
| POST | `/me/onboarding/complete` | Mark onboarding done |
| POST | `/orgs` | Create an organization `{name}` |
| GET | `/orgs` | (sessions and tokens) Organizations the caller can use, with its role in each |
| GET | `/tokens/verify` | (token only) Describe the calling API token, including `global`, `org_ids` and `instance_role` |

## Organization `/orgs/{orgID}`

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/` | org.read | Organization, role, permissions, quota |
| PATCH | `/` | org.update | `{name?, enforce_mfa?, session_ttl_minutes?, ip_allowlist?}` |
| DELETE | `/` | org.delete | `{confirm: name}`; all zones must be removed first |
| GET | `/overview` | org.read | Counts, recent zones and activity |
| GET | `/search?q=` | zones.read | Zones and records matching a query |
| POST | `/leave` | session | Leave the organization |
| GET | `/nameserver-sets` | zones.read | Available nameserver sets |
| GET | `/members` | members.read | Members |
| PATCH | `/members/{id}` | members.manage | `{role, zone_ids?}` |
| DELETE | `/members/{id}` | members.manage | Remove a member |
| GET, POST | `/invites` | members.manage | List, or create `{emails[], role, zone_ids?}` |
| POST | `/invites/{id}/resend` | members.manage | Re-send with a fresh link |
| DELETE | `/invites/{id}` | members.manage | Revoke |
| GET, POST | `/tokens` | tokens.manage | List, or create `{name, role, zone_ids?, ip_allowlist?, expires_in_days?}`. `role` is `viewer`, `editor`, `admin` (zone admin) or `org_admin` |
| POST | `/tokens/{id}/roll` | tokens.manage | Rotate the secret |
| DELETE | `/tokens/{id}` | tokens.manage | Revoke |
| GET, PUT, DELETE | `/sso` | sso.manage | OIDC connection |
| POST | `/sso/domains` | sso.manage | `{domain}` |
| POST | `/sso/domains/{id}/verify` | sso.manage | Check the TXT record |
| DELETE | `/sso/domains/{id}` | sso.manage | Remove a domain |
| GET | `/scim` | sso.manage | SCIM tokens, groups and base URL |
| POST | `/scim/tokens` | sso.manage | `{name}` |
| DELETE | `/scim/tokens/{id}` | sso.manage | Revoke |
| PUT | `/scim/groups/{id}/role` | sso.manage | `{role: string or null}` |
| GET, POST | `/webhooks` | webhooks.manage | List, or create `{name, url, events[], enabled}` |
| PUT, DELETE | `/webhooks/{id}` | webhooks.manage | Update or delete |
| POST | `/webhooks/{id}/test` | webhooks.manage | Queue a test event |
| POST | `/webhooks/{id}/rotate-secret` | webhooks.manage | New signing secret |
| GET | `/webhooks/{id}/deliveries` | webhooks.manage | Last 100 deliveries |
| GET | `/audit-logs` | audit.read | Filters: `q, action (prefix), resource_type, outcome, zone_id, actor_id, since, until, before (cursor), limit` |
| GET | `/audit-logs/export?format=csv\|json` | audit.read | Streamed export (same filters) |

## Zones `/orgs/{orgID}/zones`

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/` | zones.read | Zones visible to the caller |
| POST | `/scan` | zones.create | `{name}` discovers existing public records. `skipped_addresses` counts A/AAAA answers dropped for pointing at reserved ranges (for example a fake-IP proxy rewriting DNS) |
| POST | `/` | zones.create | `{name, kind?, masters?, nameserver_set_id?, records?, dnssec?, skip_verification?, template_id?}`. `name` may be a CIDR such as `192.0.2.0/24` to create its reverse zone. `kind` is Native, Master, Slave, Producer or Consumer |
| GET | `/{zoneID}` | zones.read | Zone with serial and DNSSEC state |
| DELETE | `/{zoneID}` | zones.delete | `{confirm: domain}` |
| GET | `/{zoneID}/overview` | zones.read | Counts, activity and top queried names |
| GET | `/{zoneID}/records` | zones.read | All records |
| POST | `/{zoneID}/records` | dns.edit | `{name, type, ttl, content, comment?, disabled?, create_ptr?}`. Responds with `{record, ptr}` |
| PUT | `/{zoneID}/records/{recordID}` | dns.edit | Replace a record; same body and response as create |
| DELETE | `/{zoneID}/records/{recordID}` | dns.edit | Delete a record |
| POST | `/{zoneID}/records/bulk-delete` | dns.edit | `{ids[]}` |
| POST | `/{zoneID}/import/preview` | dns.edit | `{text}` parses a zone file |
| POST | `/{zoneID}/import` | dns.edit | `{text or records, mode: merge or replace}` |
| GET | `/{zoneID}/export` | zones.read | BIND zone file |
| GET, PATCH | `/{zoneID}/settings` | zones.read, zones.edit | SOA, kind, catalog, masters, transfer metadata |
| POST | `/{zoneID}/apply-template` | dns.edit | `{template_id, mode: merge or replace}` |
| POST | `/{zoneID}/save-as-template` | zones.create | `{name, description?}` |
| POST | `/{zoneID}/nameservers` | zones.edit | `{nameserver_set_id}` |
| GET | `/{zoneID}/dnssec` | zones.read | Keys and DS records |
| POST | `/{zoneID}/dnssec/enable` | zones.edit | `{algorithm?, nsec3?}` |
| POST | `/{zoneID}/dnssec/disable` | zones.edit | Remove all keys |
| POST | `/{zoneID}/dnssec/keys` | zones.edit | `{keytype, algorithm, active, published}` |
| PATCH, DELETE | `/{zoneID}/dnssec/keys/{keyID}` | zones.edit | Activate, deactivate or delete a key |
| POST | `/{zoneID}/check-nameservers` | zones.read | Re-check delegation now |
| POST | `/{zoneID}/activate` | org.update | Mark active without delegation checks |
| POST | `/{zoneID}/move` | zones.delete | `{target_org_id}` |
| POST | `/{zoneID}/actions/{notify\|rectify\|axfr-retrieve\|flush-cache}` | zones.edit | Server operations |
| GET | `/{zoneID}/audit-logs` | audit.read | Zone activity |

### Zone templates `/orgs/{orgID}/templates`

| Method | Path | Permission | Description |
| --- | --- | --- | --- |
| GET | `/` | zones.read | Organization templates and instance-wide templates |
| POST | `/` | zones.create | `{name, description?, records: [{name, type, ttl, content}]}` with names relative to the zone |
| PUT, DELETE | `/{templateID}` | zones.create | Update or delete an organization template |

The zone's own (apex) NS records follow its nameserver set and cannot be created, edited or deleted as records; use `POST /{zoneID}/nameservers`. NS records for subdomain delegations are ordinary records. Imports and templates skip apex NS and SOA records.

Hostnames in record content (CNAME, MX, NS, SRV and similar targets) are absolute when they contain a dot, with or without a trailing dot: `casca.example.net` stays `casca.example.net.`. A single label such as `www`, or `@`, is relative to the zone. Zone file imports and templates use zone file rules instead, where any name without a trailing dot is relative.

Record IDs are opaque and change when a record's name, type or content changes. A `409 stale_record` response means someone else changed the record first.

## Instance administration `/admin` (instance administrators)

Global API tokens can call `/admin` too, depending on their instance access: `orgs` (Manage organizations) reaches the organization endpoints, `admin` (Full administrator) reaches every endpoint except `/tokens` and `/settings/test-email`, which need a signed-in administrator.

| Method | Path | Description |
| --- | --- | --- |
| GET, POST | `/tokens` | (signed-in administrators) Global API tokens; create `{name, role, org_ids?, instance_role?, ip_allowlist?, expires_in_days?}`. Empty `org_ids` means every organization; `instance_role` is `none`, `orgs` or `admin` |
| POST | `/tokens/{id}/roll` | (signed-in administrators) Rotate a global token's secret |
| DELETE | `/tokens/{id}` | (signed-in administrators) Revoke a global token |
| GET | `/overview` | Platform statistics |
| GET, POST | `/servers` | PowerDNS servers |
| POST | `/servers/test` | Test connection details |
| PUT, DELETE | `/servers/{id}` | Update or remove |
| GET | `/servers/{id}/status` | Live statistics |
| GET | `/servers/{id}/config` | Runtime configuration, secrets redacted |
| GET | `/servers/{id}/unmanaged-zones` | Zones on the server that are not in Flare |
| POST | `/servers/{id}/adopt` | `{org_id, zones[], nameserver_set_id?, mark_active}` |
| GET, POST | `/servers/{id}/tsig-keys` | TSIG keys |
| GET, DELETE | `/servers/{id}/tsig-keys/{keyID}` | Reveal or delete |
| GET, POST | `/nameserver-sets` | Nameserver sets; create `{name, nameservers[], hostmaster?, is_default}` |
| PUT, DELETE | `/nameserver-sets/{id}` | Update or delete. Create and update respond with `{set, zones_updated, zones_failed}`; changing the nameservers or hostmaster rewrites the apex NS and SOA records of every zone using the set |
| GET, PATCH | `/settings` | Instance settings |
| POST | `/settings/test-email` | Send a test email to yourself |
| POST | `/settings/test-ldap` | `{username, password}` checks the LDAP configuration |
| GET, POST | `/templates` | Instance-wide zone templates |
| PUT, DELETE | `/templates/{id}` | Update or delete |
| GET | `/users`, `/users/{id}` | Users |
| POST | `/users` | `{email, name?, password?, is_superadmin?, send_email?}`; without a password, returns a 7-day `setup_url` |
| PATCH | `/users/{id}` | `{email?, name?, is_superadmin?, disabled?, reset_mfa?, logout?}` |
| DELETE | `/users/{id}` | Delete a user |
| GET, POST | `/orgs` | Organizations; create `{name, owner_email?}`. `owner_email` defaults to the signed-in administrator and is required for API tokens |
| PATCH | `/orgs/{id}` | `{max_zones, nameserver_set_id, pdns_server_id, suspended}` |
| GET | `/zones` | All zones |
| GET | `/audit-logs`, `/audit-logs/export` | Instance-wide audit log |

## PowerDNS-compatible API `/api/v1/servers`

Authenticate with a Flare API token in `X-API-Key` (or `Authorization: Bearer`). The server ID is `localhost`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/servers`, `/servers/localhost` | Server information |
| GET, POST | `/servers/localhost/zones` | Zones the token can see; create a zone (`zones.create`). For global tokens, zones from every organization in scope are listed with the organization slug in `account`, and creating a zone needs `account` (organization slug or ID) unless the token is limited to one organization |
| GET, PATCH, DELETE | `/servers/localhost/zones/{zone}` | Zone with RRsets; PATCH `{rrsets: [{name, type, ttl, changetype: REPLACE or DELETE, records}]}` |
| GET | `/servers/localhost/zones/{zone}/export` | BIND zone file |
| PUT | `/servers/localhost/zones/{zone}/{notify,rectify,axfr-retrieve}` | Server operations |

RRsets outside the zone are rejected, content is validated like dashboard edits, and every change is audited as `record.api_patch`.

## Dynamic DNS `/nic/update`

dyndns2 protocol. HTTP Basic authentication with any username and an API token as the password (or a bearer token). Parameters: `hostname` (comma-separated for several), `myip` (IPv4, IPv6, or both comma-separated; defaults to the client address).
Replies: `good <ip>`, `nochg <ip>`, `badauth`, `nohost`, `notfqdn`, `badip`, `abuse`, `dnserr`. The token needs `dns.edit`; the TTL is set in instance settings.

## SCIM 2.0 `/scim/v2`

Bearer token from **Single sign-on > SCIM provisioning**.

`GET /ServiceProviderConfig`, `GET /ResourceTypes`, `GET /Schemas`,
`GET|POST /Users`, `GET|PUT|PATCH|DELETE /Users/{id}`,
`GET|POST /Groups`, `GET|PUT|PATCH|DELETE /Groups/{id}`.

Filters: `userName eq "..."`, `externalId eq "..."`, `displayName eq "..."`. Pagination: `startIndex`, `count`.
