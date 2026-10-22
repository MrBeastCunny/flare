export type Role = "owner" | "admin" | "editor" | "viewer" | "auditor";
export type TokenRole = "admin" | "editor" | "viewer";
export type ZoneStatus = "pending" | "active" | "moved" | "paused";

export type Perm =
  | "org.read"
  | "org.update"
  | "org.delete"
  | "members.read"
  | "members.manage"
  | "zones.read"
  | "zones.create"
  | "zones.edit"
  | "zones.delete"
  | "dns.edit"
  | "audit.read"
  | "tokens.manage"
  | "sso.manage"
  | "webhooks.manage";

export interface PublicConfig {
  instance_name: string;
  signup_enabled: boolean;
  setup_required: boolean;
  password_min_length: number;
  announcement: string;
  support_email: string;
  bootstrap_server: boolean;
  email_enabled: boolean;
  ldap_enabled: boolean;
  version: string;
}

export interface User {
  id: string;
  email: string;
  name: string;
  is_superadmin: boolean;
  disabled: boolean;
  email_verified: boolean;
  totp_enabled: boolean;
  onboarded_at: string | null;
  last_login_at: string | null;
  created_via: string;
  preferences: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Org {
  id: string;
  name: string;
  slug: string;
  max_zones: number | null;
  nameserver_set_id: string | null;
  pdns_server_id: string | null;
  enforce_mfa: boolean;
  session_ttl_minutes: number | null;
  ip_allowlist: string[];
  suspended: boolean;
  created_at: string;
  updated_at: string;
}

export interface MeOrg extends Org {
  role: Role;
  zone_ids: string[] | null;
  zone_count: number;
  permissions: Perm[];
}

export interface Me {
  user: User;
  orgs: MeOrg[];
  has_password: boolean;
  auth_method: "password" | "sso";
  session_id: string;
  mfa_setup_required: boolean;
  needs_onboarding: boolean;
  can_create_org: boolean;
  instance_name: string;
  announcement: string;
}

export interface OrgDetail {
  org: Org;
  role: Role;
  zone_ids: string[] | null;
  zone_count: number;
  max_zones: number;
  permissions: Perm[];
  record_types: { forward: string[]; reverse: string[] };
  auto_ptr: boolean;
}

export interface Zone {
  id: string;
  org_id: string;
  pdns_server_id: string;
  nameserver_set_id: string | null;
  name: string;
  kind: "Native" | "Master" | "Slave" | "Producer" | "Consumer";
  status: ZoneStatus;
  assigned_nameservers: string[];
  observed_nameservers: string[];
  last_ns_check_at: string | null;
  activated_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  org_name?: string;
  pdns_server_name?: string;
}

export interface DnsRecord {
  id: string;
  name: string;
  type: string;
  ttl: number;
  content: string;
  disabled: boolean;
  comment: string;
}

export interface ParsedRecord {
  name: string;
  type: string;
  ttl: number;
  content: string;
}

export interface Member {
  id: string;
  org_id: string;
  user_id: string;
  role: Role;
  zone_ids: string[] | null;
  source: string;
  suspended: boolean;
  created_at: string;
  updated_at: string;
  user_email: string;
  user_name: string;
  user_totp_enabled: boolean;
  user_last_login_at: string | null;
  user_disabled: boolean;
}

export interface Invitation {
  id: string;
  org_id: string;
  email: string;
  role: Role;
  zone_ids: string[] | null;
  invited_by: string | null;
  inviter_name: string;
  expires_at: string;
  accepted_at: string | null;
  created_at: string;
}

export interface ApiToken {
  id: string;
  org_id: string;
  name: string;
  prefix: string;
  role: TokenRole;
  zone_ids: string[] | null;
  ip_allowlist: string[];
  created_by: string | null;
  creator_name: string;
  expires_at: string | null;
  last_used_at: string | null;
  last_used_ip: string;
  revoked_at: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  org_id: string | null;
  zone_id: string | null;
  actor_type: "user" | "api_token" | "scim" | "system" | "anonymous";
  actor_id: string | null;
  actor_label: string;
  action: string;
  resource_type: string;
  resource_id: string;
  resource_name: string;
  outcome: "success" | "failure";
  metadata: Record<string, unknown>;
  ip: string;
  user_agent: string;
  created_at: string;
  org_name?: string;
}

export interface AuditPage {
  entries: AuditEntry[];
  next_cursor: number | null;
}

export interface DayCount {
  day: string;
  count: number;
}

export interface RoleMapping {
  group: string;
  role: Role;
}

export interface SSOConnection {
  id: string;
  org_id: string;
  name: string;
  issuer: string;
  client_id: string;
  scopes: string[];
  groups_claim: string;
  role_mappings: RoleMapping[];
  default_role: Role;
  jit_provisioning: boolean;
  enforce_sso: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface SSODomain {
  id: string;
  org_id: string;
  domain: string;
  verification_token: string;
  verified_at: string | null;
  created_at: string;
}

export interface SCIMToken {
  id: string;
  org_id: string;
  name: string;
  prefix: string;
  last_used_at: string | null;
  created_at: string;
}

export interface SCIMGroup {
  id: string;
  display_name: string;
  external_id: string | null;
  role: Role | null;
  member_ids: string[];
  created_at: string;
}

export interface Webhook {
  id: string;
  org_id: string;
  name: string;
  url: string;
  events: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  last_delivery_status: string | null;
  last_delivery_at: string | null;
}

export interface WebhookDelivery {
  id: number;
  webhook_id: string;
  event: string;
  payload: unknown;
  status: "pending" | "delivered" | "failed";
  attempts: number;
  response_status: number | null;
  response_body: string;
  next_attempt_at: string;
  delivered_at: string | null;
  created_at: string;
}

export interface PdnsServer {
  id: string;
  name: string;
  api_url: string;
  server_id: string;
  description: string;
  is_default: boolean;
  enabled: boolean;
  last_status: "unknown" | "healthy" | "unreachable";
  last_checked_at: string | null;
  version: string;
  zone_count: number;
  created_at: string;
}

export interface NameserverSet {
  id: string;
  name: string;
  nameservers: string[];
  hostmaster: string;
  is_default: boolean;
  zone_count: number;
  created_at: string;
}

export interface SOA {
  primary: string;
  hostmaster: string;
  serial: number;
  refresh: number;
  retry: number;
  expire: number;
  minimum: number;
  ttl: number;
}

export interface ZoneSettings {
  kind: Zone["kind"];
  catalog: string;
  masters: string[];
  soa: SOA;
  soa_edit_api: string;
  serial: number;
  also_notify: string[];
  allow_axfr_from: string[];
  tsig_allow_axfr: string[];
  axfr_master_tsig: string[];
  nameserver_set_id: string | null;
  nameservers: string[];
  nameserver_sets: NameserverSet[];
}

export interface CryptoKey {
  id: number;
  keytype: "ksk" | "zsk" | "csk";
  active: boolean;
  published: boolean;
  dnskey: string;
  ds: string[];
  algorithm: string;
  bits: number;
}

export interface DnssecInfo {
  enabled: boolean;
  nsec3param: string;
  nsec3narrow: boolean;
  keys: CryptoKey[];
  ds: string[];
  presigned: boolean;
}

export interface InstanceSettings {
  instance_name: string;
  signup_enabled: boolean;
  allow_org_creation: boolean;
  default_max_zones: number;
  require_mfa: boolean;
  password_min_length: number;
  audit_retention_days: number;
  session_ttl_hours: number;
  support_email: string;
  default_ttl: number;
  soa: { refresh: number; retry: number; expire: number; minimum: number; ttl: number };
  default_dnssec: boolean;
  soa_edit_api: string;
  announcement_banner: string;
  smtp: { host: string; port: number; username: string; from: string; tls: string; password_set: boolean };
  setup_completed_at: string | null;
  env_smtp_configured: boolean;
  forward_record_types: string[];
  reverse_record_types: string[];
  auto_ptr: boolean;
  dyndns_ttl: number;
  ldap: LDAPSettings;
}

export interface LDAPSettings {
  enabled: boolean;
  url: string;
  start_tls: boolean;
  insecure_skip_verify: boolean;
  bind_dn: string;
  bind_password_set?: boolean;
  base_dn: string;
  user_filter: string;
  email_attribute: string;
  name_attribute: string;
  group_attribute: string;
  admin_group_dn: string;
  default_org_id: string | null;
  default_role: Role;
  group_roles: RoleMapping[];
}

export interface TemplateRecord {
  name: string;
  type: string;
  ttl: number;
  content: string;
}

export interface ZoneTemplate {
  id: string;
  org_id: string | null;
  name: string;
  description: string;
  records: TemplateRecord[];
  created_at: string;
  updated_at: string;
}

export interface AdminUser extends User {
  org_count: number;
}

export interface AdminOrg extends Org {
  member_count: number;
  zone_count: number;
}

export interface TSIGKey {
  id: string;
  name: string;
  algorithm: string;
  key?: string;
}
