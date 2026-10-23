package store

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID             uuid.UUID       `json:"id"`
	Email          string          `json:"email"`
	Name           string          `json:"name"`
	PasswordHash   *string         `json:"-"`
	IsSuperadmin   bool            `json:"is_superadmin"`
	Disabled       bool            `json:"disabled"`
	EmailVerified  bool            `json:"email_verified"`
	TOTPSecret     *string         `json:"-"`
	TOTPEnabled    bool            `json:"totp_enabled"`
	RecoveryCodes  []string        `json:"-"`
	OnboardedAt    *time.Time      `json:"onboarded_at"`
	LastLoginAt    *time.Time      `json:"last_login_at"`
	SCIMExternalID *string         `json:"-"`
	CreatedVia     string          `json:"created_via"`
	Preferences    json.RawMessage `json:"preferences"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func (u *User) HasPassword() bool { return u.PasswordHash != nil && *u.PasswordHash != "" }

func (u *User) DisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

type Session struct {
	ID              uuid.UUID  `json:"id"`
	UserID          uuid.UUID  `json:"-"`
	AuthMethod      string     `json:"auth_method"`
	SSOConnectionID *uuid.UUID `json:"-"`
	IP              string     `json:"ip"`
	UserAgent       string     `json:"user_agent"`
	CreatedAt       time.Time  `json:"created_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
}

type Org struct {
	ID                uuid.UUID  `json:"id"`
	Name              string     `json:"name"`
	Slug              string     `json:"slug"`
	MaxZones          *int       `json:"max_zones"`
	NameserverSetID   *uuid.UUID `json:"nameserver_set_id"`
	PDNSServerID      *uuid.UUID `json:"pdns_server_id"`
	EnforceMFA        bool       `json:"enforce_mfa"`
	SessionTTLMinutes *int       `json:"session_ttl_minutes"`
	IPAllowlist       []string   `json:"ip_allowlist"`
	Suspended         bool       `json:"suspended"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Membership struct {
	ID        uuid.UUID   `json:"id"`
	OrgID     uuid.UUID   `json:"org_id"`
	UserID    uuid.UUID   `json:"user_id"`
	Role      string      `json:"role"`
	ZoneIDs   []uuid.UUID `json:"zone_ids"`
	Source    string      `json:"source"`
	Suspended bool        `json:"suspended"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`

	// Joined user fields
	UserEmail       string     `json:"user_email,omitempty"`
	UserName        string     `json:"user_name,omitempty"`
	UserTOTP        bool       `json:"user_totp_enabled"`
	UserLastLoginAt *time.Time `json:"user_last_login_at,omitempty"`
	UserDisabled    bool       `json:"user_disabled"`
}

// OrgMembership is an organization as seen by one of its members.
type OrgMembership struct {
	Org
	Role      string      `json:"role"`
	ZoneIDs   []uuid.UUID `json:"zone_ids"`
	ZoneCount int         `json:"zone_count"`
}

type Invitation struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	Email       string      `json:"email"`
	Role        string      `json:"role"`
	ZoneIDs     []uuid.UUID `json:"zone_ids"`
	InvitedBy   *uuid.UUID  `json:"invited_by"`
	InviterName string      `json:"inviter_name,omitempty"`
	ExpiresAt   time.Time   `json:"expires_at"`
	AcceptedAt  *time.Time  `json:"accepted_at"`
	CreatedAt   time.Time   `json:"created_at"`
}

type PDNSServer struct {
	ID            uuid.UUID  `json:"id"`
	Name          string     `json:"name"`
	APIURL        string     `json:"api_url"`
	APIKeyEnc     string     `json:"-"`
	ServerID      string     `json:"server_id"`
	Description   string     `json:"description"`
	IsDefault     bool       `json:"is_default"`
	Enabled       bool       `json:"enabled"`
	LastStatus    string     `json:"last_status"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	Version       string     `json:"version"`
	ZoneCount     int        `json:"zone_count"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type NameserverSet struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Nameservers []string  `json:"nameservers"`
	Hostmaster  string    `json:"hostmaster"`
	IsDefault   bool      `json:"is_default"`
	ZoneCount   int       `json:"zone_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Zone struct {
	ID                  uuid.UUID  `json:"id"`
	OrgID               uuid.UUID  `json:"org_id"`
	PDNSServerID        uuid.UUID  `json:"pdns_server_id"`
	NameserverSetID     *uuid.UUID `json:"nameserver_set_id"`
	Name                string     `json:"name"`
	Kind                string     `json:"kind"`
	Status              string     `json:"status"`
	AssignedNameservers []string   `json:"assigned_nameservers"`
	ObservedNameservers []string   `json:"observed_nameservers"`
	LastNSCheckAt       *time.Time `json:"last_ns_check_at"`
	ActivatedAt         *time.Time `json:"activated_at"`
	CreatedBy           *uuid.UUID `json:"created_by"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`

	OrgName        string `json:"org_name,omitempty"`
	PDNSServerName string `json:"pdns_server_name,omitempty"`
}

type APIToken struct {
	ID    uuid.UUID  `json:"id"`
	OrgID *uuid.UUID `json:"org_id"` // nil for a global token
	// OrgIDs limits a global token to some organizations; nil means every organization.
	OrgIDs []uuid.UUID `json:"org_ids"`
	// InstanceRole grants a global token access to the admin API: none, orgs or admin.
	InstanceRole string      `json:"instance_role"`
	Name         string      `json:"name"`
	Prefix       string      `json:"prefix"`
	Role         string      `json:"role"`
	ZoneIDs      []uuid.UUID `json:"zone_ids"`
	IPAllowlist  []string    `json:"ip_allowlist"`
	CreatedBy    *uuid.UUID  `json:"created_by"`
	CreatorName  string      `json:"creator_name,omitempty"`
	ExpiresAt    *time.Time  `json:"expires_at"`
	LastUsedAt   *time.Time  `json:"last_used_at"`
	LastUsedIP   string      `json:"last_used_ip"`
	RevokedAt    *time.Time  `json:"revoked_at"`
	CreatedAt    time.Time   `json:"created_at"`
}

type RoleMapping struct {
	Group string `json:"group"`
	Role  string `json:"role"`
}

type SSOConnection struct {
	ID              uuid.UUID     `json:"id"`
	OrgID           uuid.UUID     `json:"org_id"`
	Name            string        `json:"name"`
	Issuer          string        `json:"issuer"`
	ClientID        string        `json:"client_id"`
	ClientSecretEnc string        `json:"-"`
	Scopes          []string      `json:"scopes"`
	GroupsClaim     string        `json:"groups_claim"`
	RoleMappings    []RoleMapping `json:"role_mappings"`
	DefaultRole     string        `json:"default_role"`
	JITProvisioning bool          `json:"jit_provisioning"`
	EnforceSSO      bool          `json:"enforce_sso"`
	Enabled         bool          `json:"enabled"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

type SSODomain struct {
	ID                uuid.UUID  `json:"id"`
	OrgID             uuid.UUID  `json:"org_id"`
	Domain            string     `json:"domain"`
	VerificationToken string     `json:"verification_token"`
	VerifiedAt        *time.Time `json:"verified_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

type SCIMToken struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedBy  *uuid.UUID `json:"created_by"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type SCIMGroup struct {
	ID          uuid.UUID   `json:"id"`
	OrgID       uuid.UUID   `json:"org_id"`
	DisplayName string      `json:"display_name"`
	ExternalID  *string     `json:"external_id"`
	Role        *string     `json:"role"`
	MemberIDs   []uuid.UUID `json:"member_ids"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

type AuditEntry struct {
	ID           int64           `json:"id"`
	OrgID        *uuid.UUID      `json:"org_id"`
	ZoneID       *uuid.UUID      `json:"zone_id"`
	ActorType    string          `json:"actor_type"`
	ActorID      *uuid.UUID      `json:"actor_id"`
	ActorLabel   string          `json:"actor_label"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	ResourceName string          `json:"resource_name"`
	Outcome      string          `json:"outcome"`
	Metadata     json.RawMessage `json:"metadata"`
	IP           string          `json:"ip"`
	UserAgent    string          `json:"user_agent"`
	CreatedAt    time.Time       `json:"created_at"`
	OrgName      string          `json:"org_name,omitempty"`
	// InstanceAdmin marks events performed through instance administration.
	InstanceAdmin bool `json:"instance_admin"`
}

type Webhook struct {
	ID        uuid.UUID  `json:"id"`
	OrgID     uuid.UUID  `json:"org_id"`
	Name      string     `json:"name"`
	URL       string     `json:"url"`
	SecretEnc string     `json:"-"`
	Events    []string   `json:"events"`
	Enabled   bool       `json:"enabled"`
	CreatedBy *uuid.UUID `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	LastDeliveryStatus *string    `json:"last_delivery_status"`
	LastDeliveryAt     *time.Time `json:"last_delivery_at"`
}

type WebhookDelivery struct {
	ID             int64           `json:"id"`
	WebhookID      uuid.UUID       `json:"webhook_id"`
	Event          string          `json:"event"`
	Payload        json.RawMessage `json:"payload"`
	Status         string          `json:"status"`
	Attempts       int             `json:"attempts"`
	ResponseStatus *int            `json:"response_status"`
	ResponseBody   string          `json:"response_body"`
	NextAttemptAt  time.Time       `json:"next_attempt_at"`
	DeliveredAt    *time.Time      `json:"delivered_at"`
	CreatedAt      time.Time       `json:"created_at"`
}

// InstanceSettings is the global configuration managed by instance administrators.
type InstanceSettings struct {
	InstanceName       string      `json:"instance_name"`
	SignupEnabled      bool        `json:"signup_enabled"`
	AllowOrgCreation   bool        `json:"allow_org_creation"`
	DefaultMaxZones    int         `json:"default_max_zones"`
	RequireMFA         bool        `json:"require_mfa"`
	PasswordMinLength  int         `json:"password_min_length"`
	AuditRetentionDays int         `json:"audit_retention_days"`
	SessionTTLHours    int         `json:"session_ttl_hours"`
	SupportEmail       string      `json:"support_email"`
	DefaultTTL         int         `json:"default_ttl"`
	SOA                SOADefaults `json:"soa"`
	DefaultDNSSEC      bool        `json:"default_dnssec"`
	SOAEditAPI         string      `json:"soa_edit_api"`
	SMTP               SMTPConfig  `json:"smtp"`
	SetupCompletedAt   *time.Time  `json:"setup_completed_at"`
	AnnouncementBanner string      `json:"announcement_banner"`
	// Record types offered for forward and reverse zones; empty means all.
	ForwardRecordTypes []string   `json:"forward_record_types"`
	ReverseRecordTypes []string   `json:"reverse_record_types"`
	AutoPTR            bool       `json:"auto_ptr"`
	DynDNSTTL          int        `json:"dyndns_ttl"`
	LDAP               LDAPConfig `json:"ldap"`
}

type SOADefaults struct {
	Refresh int `json:"refresh"`
	Retry   int `json:"retry"`
	Expire  int `json:"expire"`
	Minimum int `json:"minimum"`
	TTL     int `json:"ttl"`
}

type SMTPConfig struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	PasswordEnc string `json:"password_enc,omitempty"`
	From        string `json:"from"`
	TLS         string `json:"tls"`
}

func DefaultInstanceSettings() InstanceSettings {
	return InstanceSettings{
		InstanceName:       "Flare",
		SignupEnabled:      false,
		AllowOrgCreation:   true,
		DefaultMaxZones:    1000,
		PasswordMinLength:  12,
		AuditRetentionDays: 365,
		SessionTTLHours:    168,
		DefaultTTL:         3600,
		SOA:                SOADefaults{Refresh: 10800, Retry: 3600, Expire: 604800, Minimum: 3600, TTL: 3600},
		SOAEditAPI:         "DEFAULT",
		SMTP:               SMTPConfig{Port: 587, TLS: "starttls"},
		ReverseRecordTypes: []string{"PTR", "NS", "CNAME", "TXT", "SOA", "DS"},
		DynDNSTTL:          60,
		LDAP: LDAPConfig{UserFilter: "(|(uid={username})(mail={username})(sAMAccountName={username}))", EmailAttribute: "mail",
			NameAttribute: "cn", GroupAttribute: "memberOf", DefaultRole: "viewer"},
	}
}

type TemplateRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl"`
	Content string `json:"content"`
}

type ZoneTemplate struct {
	ID          uuid.UUID        `json:"id"`
	OrgID       *uuid.UUID       `json:"org_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Records     []TemplateRecord `json:"records"`
	CreatedBy   *uuid.UUID       `json:"created_by"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// LDAPConfig configures directory authentication (OpenLDAP or Active Directory).
type LDAPConfig struct {
	Enabled            bool       `json:"enabled"`
	URL                string     `json:"url"`
	StartTLS           bool       `json:"start_tls"`
	InsecureSkipVerify bool       `json:"insecure_skip_verify"`
	BindDN             string     `json:"bind_dn"`
	BindPasswordEnc    string     `json:"bind_password_enc,omitempty"`
	BaseDN             string     `json:"base_dn"`
	UserFilter         string     `json:"user_filter"`
	EmailAttribute     string     `json:"email_attribute"`
	NameAttribute      string     `json:"name_attribute"`
	GroupAttribute     string     `json:"group_attribute"`
	AdminGroupDN       string     `json:"admin_group_dn"`
	DefaultOrgID       *uuid.UUID `json:"default_org_id"`
	DefaultRole        string     `json:"default_role"`
	// GroupRoles maps directory group DNs to roles in the default organization.
	GroupRoles []RoleMapping `json:"group_roles"`
}
