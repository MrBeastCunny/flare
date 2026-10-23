package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flare-dns/flare/internal/pdns"
	"github.com/flare-dns/flare/internal/store"
	"github.com/google/uuid"
)

func TestRolePermissions(t *testing.T) {
	has := func(role string, token bool, p Perm) bool {
		for _, x := range permsFor(role, token) {
			if x == p {
				return true
			}
		}
		return false
	}
	if !has("owner", false, PermOrgDelete) || has("admin", false, PermOrgDelete) {
		t.Error("only owners may delete organizations")
	}
	if has("editor", false, PermMembersManage) || !has("editor", false, PermDNSEdit) {
		t.Error("editors edit DNS but cannot manage members")
	}
	if has("viewer", false, PermDNSEdit) || has("viewer", false, PermAuditRead) {
		t.Error("viewers are read-only and cannot read the audit log")
	}
	if !has("auditor", false, PermAuditRead) || has("auditor", false, PermDNSEdit) {
		t.Error("auditors read the audit log but cannot edit")
	}
	for _, p := range []Perm{PermMembersManage, PermSSOManage, PermTokensManage, PermOrgUpdate, PermOrgDelete} {
		if has("admin", true, p) {
			t.Errorf("zone admin tokens must not get %s", p)
		}
	}
	for role := range tokenRolePerms {
		for _, p := range []Perm{PermSSOManage, PermTokensManage, PermOrgDelete} {
			if has(role, true, p) {
				t.Errorf("%s tokens must never get %s", role, p)
			}
		}
	}
	for _, p := range []Perm{PermOrgUpdate, PermMembersManage, PermWebhooksManage, PermZonesDelete, PermDNSEdit} {
		if !has("org_admin", true, p) {
			t.Errorf("organization admin tokens need %s", p)
		}
	}
}

func TestTokenScope(t *testing.T) {
	o1, o2 := &store.Org{ID: uuid.New()}, &store.Org{ID: uuid.New()}
	orgTok := &store.APIToken{OrgID: &o1.ID, Role: "editor"}
	if _, err := tokenScope(orgTok, o1); err != nil {
		t.Error("organization token must work in its organization")
	}
	if _, err := tokenScope(orgTok, o2); err == nil {
		t.Error("organization token must not reach another organization")
	}
	all := &store.APIToken{Role: "viewer", InstanceRole: "none"}
	if _, err := tokenScope(all, o1); err != nil {
		t.Error("global token without org_ids reaches every organization")
	}
	some := &store.APIToken{Role: "viewer", OrgIDs: []uuid.UUID{o1.ID}}
	if _, err := tokenScope(some, o1); err != nil {
		t.Error("scoped global token must reach listed organizations")
	}
	if _, err := tokenScope(some, o2); err == nil {
		t.Error("scoped global token must not reach other organizations")
	}
	suspended := &store.Org{ID: uuid.New(), Suspended: true}
	if _, err := tokenScope(all, suspended); err == nil {
		t.Error("suspended organizations block ordinary global tokens")
	}
	if _, err := tokenScope(&store.APIToken{Role: "viewer", InstanceRole: "admin"}, suspended); err != nil {
		t.Error("full administrator tokens reach suspended organizations, like instance administrators")
	}
	if tokenInstanceAdmin(&store.APIToken{OrgID: &o1.ID, InstanceRole: "admin"}) {
		t.Error("organization tokens never have instance access")
	}
}

func TestRequireInstance(t *testing.T) {
	a := &App{Log: slog.New(slog.DiscardHandler)}
	o := uuid.New()
	cases := []struct {
		name  string
		act   *Actor
		level string
		want  int
	}{
		{"superadmin", &Actor{Type: "user", User: &store.User{IsSuperadmin: true}}, "admin", 200},
		{"user", &Actor{Type: "user", User: &store.User{}}, "orgs", 403},
		{"orgs token on org routes", &Actor{Type: "api_token", Token: &store.APIToken{InstanceRole: "orgs"}}, "orgs", 200},
		{"orgs token on admin routes", &Actor{Type: "api_token", Token: &store.APIToken{InstanceRole: "orgs"}}, "admin", 403},
		{"admin token", &Actor{Type: "api_token", Token: &store.APIToken{InstanceRole: "admin"}}, "admin", 200},
		{"no instance access", &Actor{Type: "api_token", Token: &store.APIToken{InstanceRole: "none"}}, "orgs", 403},
		{"organization token", &Actor{Type: "api_token", Token: &store.APIToken{OrgID: &o, InstanceRole: "admin"}}, "orgs", 403},
	}
	for _, c := range cases {
		h := a.RequireInstance(c.level)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		h.ServeHTTP(rec, req.WithContext(context.WithValue(req.Context(), keyActor, c.act)))
		if rec.Code != c.want {
			t.Errorf("%s: got %d, want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestCan(t *testing.T) {
	a := &App{}
	ctx := context.WithValue(context.Background(), keyMembership, &access{Role: "editor"})
	ctx = context.WithValue(ctx, keyActor, &Actor{Type: "user"})
	if !a.can(ctx, PermDNSEdit) || a.can(ctx, PermZonesDelete) {
		t.Error("editor permissions wrong")
	}
	tokCtx := context.WithValue(ctx, keyActor, &Actor{Type: "api_token"})
	if a.can(tokCtx, PermZonesCreate) {
		t.Error("editor token must not create zones")
	}
}

func TestZoneScope(t *testing.T) {
	z1, z2 := uuid.New(), uuid.New()
	if !zoneAllowed(&access{}, z1) {
		t.Error("nil scope allows all zones")
	}
	scoped := &access{ZoneIDs: []uuid.UUID{z1}}
	if !zoneAllowed(scoped, z1) || zoneAllowed(scoped, z2) {
		t.Error("zone scope not enforced")
	}
	if zoneAllowed(nil, z1) {
		t.Error("nil access must deny")
	}
}

func TestEventMatches(t *testing.T) {
	cases := []struct {
		patterns []string
		event    string
		want     bool
	}{
		{[]string{"*"}, "record.create", true},
		{[]string{"record.*"}, "record.create", true},
		{[]string{"record.*"}, "zone.create", false},
		{[]string{"zone.create"}, "zone.create", true},
		{[]string{"zone.create"}, "zone.delete", false},
	}
	for _, c := range cases {
		if got := eventMatches(c.patterns, c.event); got != c.want {
			t.Errorf("eventMatches(%v, %q) = %v", c.patterns, c.event, got)
		}
	}
}

func TestResolveRole(t *testing.T) {
	m := []store.RoleMapping{{Group: "dns-admins", Role: "admin"}, {Group: "dns-ops", Role: "editor"}}
	if r := resolveRole(m, []string{"DNS-OPS", "dns-admins"}, "viewer"); r != "admin" {
		t.Errorf("highest role should win, got %s", r)
	}
	if r := resolveRole(m, []string{"sales"}, "viewer"); r != "viewer" {
		t.Errorf("default role expected, got %s", r)
	}
}

func TestSafeRedirect(t *testing.T) {
	for in, want := range map[string]string{
		"/abc/dns":             "/abc/dns",
		"":                     "/",
		"https://evil.example": "/",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"/api/v1/me":           "/",
	} {
		if got := safeRedirect(in); got != want {
			t.Errorf("safeRedirect(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPAllowlist(t *testing.T) {
	list := []string{"10.0.0.0/8", "203.0.113.7"}
	if !ipAllowed("10.1.2.3", list) || !ipAllowed("203.0.113.7", list) {
		t.Error("expected allowed")
	}
	if ipAllowed("192.0.2.1", list) || ipAllowed("not-an-ip", list) {
		t.Error("expected denied")
	}
	if err := validateCIDRs([]string{"10.0.0.0/33"}); err == nil {
		t.Error("invalid CIDR accepted")
	}
}

func TestRecordIDRoundTrip(t *testing.T) {
	id := recordID("www.example.com.", "TXT", `"hello world"`)
	n, ty, c, err := parseRecordID(id)
	if err != nil || n != "www.example.com." || ty != "TXT" || c != `"hello world"` {
		t.Fatalf("round trip failed: %q %q %q %v", n, ty, c, err)
	}
	if _, _, _, err := parseRecordID("!!!"); err == nil {
		t.Error("expected error for malformed id")
	}
}

func TestFlattenRRSetsOrdersSOAFirst(t *testing.T) {
	sets := []pdns.RRSet{
		{Name: "www.example.com.", Type: "A", TTL: 300, Records: []pdns.Record{{Content: "192.0.2.1"}}},
		{Name: "example.com.", Type: "SOA", TTL: 3600, Records: []pdns.Record{{Content: "ns1. host. 1 2 3 4 5"}}},
		{Name: "example.com.", Type: "A", TTL: 300, Records: []pdns.Record{{Content: "192.0.2.2"}}, Comments: []pdns.Comment{{Content: "apex"}}},
	}
	out := flattenRRSets(sets)
	if len(out) != 3 || out[0].Type != "SOA" || out[1].Name != "example.com." || out[2].Name != "www.example.com." {
		t.Fatalf("unexpected order: %+v", out)
	}
	if out[1].Comment != "apex" {
		t.Error("comment not propagated")
	}
}

func TestConflictCheck(t *testing.T) {
	sets := []pdns.RRSet{{Name: "a.example.com.", Type: "A", Records: []pdns.Record{{Content: "192.0.2.1"}}}}
	if err := conflictCheck(sets, "a.example.com.", "CNAME", nil); err == nil {
		t.Error("CNAME next to A must conflict")
	}
	sets = []pdns.RRSet{{Name: "b.example.com.", Type: "CNAME", Records: []pdns.Record{{Content: "x."}}}}
	if err := conflictCheck(sets, "b.example.com.", "TXT", nil); err == nil {
		t.Error("TXT next to CNAME must conflict")
	}
	if err := conflictCheck(sets, "c.example.com.", "A", nil); err != nil {
		t.Error("unrelated names must not conflict")
	}
}

func TestSlugify(t *testing.T) {
	s := slugify("Acme, Inc. (EU)")
	if !strings.HasPrefix(s, "acme-inc-eu-") || len(s) != len("acme-inc-eu-")+4 {
		t.Errorf("unexpected slug %q", s)
	}
}

func TestCheckPassword(t *testing.T) {
	a := &App{}
	s := store.DefaultInstanceSettings()
	if err := a.checkPassword("short", "x@example.com", s); err == nil {
		t.Error("short password accepted")
	}
	if err := a.checkPassword("alice-is-great-123", "alice@example.com", s); err == nil {
		t.Error("password containing the email local part accepted")
	}
	if err := a.checkPassword("tangerine-orbit-glacier", "bob@example.com", s); err != nil {
		t.Errorf("good password rejected: %v", err)
	}
}
