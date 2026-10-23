package api

import (
	"context"
	"crypto/subtle"
	"html"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (a *App) perm(p Perm) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.require(r.Context(), p); err != nil {
				a.fail(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Router builds the HTTP handler. webFS holds the built single-page app (may be nil).
func (a *App) Router(webFS fs.FS) http.Handler {
	r := chi.NewRouter()
	r.Use(a.Base)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := a.Store.Pool.Ping(ctx); err != nil {
			writeJSON(w, 503, map[string]string{"status": "unavailable", "error": "database"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
	})
	r.Get("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if a.Cfg.MetricsToken != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(a.Cfg.MetricsToken)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		promhttp.Handler().ServeHTTP(w, r)
	})

	// DynDNS2 protocol (routers, ddclient, inadyn)
	r.Get("/nic/update", a.handleDynDNS)
	r.Post("/nic/update", a.handleDynDNS)

	// SCIM 2.0 provisioning
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(a.SCIMAuth)
		r.Get("/ServiceProviderConfig", a.handleSCIMServiceProviderConfig)
		r.Get("/ResourceTypes", a.handleSCIMResourceTypes)
		r.Get("/Schemas", a.handleSCIMSchemas)
		r.Get("/Users", a.handleSCIMListUsers)
		r.Post("/Users", a.handleSCIMCreateUser)
		r.Get("/Users/{id}", a.handleSCIMGetUser)
		r.Put("/Users/{id}", a.handleSCIMReplaceUser)
		r.Patch("/Users/{id}", a.handleSCIMPatchUser)
		r.Delete("/Users/{id}", a.handleSCIMDeleteUser)
		r.Get("/Groups", a.handleSCIMListGroups)
		r.Post("/Groups", a.handleSCIMCreateGroup)
		r.Get("/Groups/{id}", a.handleSCIMGetGroup)
		r.Put("/Groups/{id}", a.handleSCIMReplaceGroup)
		r.Patch("/Groups/{id}", a.handleSCIMPatchGroup)
		r.Delete("/Groups/{id}", a.handleSCIMDeleteGroup)
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(a.Authenticate, a.CSRF, a.APIRateLimit)

		r.Get("/config", a.handlePublicConfig)

		// PowerDNS-compatible API for external-dns, cert-manager, Terraform and acme.sh.
		r.Route("/servers", func(r chi.Router) {
			r.Use(a.PDNSCompat)
			r.Get("/", a.handleCompatServers)
			r.Get("/{serverID}", a.handleCompatServer)
			r.Get("/{serverID}/zones", a.handleCompatListZones)
			r.Post("/{serverID}/zones", a.handleCompatCreateZone)
			r.Route("/{serverID}/zones/{zoneID}", func(r chi.Router) {
				r.Use(a.CompatZoneOrg)
				r.Get("/", a.handleCompatGetZone)
				r.Patch("/", a.handleCompatPatchZone)
				r.Delete("/", a.handleCompatDeleteZone)
				r.Get("/export", a.handleCompatZoneAction("export"))
				r.Put("/notify", a.handleCompatZoneAction("notify"))
				r.Put("/rectify", a.handleCompatZoneAction("rectify"))
				r.Put("/axfr-retrieve", a.handleCompatZoneAction("axfr-retrieve"))
			})
		})
		r.With(a.RateLimit("setup", 10, 2)).Post("/setup", a.handleSetup)
		r.With(a.RateLimit("setup-test", 30, 10)).Post("/setup/test-server", a.handleSetupTestServer)

		r.Route("/auth", func(r chi.Router) {
			r.With(a.RateLimit("login", 20, 10)).Post("/login", a.handleLogin)
			r.With(a.RateLimit("mfa", 20, 10)).Post("/login/mfa", a.handleLoginMFA)
			r.Post("/logout", a.handleLogout)
			r.With(a.RateLimit("signup", 10, 2)).Post("/signup", a.handleSignup)
			r.With(a.RateLimit("forgot", 5, 1)).Post("/password/forgot", a.handleForgotPassword)
			r.With(a.RateLimit("reset", 10, 2)).Post("/password/reset", a.handleResetPassword)
			r.With(a.RateLimit("sso", 30, 15)).Post("/sso/discover", a.handleSSODiscover)
			r.Get("/sso/{connID}/start", a.handleSSOStart)
			r.Get("/sso/callback", a.handleSSOCallback)
		})
		r.Get("/invites/{token}", a.handleGetInvite)
		r.With(a.RateLimit("invite", 20, 5)).Post("/invites/{token}/accept", a.handleAcceptInvite)

		// User-only endpoints
		r.Group(func(r chi.Router) {
			r.Use(a.RequireUser)
			r.Get("/me", a.handleMe)
			r.Patch("/me", a.handleUpdateMe)
			r.Delete("/me", a.handleDeleteMe)
			r.Post("/me/password", a.handleChangePassword)
			r.Post("/me/mfa/setup", a.handleMFASetup)
			r.Post("/me/mfa/enable", a.handleMFAEnable)
			r.Post("/me/mfa/disable", a.handleMFADisable)
			r.Post("/me/mfa/recovery-codes", a.handleRegenerateRecoveryCodes)
			r.Get("/me/sessions", a.handleListSessions)
			r.Delete("/me/sessions/{sessionID}", a.handleRevokeSession)
			r.Post("/me/sessions/revoke-others", a.handleRevokeOtherSessions)
			r.Post("/me/onboarding/complete", a.handleCompleteOnboarding)
			r.Post("/orgs", a.handleCreateOrg)
		})

		r.Group(func(r chi.Router) {
			r.Use(a.RequireActor)
			r.Get("/tokens/verify", a.handleVerifyToken)
			r.Get("/orgs", a.handleListOrgs)

			r.Route("/orgs/{orgID}", func(r chi.Router) {
				r.Use(a.LoadOrg)
				r.With(a.perm(PermOrgRead)).Get("/", a.handleGetOrg)
				r.With(a.perm(PermOrgUpdate)).Patch("/", a.handleUpdateOrg)
				r.With(a.perm(PermOrgDelete)).Delete("/", a.handleDeleteOrg)
				r.With(a.perm(PermOrgRead)).Get("/overview", a.handleOrgOverview)
				r.With(a.perm(PermZonesRead)).Get("/search", a.handleSearch)
				r.With(a.RequireUser).Post("/leave", a.handleLeaveOrg)
				r.With(a.perm(PermZonesRead)).Get("/nameserver-sets", a.handleNameserverSetsPublic)

				r.With(a.perm(PermMembersRead)).Get("/members", a.handleListMembers)
				r.With(a.perm(PermMembersManage)).Patch("/members/{memberID}", a.handleUpdateMember)
				r.With(a.perm(PermMembersManage)).Delete("/members/{memberID}", a.handleRemoveMember)

				r.Route("/invites", func(r chi.Router) {
					r.Use(a.perm(PermMembersManage))
					r.Get("/", a.handleListInvites)
					r.Post("/", a.handleCreateInvite)
					r.Post("/{inviteID}/resend", a.handleResendInvite)
					r.Delete("/{inviteID}", a.handleDeleteInvite)
				})

				r.Route("/tokens", func(r chi.Router) {
					r.Use(a.RequireUser, a.perm(PermTokensManage))
					r.Get("/", a.handleListTokens)
					r.Post("/", a.handleCreateToken)
					r.Post("/{tokenID}/roll", a.handleRollToken)
					r.Delete("/{tokenID}", a.handleRevokeToken)
				})

				r.Route("/sso", func(r chi.Router) {
					r.Use(a.RequireUser, a.perm(PermSSOManage))
					r.Get("/", a.handleGetSSO)
					r.Put("/", a.handlePutSSO)
					r.Delete("/", a.handleDeleteSSO)
					r.Post("/domains", a.handleAddSSODomain)
					r.Post("/domains/{domainID}/verify", a.handleVerifySSODomain)
					r.Delete("/domains/{domainID}", a.handleDeleteSSODomain)
				})

				r.Route("/scim", func(r chi.Router) {
					r.Use(a.RequireUser, a.perm(PermSSOManage))
					r.Get("/", a.handleListSCIM)
					r.Post("/tokens", a.handleCreateSCIMToken)
					r.Delete("/tokens/{tokenID}", a.handleDeleteSCIMToken)
					r.Put("/groups/{groupID}/role", a.handleSetGroupRole)
				})

				r.Route("/webhooks", func(r chi.Router) {
					r.Use(a.perm(PermWebhooksManage))
					r.Get("/", a.handleListWebhooks)
					r.Post("/", a.handleCreateWebhook)
					r.Put("/{webhookID}", a.handleUpdateWebhook)
					r.Delete("/{webhookID}", a.handleDeleteWebhook)
					r.Post("/{webhookID}/rotate-secret", a.handleRotateWebhookSecret)
					r.Post("/{webhookID}/test", a.handleTestWebhook)
					r.Get("/{webhookID}/deliveries", a.handleWebhookDeliveries)
				})

				r.With(a.perm(PermAuditRead)).Get("/audit-logs", a.handleOrgAudit)
				r.With(a.perm(PermAuditRead)).Get("/audit-logs/export", a.handleOrgAuditExport)

				r.With(a.perm(PermZonesRead)).Get("/templates", a.handleListTemplates)
				r.With(a.perm(PermZonesCreate)).Post("/templates", a.handleCreateTemplate)
				r.With(a.perm(PermZonesCreate)).Put("/templates/{templateID}", a.handleUpdateTemplate)
				r.With(a.perm(PermZonesCreate)).Delete("/templates/{templateID}", a.handleDeleteTemplate)

				r.With(a.perm(PermZonesRead)).Get("/zones", a.handleListZones)
				r.With(a.perm(PermZonesCreate)).Post("/zones", a.handleCreateZone)
				r.With(a.perm(PermZonesCreate)).Post("/zones/scan", a.handleScanZone)

				r.Route("/zones/{zoneID}", func(r chi.Router) {
					r.Use(a.LoadZone)
					r.With(a.perm(PermZonesRead)).Get("/", a.handleGetZone)
					r.With(a.perm(PermZonesDelete)).Delete("/", a.handleDeleteZone)
					r.With(a.perm(PermZonesRead)).Get("/overview", a.handleZoneOverview)

					r.With(a.perm(PermZonesRead)).Get("/records", a.handleListRecords)
					r.With(a.perm(PermDNSEdit)).Post("/records", a.handleCreateRecord)
					r.With(a.perm(PermDNSEdit)).Post("/records/bulk-delete", a.handleBulkDeleteRecords)
					r.With(a.perm(PermDNSEdit)).Put("/records/{recordID}", a.handleUpdateRecord)
					r.With(a.perm(PermDNSEdit)).Delete("/records/{recordID}", a.handleDeleteRecord)
					r.With(a.perm(PermDNSEdit)).Post("/import/preview", a.handleImportPreview)
					r.With(a.perm(PermDNSEdit)).Post("/import", a.handleImportRecords)
					r.With(a.perm(PermZonesRead)).Get("/export", a.handleExportZone)
					r.With(a.perm(PermDNSEdit)).Post("/apply-template", a.handleApplyTemplate)
					r.With(a.perm(PermZonesCreate)).Post("/save-as-template", a.handleTemplateFromZone)

					r.With(a.perm(PermZonesRead)).Get("/settings", a.handleGetZoneSettings)
					r.With(a.perm(PermZonesEdit)).Patch("/settings", a.handleUpdateZoneSettings)
					r.With(a.perm(PermZonesEdit)).Post("/nameservers", a.handleChangeZoneNameservers)

					r.With(a.perm(PermZonesRead)).Get("/dnssec", a.handleGetDNSSEC)
					r.With(a.perm(PermZonesEdit)).Post("/dnssec/enable", a.handleEnableDNSSEC)
					r.With(a.perm(PermZonesEdit)).Post("/dnssec/disable", a.handleDisableDNSSEC)
					r.With(a.perm(PermZonesEdit)).Post("/dnssec/keys", a.handleAddCryptoKey)
					r.With(a.perm(PermZonesEdit)).Patch("/dnssec/keys/{keyID}", a.handleUpdateCryptoKey)
					r.With(a.perm(PermZonesEdit)).Delete("/dnssec/keys/{keyID}", a.handleDeleteCryptoKey)

					r.With(a.perm(PermZonesRead)).Post("/check-nameservers", a.handleCheckNameservers)
					r.With(a.perm(PermOrgUpdate)).Post("/activate", a.handleActivateZone)
					r.With(a.perm(PermZonesDelete)).Post("/move", a.handleMoveZone)
					r.With(a.perm(PermZonesEdit)).Post("/actions/{action}", a.handleZoneAction)
					r.With(a.perm(PermAuditRead)).Get("/audit-logs", a.handleZoneAudit)
				})
			})
		})

		r.Route("/admin", func(r chi.Router) {
			r.Use(a.RequireActor)

			// Organization management: instance administrators, and global API tokens with
			// "Manage organizations" or "Full administrator" access.
			r.Group(func(r chi.Router) {
				r.Use(a.RequireInstance("orgs"))
				r.Get("/orgs", a.handleAdminOrgs)
				r.Post("/orgs", a.handleAdminCreateOrg)
				r.Patch("/orgs/{orgID}", a.handleAdminUpdateOrg)
			})

			// Signed-in administrators only: tokens never create tokens, and test emails go to the
			// signed-in administrator.
			r.Group(func(r chi.Router) {
				r.Use(a.RequireUser, a.RequireSuperadmin)
				r.Get("/tokens", a.handleListGlobalTokens)
				r.Post("/tokens", a.handleCreateGlobalToken)
				r.Post("/tokens/{tokenID}/roll", a.handleRollGlobalToken)
				r.Delete("/tokens/{tokenID}", a.handleRevokeGlobalToken)
				r.Post("/settings/test-email", a.handleTestEmail)
			})

			r.Group(func(r chi.Router) {
				r.Use(a.RequireInstance("admin"))
				r.Get("/overview", a.handleAdminOverview)
				r.Get("/servers", a.handleListServers)
				r.Post("/servers", a.handleCreateServer)
				r.Post("/servers/test", a.handleTestServer)
				r.Put("/servers/{serverID}", a.handleUpdateServer)
				r.Delete("/servers/{serverID}", a.handleDeleteServer)
				r.Get("/servers/{serverID}/status", a.handleServerStatus)
				r.Get("/servers/{serverID}/unmanaged-zones", a.handleUnmanagedZones)
				r.Get("/servers/{serverID}/config", a.handleServerConfig)
				r.Post("/servers/{serverID}/adopt", a.handleAdoptZones)
				r.Get("/servers/{serverID}/tsig-keys", a.handleListTSIG)
				r.Post("/servers/{serverID}/tsig-keys", a.handleCreateTSIG)
				r.Get("/servers/{serverID}/tsig-keys/{keyID}", a.handleRevealTSIG)
				r.Delete("/servers/{serverID}/tsig-keys/{keyID}", a.handleDeleteTSIG)
				r.Get("/nameserver-sets", a.handleListNameserverSets)
				r.Post("/nameserver-sets", a.handleSaveNameserverSet)
				r.Put("/nameserver-sets/{setID}", a.handleSaveNameserverSet)
				r.Delete("/nameserver-sets/{setID}", a.handleDeleteNameserverSet)
				r.Get("/settings", a.handleGetSettings)
				r.Patch("/settings", a.handleUpdateSettings)
				r.Post("/settings/test-ldap", a.handleTestLDAP)
				r.Get("/users", a.handleAdminUsers)
				r.Post("/users", a.handleAdminCreateUser)
				r.Get("/users/{userID}", a.handleAdminUserDetail)
				r.Patch("/users/{userID}", a.handleAdminUpdateUser)
				r.Delete("/users/{userID}", a.handleAdminDeleteUser)
				r.Get("/zones", a.handleAdminZones)
				r.Get("/templates", a.handleAdminTemplates)
				r.Post("/templates", a.handleAdminCreateTemplate)
				r.Put("/templates/{templateID}", a.handleAdminUpdateTemplate)
				r.Delete("/templates/{templateID}", a.handleAdminDeleteTemplate)
				r.Get("/audit-logs", a.handleAdminAudit)
				r.Get("/audit-logs/export", a.handleAdminAuditExport)
			})
		})

		r.NotFound(func(w http.ResponseWriter, r *http.Request) { a.fail(w, r, errNotFound("Endpoint")) })
		r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
			a.fail(w, r, errCode(405, "method_not_allowed", "Method not allowed"))
		})
	})

	r.Handle("/*", a.spa(webFS))
	return r
}

func init() {
	// Go's built-in table does not know the web app manifest extension.
	_ = mime.AddExtensionType(".webmanifest", "application/manifest+json")
}

const csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
	"font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'; " +
	"base-uri 'self'; form-action 'self'"

func (a *App) spa(webFS fs.FS) http.Handler {
	if webFS == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "The web UI is not bundled in this build. Run the Vite dev server.", http.StatusNotFound)
		})
	}
	files := http.FileServer(http.FS(webFS))
	index, _ := fs.ReadFile(webFS, "index.html")
	// Link previews (Slack, X, LinkedIn) require an absolute og:image URL.
	if base := strings.TrimSuffix(a.Cfg.PublicURL, "/"); base != "" {
		index = []byte(strings.Replace(string(index), `content="/og-image.png"`, `content="`+html.EscapeString(base)+`/og-image.png"`, 1))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p != "" && p != "index.html" {
			if st, err := fs.Stat(webFS, p); err == nil && !st.IsDir() {
				if strings.HasPrefix(p, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "public, max-age=3600")
				}
				files.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(p, "assets/") {
				http.NotFound(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", csp)
		_, _ = w.Write(index)
	})
}
