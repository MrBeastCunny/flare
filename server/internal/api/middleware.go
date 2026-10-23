package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	sessionCookie = "flare_session"
	csrfCookie    = "flare_csrf"
	csrfHeader    = "X-CSRF-Token"
)

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "flare_http_requests_total", Help: "HTTP requests by route and status.",
	}, []string{"method", "route", "status"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "flare_http_request_duration_seconds", Help: "HTTP request latency.",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "route"})
)

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// clientIP returns the caller IP, honouring proxy headers only when configured.
func (a *App) clientIP(r *http.Request) string {
	if a.Cfg.TrustProxy {
		if v := r.Header.Get("X-Real-IP"); v != "" {
			return strings.TrimSpace(v)
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			return strings.TrimSpace(strings.Split(v, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Base wraps every request with request IDs, logging, recovery, metrics and security headers.
func (a *App) Base(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rid := r.Header.Get("X-Request-ID")
		if rid == "" || len(rid) > 64 {
			rid = uuid.NewString()
		}
		ctx := context.WithValue(r.Context(), keyRequestID, rid)
		r = r.WithContext(ctx)

		h := w.Header()
		h.Set("X-Request-ID", rid)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if a.Cfg.CookieSecure {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			if rec := recover(); rec != nil {
				a.Log.Error("panic", "err", rec, "stack", string(debug.Stack()), "request_id", rid)
				if sw.status == 0 {
					writeJSON(sw, 500, map[string]any{"error": apiError{Code: "internal_error", Message: "Internal server error"}})
				}
			}
			route := "unmatched"
			if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
				route = rc.RoutePattern()
			}
			if sw.status == 0 {
				sw.status = 200
			}
			dur := time.Since(start)
			httpRequests.WithLabelValues(r.Method, route, strconv.Itoa(sw.status)).Inc()
			httpDuration.WithLabelValues(r.Method, route).Observe(dur.Seconds())
			if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/scim/") || sw.status >= 500 {
				a.Log.Info("request", "method", r.Method, "path", r.URL.Path, "route", route, "status", sw.status,
					"duration_ms", dur.Milliseconds(), "bytes", sw.bytes, "ip", a.clientIP(r), "request_id", rid)
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

// Authenticate resolves the session cookie or bearer token into an Actor (if any).
func (a *App) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// API tokens arrive as a Bearer token, or in X-API-Key for PowerDNS-compatible clients.
		raw := ""
		if authz := r.Header.Get("Authorization"); strings.HasPrefix(authz, "Bearer ") {
			raw = strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
		} else if k := r.Header.Get("X-API-Key"); k != "" {
			raw = strings.TrimSpace(k)
		}
		if raw != "" {
			tok, err := a.Store.APITokenByHash(ctx, secure.HashToken(raw))
			if err != nil {
				if !errors.Is(err, db.ErrNotFound) {
					a.fail(w, r, err)
					return
				}
				a.fail(w, r, errUnauthorized("Invalid or expired API token."))
				return
			}
			ip := a.clientIP(r)
			if len(tok.IPAllowlist) > 0 && !ipAllowed(ip, tok.IPAllowlist) {
				a.fail(w, r, errForbidden("This API token is not allowed from your IP address."))
				return
			}
			_ = a.Store.TouchAPIToken(ctx, tok.ID, ip)
			act := &Actor{Type: "api_token", Token: tok, OrgID: tok.OrgID, ID: &tok.ID, Label: "API token: " + tok.Name}
			next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, keyActor, act)))
			return
		}
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			se, err := a.Store.SessionByToken(ctx, secure.HashToken(c.Value))
			if err == nil {
				u, err := a.Store.UserByID(ctx, se.UserID)
				if err == nil && !u.Disabled {
					if time.Since(se.LastSeenAt) > time.Minute {
						_ = a.Store.TouchSession(ctx, se.ID, a.clientIP(r))
					}
					act := &Actor{Type: "user", User: u, Session: se, ID: &u.ID, Label: u.Email}
					ctx = context.WithValue(ctx, keyActor, act)
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CSRF protects cookie-authenticated, state-changing requests using a double-submit token.
func (a *App) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.Header.Get("X-API-Key") != "" {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(csrfCookie)
		h := r.Header.Get(csrfHeader)
		if err != nil || c.Value == "" || h == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(h)) != 1 {
			a.fail(w, r, errCode(403, "csrf_failed", "Your session token is missing or stale. Reload the page and try again."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie issues the readable CSRF cookie if absent.
func (a *App) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 20 {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: secure.RandomToken(24), Path: "/", Secure: a.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: 60 * 60 * 24 * 365})
}

func (a *App) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		act := actorFrom(r.Context())
		if act != nil && act.Type != "user" {
			a.fail(w, r, errForbidden("This endpoint is only available to signed-in users, not API tokens."))
			return
		}
		if act == nil {
			a.fail(w, r, errUnauthorized("Sign in to continue."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) RequireActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if actorFrom(r.Context()) == nil {
			a.fail(w, r, errUnauthorized("Sign in to continue."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireInstance allows instance administrators, and global API tokens whose instance role is at
// least level ("orgs" or "admin").
func (a *App) RequireInstance(level string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			act := actorFrom(r.Context())
			ok := act != nil && ((act.Type == "user" && act.User.IsSuperadmin) ||
				(act.Type == "api_token" && act.Token.OrgID == nil && instanceRoleRank[act.Token.InstanceRole] >= instanceRoleRank[level]))
			if !ok {
				a.fail(w, r, errForbidden("Instance administrator access is required."))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (a *App) RequireSuperadmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		act := actorFrom(r.Context())
		if act == nil || act.Type != "user" || !act.User.IsSuperadmin {
			a.fail(w, r, errForbidden("Instance administrator access is required."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LoadOrg resolves {orgID} and the actor's access within that org.
func (a *App) LoadOrg(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		act := actorFrom(ctx)
		orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
		if err != nil {
			a.fail(w, r, errNotFound("Organization"))
			return
		}
		org, err := a.Store.OrgByID(ctx, orgID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		var acc *access
		switch act.Type {
		case "api_token":
			if acc, err = a.tokenAccess(r, act.Token, org); err != nil {
				a.fail(w, r, err)
				return
			}
		case "user":
			m, err := a.Store.Membership(ctx, org.ID, act.User.ID)
			if err == nil && m.Suspended && !act.User.IsSuperadmin {
				a.fail(w, r, errCode(403, "member_suspended", "Your access to this organization has been deactivated by your identity provider."))
				return
			} else if err == nil {
				acc = &access{Role: m.Role, ZoneIDs: m.ZoneIDs}
			} else if errors.Is(err, db.ErrNotFound) && act.User.IsSuperadmin {
				acc = &access{Role: "admin", ViaInstance: true}
			} else if errors.Is(err, db.ErrNotFound) {
				a.fail(w, r, errNotFound("Organization"))
				return
			} else {
				a.fail(w, r, err)
				return
			}
		default:
			a.fail(w, r, errForbidden("Not allowed"))
			return
		}

		superadmin := (act.Type == "user" && act.User.IsSuperadmin) || (act.Type == "api_token" && tokenInstanceAdmin(act.Token))
		if org.Suspended && !superadmin {
			a.fail(w, r, errCode(403, "org_suspended", "This organization has been suspended. Contact your administrator."))
			return
		}
		if len(org.IPAllowlist) > 0 && !superadmin && !ipAllowed(a.clientIP(r), org.IPAllowlist) {
			a.fail(w, r, errCode(403, "ip_not_allowed", "Access to this organization is restricted to approved networks."))
			return
		}
		if act.Type == "user" && !superadmin {
			if org.EnforceMFA && !act.User.TOTPEnabled && act.Session.AuthMethod != "sso" {
				a.fail(w, r, errCode(403, "mfa_required", "This organization requires two-factor authentication. Enable it in your profile to continue."))
				return
			}
			if org.SessionTTLMinutes != nil && *org.SessionTTLMinutes > 0 &&
				time.Since(act.Session.CreatedAt) > time.Duration(*org.SessionTTLMinutes)*time.Minute {
				a.fail(w, r, errCode(401, "session_expired", "Your session exceeded this organization's maximum session length. Sign in again."))
				return
			}
		}
		ctx = context.WithValue(ctx, keyOrg, org)
		ctx = context.WithValue(ctx, keyMembership, acc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withOrg(ctx context.Context, org *store.Org, acc *access) context.Context {
	ctx = context.WithValue(ctx, keyOrg, org)
	return context.WithValue(ctx, keyMembership, acc)
}

// LoadZone resolves {zoneID} inside the current org and enforces zone scope.
func (a *App) LoadZone(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		org := orgFrom(ctx)
		zid, err := uuid.Parse(chi.URLParam(r, "zoneID"))
		if err != nil {
			a.fail(w, r, errNotFound("Zone"))
			return
		}
		z, err := a.Store.ZoneByID(ctx, org.ID, zid)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if !zoneAllowed(accessFrom(ctx), z.ID) {
			a.fail(w, r, errNotFound("Zone"))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, keyZone, z)))
	})
}

func ipAllowed(ip string, cidrs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		if !strings.Contains(c, "/") {
			if net.ParseIP(c).Equal(parsed) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

func validateCIDRs(list []string) error {
	for _, c := range list {
		if strings.Contains(c, "/") {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("%q is not a valid CIDR range", c)
			}
		} else if net.ParseIP(c) == nil {
			return fmt.Errorf("%q is not a valid IP address", c)
		}
	}
	return nil
}

// ---- Rate limiting ----

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{buckets: map[string]*bucket{}}
	go func() {
		for range time.Tick(5 * time.Minute) {
			rl.mu.Lock()
			for k, b := range rl.buckets {
				if time.Since(b.last) > 30*time.Minute {
					delete(rl.buckets, k)
				}
			}
			rl.mu.Unlock()
		}
	}()
	return rl
}

// allow consumes one token from key's bucket (capacity burst, refilled at perMinute).
func (rl *rateLimiter) allow(key string, burst int, perMinute float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(burst), last: now}
		rl.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * perMinute
	if b.tokens > float64(burst) {
		b.tokens = float64(burst)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RateLimit limits requests per client IP for sensitive endpoints.
func (a *App) RateLimit(name string, burst int, perMinute float64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !a.limiter.allow(name+":"+a.clientIP(r), burst, perMinute) {
				w.Header().Set("Retry-After", "60")
				a.fail(w, r, errCode(429, "rate_limited", "Too many attempts. Wait a minute and try again."))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// APIRateLimit applies a generous per-actor limit to the authenticated API.
func (a *App) APIRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := "ip:" + a.clientIP(r)
		if act := actorFrom(r.Context()); act != nil && act.ID != nil {
			key = act.Type + ":" + act.ID.String()
		}
		if !a.limiter.allow("api:"+key, 600, 1200) {
			w.Header().Set("Retry-After", "10")
			a.fail(w, r, errCode(429, "rate_limited", "Rate limit exceeded. Slow down and retry shortly."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// setSessionCookie issues the session cookie.
func (a *App) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: a.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
}

func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: a.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// startSession creates a session for u and sets the cookie.
func (a *App) startSession(w http.ResponseWriter, r *http.Request, u *store.User, method string, ssoConn *uuid.UUID) error {
	set := a.Settings(r.Context())
	ttl := a.Cfg.SessionTTL
	if set.SessionTTLHours > 0 {
		ttl = time.Duration(set.SessionTTLHours) * time.Hour
	}
	token := secure.RandomToken(32)
	if _, err := a.Store.CreateSession(r.Context(), secure.HashToken(token), u.ID, method, ssoConn, a.clientIP(r), r.UserAgent(), ttl); err != nil {
		return err
	}
	_ = a.Store.TouchLogin(r.Context(), u.ID)
	a.setSessionCookie(w, token, ttl)
	return nil
}
