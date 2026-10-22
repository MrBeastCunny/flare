package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is loaded from environment variables. See .env.example in the repo root.
type Config struct {
	ListenAddr      string
	PublicURL       string // externally reachable base URL, e.g. https://dns.example.com
	DatabaseURL     string
	DBMaxConns      int32
	SecretKey       [32]byte
	CookieSecure    bool
	TrustProxy      bool
	LogLevel        string
	LogFormat       string
	DNSResolver     string // host:port used for delegation checks
	SessionTTL      time.Duration
	NSCheckInterval time.Duration
	DevMode         bool
	MetricsToken    string
	// WebhookAllowPrivate permits webhook deliveries to private, loopback and
	// link-local addresses. Off by default to prevent SSRF into the internal network.
	WebhookAllowPrivate bool

	// Optional bootstrap values. When set, the first-run setup wizard registers
	// this PowerDNS server automatically.
	BootstrapPDNSURL    string
	BootstrapPDNSKey    string
	BootstrapPDNSServer string

	// Optional SMTP settings; can also be configured in the admin dashboard.
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPTLS      string // starttls | tls | none
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:          env("FLARE_LISTEN_ADDR", ":8080"),
		PublicURL:           strings.TrimRight(env("FLARE_PUBLIC_URL", "http://localhost:8080"), "/"),
		DatabaseURL:         env("FLARE_DATABASE_URL", ""),
		DBMaxConns:          int32(envInt("FLARE_DB_MAX_CONNS", 20)),
		TrustProxy:          envBool("FLARE_TRUST_PROXY", false),
		LogLevel:            env("FLARE_LOG_LEVEL", "info"),
		LogFormat:           env("FLARE_LOG_FORMAT", "json"),
		DNSResolver:         env("FLARE_DNS_RESOLVER", "8.8.8.8:53"),
		SessionTTL:          envDuration("FLARE_SESSION_TTL", 7*24*time.Hour),
		NSCheckInterval:     envDuration("FLARE_NS_CHECK_INTERVAL", 5*time.Minute),
		DevMode:             envBool("FLARE_DEV", false),
		MetricsToken:        env("FLARE_METRICS_TOKEN", ""),
		WebhookAllowPrivate: envBool("FLARE_WEBHOOK_ALLOW_PRIVATE", false),
		BootstrapPDNSURL:    env("FLARE_BOOTSTRAP_PDNS_URL", ""),
		BootstrapPDNSKey:    env("FLARE_BOOTSTRAP_PDNS_API_KEY", ""),
		BootstrapPDNSServer: env("FLARE_BOOTSTRAP_PDNS_SERVER_ID", "localhost"),
		SMTPHost:            env("FLARE_SMTP_HOST", ""),
		SMTPPort:            envInt("FLARE_SMTP_PORT", 587),
		SMTPUsername:        env("FLARE_SMTP_USERNAME", ""),
		SMTPPassword:        env("FLARE_SMTP_PASSWORD", ""),
		SMTPFrom:            env("FLARE_SMTP_FROM", ""),
		SMTPTLS:             env("FLARE_SMTP_TLS", "starttls"),
	}
	c.CookieSecure = envBool("FLARE_COOKIE_SECURE", strings.HasPrefix(c.PublicURL, "https://"))

	if c.DatabaseURL == "" {
		return nil, errors.New("FLARE_DATABASE_URL is required")
	}
	secret := os.Getenv("FLARE_SECRET_KEY")
	if secret == "" {
		if !c.DevMode {
			return nil, errors.New("FLARE_SECRET_KEY is required (at least 32 characters)")
		}
		secret = "flare-development-secret-key-do-not-use-in-production"
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("FLARE_SECRET_KEY must be at least 32 characters, got %d", len(secret))
	}
	c.SecretKey = sha256.Sum256([]byte(secret))
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
