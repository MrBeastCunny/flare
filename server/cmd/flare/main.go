// Command flare runs the Flare DNS dashboard.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/flare-dns/flare/internal/api"
	"github.com/flare-dns/flare/internal/config"
	"github.com/flare-dns/flare/internal/db"
	"github.com/flare-dns/flare/internal/secure"
	"github.com/flare-dns/flare/internal/store"
	"github.com/flare-dns/flare/internal/web"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "migrate":
		err = migrate()
	case "healthcheck":
		err = healthcheck()
	case "reset-admin":
		err = resetAdmin(os.Args[2:])
	case "version":
		fmt.Println(api.Version)
	default:
		fmt.Fprintf(os.Stderr, "usage: flare [serve|migrate|healthcheck|reset-admin|version]\n")
		os.Exit(2)
	}
	if err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func logger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.LogLevel))
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	l := slog.New(h).With("service", "flare")
	slog.SetDefault(l)
	return l
}

func setup(ctx context.Context) (*config.Config, *slog.Logger, *store.Store, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	log := logger(cfg)
	pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("migrate: %w", err)
	}
	return cfg, log, store.New(pool), nil
}

func serve() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, log, st, err := setup(ctx)
	if err != nil {
		return err
	}
	defer st.Pool.Close()
	box, err := secure.NewBox(cfg.SecretKey)
	if err != nil {
		return err
	}
	app := api.New(cfg, st, box, log)
	app.RunJobs(ctx)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Router(web.FS()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "public_url", cfg.PublicURL, "version", api.Version, "ui_bundled", web.FS() != nil)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func migrate() error {
	ctx := context.Background()
	_, log, st, err := setup(ctx)
	if err != nil {
		return err
	}
	st.Pool.Close()
	log.Info("migrations applied")
	return nil
}

// healthcheck is used by container HEALTHCHECK in images without a shell.
func healthcheck() error {
	addr := os.Getenv("FLARE_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/readyz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}

// resetAdmin creates or restores an instance administrator. Intended for break-glass recovery.
func resetAdmin(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ExitOnError)
	email := fs.String("email", "", "administrator email")
	password := fs.String("password", "", "new password (min 12 characters)")
	_ = fs.Parse(args)
	if *email == "" || len(*password) < 12 {
		return errors.New("usage: flare reset-admin -email admin@example.com -password <at least 12 characters>")
	}
	ctx := context.Background()
	_, log, st, err := setup(ctx)
	if err != nil {
		return err
	}
	defer st.Pool.Close()
	hash, err := secure.HashPassword(*password)
	if err != nil {
		return err
	}
	e := strings.ToLower(strings.TrimSpace(*email))
	u, err := st.UserByEmail(ctx, e)
	if errors.Is(err, db.ErrNotFound) {
		u, err = st.CreateUser(ctx, store.NewUser{Email: e, Name: "Administrator", PasswordHash: &hash, IsSuperadmin: true,
			EmailVerified: true, CreatedVia: "setup"})
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		if err := st.SetUserPassword(ctx, u.ID, hash); err != nil {
			return err
		}
		if err := st.SetUserAdminFlags(ctx, u.ID, true, false); err != nil {
			return err
		}
		if err := st.SetUserTOTP(ctx, u.ID, nil, false, nil); err != nil {
			return err
		}
		_ = st.DeleteUserSessions(ctx, u.ID, nil)
	}
	_, _ = st.InsertAudit(ctx, store.AuditEntry{ActorType: "system", ActorLabel: "CLI", Action: "admin.break_glass_reset",
		ResourceType: "user", ResourceID: u.ID.String(), ResourceName: u.Email, Outcome: "success"})
	log.Info("administrator access restored", "email", u.Email)
	return nil
}
