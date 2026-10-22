package api

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	zonesByStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "flare_zones", Help: "Zones by status."}, []string{"status"})
	serverUp      = promauto.NewGaugeVec(prometheus.GaugeOpts{Name: "flare_pdns_server_up", Help: "PowerDNS server reachability."}, []string{"server"})
)

// RunJobs runs background maintenance until ctx is cancelled. Each job takes a Postgres
// advisory lock so only one replica executes it at a time.
func (a *App) RunJobs(ctx context.Context) {
	type job struct {
		id       int64
		interval time.Duration
		fn       func(context.Context)
	}
	jobs := []job{
		{1001, 15 * time.Second, a.DeliverWebhooks},
		{1002, a.Cfg.NSCheckInterval, a.checkDelegations},
		{1003, time.Minute, a.checkServers},
		{1004, time.Hour, a.housekeeping},
	}
	for _, j := range jobs {
		go func(j job) {
			// Stagger first runs to avoid a thundering herd on startup.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			t := time.NewTicker(j.interval)
			defer t.Stop()
			for {
				a.withLock(ctx, j.id, j.fn)
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}(j)
	}
}

func (a *App) withLock(ctx context.Context, id int64, fn func(context.Context)) {
	conn, err := a.Store.Pool.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, id).Scan(&ok); err != nil || !ok {
		return
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, id) }()
	jctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	defer func() {
		if rec := recover(); rec != nil {
			a.Log.Error("background job panic", "job", id, "err", rec)
		}
	}()
	fn(jctx)
}

func (a *App) checkDelegations(ctx context.Context) {
	pending, err := a.Store.ZonesByStatus(ctx, []string{"pending", "moved"}, 4*time.Minute)
	if err != nil {
		a.Log.Error("load pending zones", "err", err)
		return
	}
	active, err := a.Store.ZonesByStatus(ctx, []string{"active"}, 24*time.Hour)
	if err == nil {
		pending = append(pending, active...)
	}
	for i := range pending {
		z := &pending[i]
		updated, err := a.CheckZoneDelegation(ctx, z)
		if err != nil {
			a.Log.Warn("delegation check failed", "zone", z.Name, "err", err)
			continue
		}
		if updated.Status != z.Status {
			a.systemAudit(ctx, z.OrgID, z.ID, "zone.status_change", "zone", z.Name,
				map[string]any{"from": z.Status, "to": updated.Status, "observed": updated.ObservedNameservers})
			a.Log.Info("zone status changed", "zone", z.Name, "from", z.Status, "to", updated.Status)
		}
	}
	if counts, err := a.Store.ZoneCountsByStatus(ctx, nil); err == nil {
		zonesByStatus.Reset()
		for st, n := range counts {
			zonesByStatus.WithLabelValues(st).Set(float64(n))
		}
	}
}

func (a *App) checkServers(ctx context.Context) {
	servers, err := a.Store.ListServers(ctx)
	if err != nil {
		return
	}
	for i := range servers {
		s := &servers[i]
		if !s.Enabled {
			continue
		}
		c, err := a.PDNS(s)
		if err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		info, err := c.Server(cctx)
		cancel()
		if err != nil {
			_ = a.Store.SetServerStatus(ctx, s.ID, "unreachable", "")
			serverUp.WithLabelValues(s.Name).Set(0)
			if s.LastStatus != "unreachable" {
				a.Log.Error("powerdns server unreachable", "server", s.Name, "err", err)
			}
			continue
		}
		_ = a.Store.SetServerStatus(ctx, s.ID, "healthy", info.Version)
		serverUp.WithLabelValues(s.Name).Set(1)
	}
}

func (a *App) housekeeping(ctx context.Context) {
	if err := a.Store.PurgeExpired(ctx); err != nil {
		a.Log.Error("purge expired", "err", err)
	}
	s := a.Settings(ctx)
	if n, err := a.Store.PurgeAuditLogs(ctx, s.AuditRetentionDays); err != nil {
		a.Log.Error("purge audit logs", "err", err)
	} else if n > 0 {
		a.Log.Info("purged audit logs past retention", "rows", n, "retention_days", s.AuditRetentionDays)
	}
}
