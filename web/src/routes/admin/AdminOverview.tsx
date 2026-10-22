import { useQuery } from "@tanstack/react-query";
import { Badge, Banner, LayerCard, Text, LinkButton } from "@cloudflare/kumo";
import { HardDrivesIcon, EnvelopeSimpleIcon } from "@phosphor-icons/react";
import { PageHeader, StatCard, Section } from "../../components/ui";
import { ActivityChart } from "../../components/ActivityChart";
import { VirtualList } from "../../components/VirtualList";
import { actionLabel } from "../../components/AuditLogView";
import { api } from "../../lib/api";
import { keys } from "../../lib/queries";
import { formatNumber, timeAgo, stripDot } from "../../lib/format";
import type { AuditEntry, DayCount, PdnsServer } from "../../lib/types";

interface AdminOverviewData {
  user_count: number;
  mfa_user_count: number;
  org_count: number;
  zone_count: number;
  zone_status_counts: Record<string, number>;
  server_count: number;
  healthy_server_count: number;
  servers: PdnsServer[];
  activity: DayCount[];
  recent_activity: AuditEntry[];
  version: string;
  email_enabled: boolean;
}

export default function AdminOverview() {
  const ov = useQuery({ queryKey: keys.admin("overview"), queryFn: () => api<AdminOverviewData>("/admin/overview"), refetchInterval: 30_000 });
  const d = ov.data;
  return (
    <div className="grid gap-6">
      <PageHeader title="Instance overview" description={d ? `Version ${d.version}` : undefined} />
      {d && d.healthy_server_count < d.server_count && (
        <Banner variant="error" icon={<HardDrivesIcon weight="fill" />} title="DNS server unreachable" description={`${d.server_count - d.healthy_server_count} of ${d.server_count} DNS servers failed their last health check.`} action={<LinkButton size="sm" href="/admin/servers">View servers</LinkButton>} />
      )}
      {d && !d.email_enabled && (
        <Banner
          variant="alert"
          icon={<EnvelopeSimpleIcon weight="fill" />}
          title="Email delivery is not configured"
          description="Invitations and password resets cannot be emailed. Configure SMTP in settings."
          action={<LinkButton size="sm" href="/admin/settings">Configure</LinkButton>}
        />
      )}
      <div className="grid gap-4 md:grid-cols-4">
        <StatCard loading={ov.isLoading} label="Organizations" value={formatNumber(d?.org_count)} />
        <StatCard loading={ov.isLoading} label="Users" value={formatNumber(d?.user_count)} hint={d ? `${Math.round((d.mfa_user_count / Math.max(1, d.user_count)) * 100)}% with 2FA` : undefined} />
        <StatCard loading={ov.isLoading} label="Zones" value={formatNumber(d?.zone_count)} hint={d ? `${d.zone_status_counts.active ?? 0} active, ${d.zone_status_counts.pending ?? 0} pending` : undefined} />
        <StatCard loading={ov.isLoading} label="DNS servers" value={d ? `${d.healthy_server_count} / ${d.server_count}` : "0"} hint="Healthy" />
      </div>
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="grid content-start gap-6 lg:col-span-2">
          <LayerCard className="px-5 py-4">
            <div className="mb-2 grid gap-0.5">
              <Text variant="heading" as="h2">
                Platform activity
              </Text>
              <Text variant="secondary">Audit events across all organizations, last 30 days.</Text>
            </div>
            <ActivityChart data={d?.activity ?? []} loading={ov.isLoading} name="Events" />
          </LayerCard>
          <Section padded={false} title="Latest events" actions={<LinkButton size="sm" variant="ghost" href="/admin/audit-log">View audit log</LinkButton>}>
            <VirtualList
              ariaLabel="Latest events"
              items={d?.recent_activity ?? []}
              itemKey={(e) => String(e.id)}
              maxHeight={420}
              renderItem={(e) => (
                <div className="flex items-center justify-between gap-4 px-5 py-3">
                  <div className="grid min-w-0 gap-0.5">
                    <span className="truncate font-medium text-kumo-strong">{actionLabel(e.action)}</span>
                    <span className="truncate text-sm text-kumo-subtle">
                      {e.actor_label}
                      {e.org_name ? ` · ${e.org_name}` : ""}
                      {e.resource_name && e.resource_name !== e.actor_label ? ` · ${stripDot(e.resource_name)}` : ""}
                    </span>
                  </div>
                  <span className="shrink-0 text-sm text-kumo-subtle">{timeAgo(e.created_at)}</span>
                </div>
              )}
            />
          </Section>
        </div>
        <Section padded={false} title="DNS servers" actions={<LinkButton size="sm" variant="ghost" href="/admin/servers">Manage</LinkButton>}>
          <VirtualList
            ariaLabel="DNS servers"
            items={d?.servers ?? []}
            itemKey={(s) => s.id}
            maxHeight={420}
            renderItem={(s) => (
              <div className="flex items-center justify-between gap-3 px-5 py-3">
                <div className="grid min-w-0 gap-0.5">
                  <span className="truncate font-medium">{s.name}</span>
                  <span className="truncate text-sm text-kumo-subtle">
                    {s.zone_count} zones · PowerDNS {s.version || "unknown"}
                  </span>
                </div>
                <Badge variant={s.last_status === "healthy" ? "success" : s.last_status === "unreachable" ? "error" : "neutral"} appearance="dot">
                  {s.last_status === "healthy" ? "Healthy" : s.last_status === "unreachable" ? "Unreachable" : "Unknown"}
                </Badge>
              </div>
            )}
          />
        </Section>
      </div>
    </div>
  );
}
