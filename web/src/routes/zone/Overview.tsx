import { useQuery } from "@tanstack/react-query";
import { Badge, Banner, LayerCard, Text, LinkButton } from "@cloudflare/kumo";
import { ListBulletsIcon, LockKeyIcon, PlusIcon, WarningIcon } from "@phosphor-icons/react";
import { PageHeader, Section, StatCard, ZoneStatusBadge, DetailRow, Mono } from "../../components/ui";
import { NameserverInstructions, NameserverList } from "../../components/NameserverInstructions";
import { ActivityChart } from "../../components/ActivityChart";
import { VirtualList } from "../../components/VirtualList";
import { actionLabel } from "../../components/AuditLogView";
import { api } from "../../lib/api";
import { keys, useCurrentZone, usePerms } from "../../lib/queries";
import { formatDateTime, formatNumber, stripDot, timeAgo, relativeName } from "../../lib/format";
import type { AuditEntry, DayCount, Zone } from "../../lib/types";

interface Overview {
  zone: Zone;
  serial?: number;
  dnssec?: boolean;
  kind?: string;
  server_reachable?: boolean;
  server_error?: string;
  record_counts: Record<string, number>;
  record_total: number;
  activity?: DayCount[];
  recent_changes?: AuditEntry[];
  top_queries?: { name: string; type: string; count: number }[];
}

const kindLabel: Record<string, string> = { Native: "Primary (native)", Master: "Primary", Slave: "Secondary" };

export default function ZoneOverview() {
  const { zone, orgId } = useCurrentZone();
  const { can } = usePerms(orgId);
  const ov = useQuery({
    queryKey: keys.zoneOverview(orgId, zone?.id ?? ""),
    queryFn: () => api<Overview>(`/orgs/${orgId}/zones/${zone!.id}/overview`),
    enabled: !!zone,
  });
  if (!zone) return null;
  const base = `/${orgId}/${stripDot(zone.name)}`;
  const counts = Object.entries(ov.data?.record_counts ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="grid gap-6">
      <PageHeader
        title={
          <span className="flex flex-wrap items-center gap-3">
            {stripDot(zone.name)} <ZoneStatusBadge status={zone.status} />
          </span>
        }
        description={`Managed on ${zone.pdns_server_name ?? "PowerDNS"}`}
        actions={
          <>
            <LinkButton icon={<ListBulletsIcon />} href={`${base}/dns`}>
              DNS records
            </LinkButton>
            {can("dns.edit") && zone.kind !== "Slave" && (
              <LinkButton variant="primary" icon={<PlusIcon />} href={`${base}/dns`}>
                Add record
              </LinkButton>
            )}
          </>
        }
      />

      {ov.data?.server_reachable === false && (
        <Banner variant="error" icon={<WarningIcon weight="fill" />} title="DNS server unreachable" description={ov.data.server_error} />
      )}

      {zone.status !== "active" && zone.kind !== "Slave" && zone.kind !== "Consumer" && (
        <Section>
          <NameserverInstructions zone={zone} />
        </Section>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard loading={ov.isLoading} label="DNS records" value={formatNumber(ov.data?.record_total ?? 0)} />
        <StatCard
          loading={ov.isLoading}
          label="DNSSEC"
          value={ov.data?.dnssec ? "Enabled" : "Off"}
          icon={<LockKeyIcon size={20} className={ov.data?.dnssec ? "text-kumo-success" : undefined} />}
        />
        <StatCard loading={ov.isLoading} label="SOA serial" value={<Mono className="text-xl">{ov.data?.serial ?? "None"}</Mono>} />
        <StatCard label="Zone type" value={<span className="text-lg">{kindLabel[zone.kind] ?? zone.kind}</span>} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="grid content-start gap-6 lg:col-span-2">
          {ov.data?.activity && (
            <LayerCard className="px-5 py-4">
              <div className="mb-2 grid gap-0.5">
                <Text variant="heading" as="h2">
                  Changes
                </Text>
                <Text variant="secondary">Configuration changes to this zone over the last 30 days.</Text>
              </div>
              <ActivityChart data={ov.data.activity} loading={ov.isLoading} />
            </LayerCard>
          )}
          {ov.data?.recent_changes && (
            <Section padded={false} title="Recent activity" actions={can("audit.read") && <LinkButton size="sm" variant="ghost" href={`${base}/activity`}>View all</LinkButton>}>
              <VirtualList
                ariaLabel="Recent activity"
                items={ov.data.recent_changes}
                itemKey={(e) => String(e.id)}
                maxHeight={360}
                empty={<div className="px-5 py-8 text-center text-kumo-subtle">No changes recorded yet.</div>}
                renderItem={(e) => (
                  <div className="flex items-center justify-between gap-4 px-5 py-3">
                    <div className="grid min-w-0 gap-0.5">
                      <span className="truncate font-medium text-kumo-strong">{actionLabel(e.action)}</span>
                      <span className="truncate text-sm text-kumo-subtle">
                        {e.actor_label} {e.resource_name && e.resource_name !== e.actor_label ? `· ${stripDot(e.resource_name)}` : ""}
                      </span>
                    </div>
                    <span className="shrink-0 text-sm text-kumo-subtle">{timeAgo(e.created_at)}</span>
                  </div>
                )}
              />
            </Section>
          )}
          {ov.data?.top_queries && ov.data.top_queries.length > 0 && (
            <Section padded={false} title="Most queried names" description="Sampled from the DNS server's recent query ring.">
              <VirtualList
                ariaLabel="Top queries"
                items={ov.data.top_queries}
                itemKey={(qq) => qq.name + qq.type}
                maxHeight={360}
                renderItem={(qq) => (
                  <div className="flex items-center justify-between px-5 py-2.5">
                    <span className="flex items-center gap-2">
                      <Badge variant="outline">{qq.type}</Badge>
                      <Mono>{relativeName(qq.name, zone.name)}</Mono>
                    </span>
                    <span className="tabular-nums text-kumo-subtle">{formatNumber(qq.count)}</span>
                  </div>
                )}
              />
            </Section>
          )}
        </div>

        <div className="grid content-start gap-6">
          <Section title="Nameservers">
            <NameserverList nameservers={zone.assigned_nameservers} />
          </Section>
          <Section title="Record types" padded={false}>
            <VirtualList
              ariaLabel="Record types"
              items={counts}
              itemKey={([t]) => t}
              maxHeight={300}
              empty={<div className="px-5 py-6 text-kumo-subtle">No records.</div>}
              renderItem={([t, n]) => (
                <div className="flex items-center justify-between px-5 py-2.5">
                  <Badge variant="outline">{t}</Badge>
                  <span className="tabular-nums text-kumo-subtle">{formatNumber(n)}</span>
                </div>
              )}
            />
          </Section>
          <Section title="Details">
            <div className="divide-y divide-kumo-line">
              <DetailRow label="Zone ID">
                <Mono className="text-xs">{zone.id}</Mono>
              </DetailRow>
              <DetailRow label="Added">{formatDateTime(zone.created_at)}</DetailRow>
              <DetailRow label="Activated">{zone.activated_at ? formatDateTime(zone.activated_at) : "Not yet"}</DetailRow>
              <DetailRow label="Last delegation check">{timeAgo(zone.last_ns_check_at)}</DetailRow>
            </div>
          </Section>
        </div>
      </div>
    </div>
  );
}
