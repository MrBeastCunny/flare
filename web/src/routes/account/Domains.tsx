import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { Badge, Button, Empty, InputGroup, LayerCard, Meter, Tabs, Text, Tooltip } from "@cloudflare/kumo";
import { isReverseZone } from "../../lib/dns";
import { displayDomain } from "../../lib/idn";
import { GlobeHemisphereWestIcon, MagnifyingGlassIcon, PlusIcon, ArrowsClockwiseIcon, LockKeyIcon, ListBulletsIcon, ChartBarIcon, SlidersHorizontalIcon } from "@phosphor-icons/react";
import { PageHeader, ZoneStatusBadge, StatCard } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { useOrg, useOrgId, useOrgOverview, usePerms, useZones } from "../../lib/queries";
import { formatDate, stripDot, timeAgo, formatNumber } from "../../lib/format";
import { ActivityChart } from "../../components/ActivityChart";
import type { Zone } from "../../lib/types";

const kindLabel: Record<string, string> = {
  Native: "Primary (native)",
  Master: "Primary",
  Slave: "Secondary",
  Producer: "Catalog producer",
  Consumer: "Catalog consumer",
};

export default function Domains() {
  const orgId = useOrgId();
  const navigate = useNavigate();
  const zones = useZones(orgId);
  const org = useOrg(orgId);
  const overview = useOrgOverview(orgId);
  const { can } = usePerms(orgId);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const [view, setView] = useState("all");

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (zones.data ?? []).filter(
      (z) =>
        (status === "all" || z.status === status) &&
        (view === "all" || (view === "reverse") === isReverseZone(z.name)) &&
        (!query || z.name.includes(query) || displayDomain(z.name).toLowerCase().includes(query)),
    );
  }, [zones.data, q, status, view]);
  const reverseCount = (zones.data ?? []).filter((z) => isReverseZone(z.name)).length;

  const counts = overview.data?.status_counts ?? {};
  const max = org.data?.max_zones ?? 0;
  const used = org.data?.zone_count ?? 0;

  const columns: Column<Zone>[] = [
    {
      key: "name",
      header: "Domain",
      width: "38%",
      render: (z) => (
        <div className="flex min-w-0 items-center gap-2.5">
          <GlobeHemisphereWestIcon size={18} className="shrink-0 text-kumo-subtle" />
          <span className="truncate font-medium text-kumo-strong">{displayDomain(z.name)}</span>
          {displayDomain(z.name) !== stripDot(z.name) && <span className="truncate text-sm text-kumo-subtle">{stripDot(z.name)}</span>}
        </div>
      ),
    },
    { key: "status", header: "Status", width: "22%", render: (z) => <ZoneStatusBadge status={z.status} /> },
    { key: "kind", header: "Type", width: "16%", render: (z) => <Text variant="secondary">{kindLabel[z.kind] ?? z.kind}</Text> },
    {
      key: "created",
      header: "Added",
      width: "14%",
      render: (z) => (
        <Tooltip content={formatDate(z.created_at)}>
          <span className="text-kumo-subtle">{timeAgo(z.created_at)}</span>
        </Tooltip>
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "10%",
      align: "right",
      render: (z) => (
        <ActionMenu
          items={[
            { key: "dns", label: "DNS records", icon: <ListBulletsIcon />, onSelect: () => navigate(`/${orgId}/${stripDot(z.name)}/dns`) },
            { key: "overview", label: "Overview", icon: <ChartBarIcon />, onSelect: () => navigate(`/${orgId}/${stripDot(z.name)}`) },
            { key: "dnssec", label: "DNSSEC", icon: <LockKeyIcon />, onSelect: () => navigate(`/${orgId}/${stripDot(z.name)}/dnssec`) },
            { key: "settings", label: "Zone settings", icon: <SlidersHorizontalIcon />, onSelect: () => navigate(`/${orgId}/${stripDot(z.name)}/settings`) },
          ]}
        />
      ),
    },
  ];

  const empty = (
    <div className="py-14">
      <Empty
        icon={<GlobeHemisphereWestIcon size={48} className="text-kumo-inactive" />}
        title={zones.data?.length ? "No domains match your filters" : "Add your first domain"}
        description={
          zones.data?.length
            ? "Try a different search or status."
            : "Host authoritative DNS for a domain you own. We will scan existing records so nothing breaks when you switch nameservers."
        }
        contents={
          !zones.data?.length && can("zones.create") ? (
            <Button variant="primary" icon={<PlusIcon />} onClick={() => navigate(`/${orgId}/add-site`)}>
              Add a domain
            </Button>
          ) : undefined
        }
      />
    </div>
  );

  return (
    <div>
      <PageHeader
        title="Domains"
        description={org.data ? `${org.data.org.name}` : undefined}
        actions={
          can("zones.create") && (
            <Button variant="primary" icon={<PlusIcon />} onClick={() => navigate(`/${orgId}/add-site`)}>
              Add a domain
            </Button>
          )
        }
      />

      <div className="mb-6 grid gap-4 md:grid-cols-4">
        <StatCard loading={org.isLoading} label="Domains" value={formatNumber(used)} hint={max > 0 ? `of ${formatNumber(max)} allowed` : undefined} />
        <StatCard loading={overview.isLoading} label="Active" value={formatNumber(counts.active ?? 0)} hint="Delegated to your nameservers" />
        <StatCard loading={overview.isLoading} label="Pending" value={formatNumber(counts.pending ?? 0)} hint="Waiting for nameserver change" />
        <StatCard loading={overview.isLoading} label="Members" value={formatNumber(overview.data?.member_count ?? 0)} hint={`${overview.data?.mfa_member_count ?? 0} with 2FA`} />
      </div>

      {max > 0 && used / max > 0.8 && (
        <LayerCard className="mb-6 px-5 py-4">
          <Meter label="Zone quota" value={used} max={max} customValue={`${used} / ${max}`} />
        </LayerCard>
      )}

      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-kumo-line px-4 py-3">
          {reverseCount > 0 && (
            <Tabs
              variant="segmented"
              value={view}
              onValueChange={setView}
              tabs={[
                { value: "all", label: "All" },
                { value: "forward", label: "Forward" },
                { value: "reverse", label: `Reverse (${reverseCount})` },
              ]}
            />
          )}
          <InputGroup className="w-full max-w-sm">
            <InputGroup.Addon>
              <MagnifyingGlassIcon />
            </InputGroup.Addon>
            <InputGroup.Input placeholder="Search domains" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search domains" />
          </InputGroup>
          <VirtualSelect
            aria-label="Filter by status"
            className="w-56"
            options={[
              { value: "all", label: `All statuses (${zones.data?.length ?? 0})` },
              { value: "active", label: `Active (${counts.active ?? 0})` },
              { value: "pending", label: `Pending (${counts.pending ?? 0})` },
              { value: "moved", label: `Moved (${counts.moved ?? 0})` },
            ]}
            value={status}
            onChange={setStatus}
          />
          <div className="ml-auto flex items-center gap-2">
            {rows.length !== (zones.data?.length ?? 0) && <Badge variant="neutral">{rows.length} shown</Badge>}
            <Button variant="ghost" size="sm" shape="square" icon={<ArrowsClockwiseIcon />} aria-label="Refresh" onClick={() => zones.refetch()} />
          </div>
        </div>
        <VirtualTable
          ariaLabel="Domains"
          rows={rows}
          columns={columns}
          rowKey={(z) => z.id}
          loading={zones.isLoading}
          onRowClick={(z) => navigate(`/${orgId}/${stripDot(z.name)}`)}
          empty={empty}
          maxHeight="calc(100vh - 420px)"
        />
      </LayerCard>

      {overview.data?.activity && (
        <div className="mt-6">
          <LayerCard className="px-5 py-4">
            <div className="mb-2 grid gap-0.5">
              <Text variant="heading" as="h2">
                Change activity
              </Text>
              <Text variant="secondary">Configuration changes across this organization over the last 30 days.</Text>
            </div>
            <ActivityChart data={overview.data.activity} />
          </LayerCard>
        </div>
      )}
    </div>
  );
}
