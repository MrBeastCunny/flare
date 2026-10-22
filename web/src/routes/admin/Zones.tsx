import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { InputGroup, LayerCard, Text } from "@cloudflare/kumo";
import { MagnifyingGlassIcon } from "@phosphor-icons/react";
import { PageHeader, ZoneStatusBadge } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { api } from "../../lib/api";
import { keys } from "../../lib/queries";
import { stripDot, timeAgo } from "../../lib/format";
import type { Zone } from "../../lib/types";

export default function Zones() {
  const navigate = useNavigate();
  const zones = useQuery({ queryKey: keys.admin("zones"), queryFn: () => api<Zone[]>("/admin/zones") });
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("all");
  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (zones.data ?? []).filter((z) => (status === "all" || z.status === status) && (!query || z.name.includes(query) || (z.org_name ?? "").toLowerCase().includes(query)));
  }, [zones.data, q, status]);

  const columns: Column<Zone>[] = [
    { key: "name", header: "Zone", width: "30%", render: (z) => <span className="truncate font-medium">{stripDot(z.name)}</span> },
    { key: "org", header: "Organization", width: "22%", render: (z) => <span className="truncate text-kumo-subtle">{z.org_name}</span> },
    { key: "status", header: "Status", width: "20%", render: (z) => <ZoneStatusBadge status={z.status} /> },
    { key: "server", header: "Server", width: "14%", render: (z) => <span className="text-kumo-subtle">{z.pdns_server_name}</span> },
    { key: "created", header: "Added", width: "14%", render: (z) => <span className="text-kumo-subtle">{timeAgo(z.created_at)}</span> },
  ];

  return (
    <div>
      <PageHeader title="All zones" description="Every zone across all organizations." />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-kumo-line px-4 py-3">
          <InputGroup className="w-full max-w-sm">
            <InputGroup.Addon>
              <MagnifyingGlassIcon />
            </InputGroup.Addon>
            <InputGroup.Input placeholder="Search zone or organization" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search zones" />
          </InputGroup>
          <VirtualSelect
            aria-label="Status"
            className="w-48"
            options={[
              { value: "all", label: "All statuses" },
              { value: "active", label: "Active" },
              { value: "pending", label: "Pending" },
              { value: "moved", label: "Moved" },
            ]}
            value={status}
            onChange={setStatus}
          />
          <span className="ml-auto">
            <Text variant="secondary">{rows.length} zones</Text>
          </span>
        </div>
        <VirtualTable ariaLabel="All zones" rows={rows} columns={columns} rowKey={(z) => z.id} loading={zones.isLoading} onRowClick={(z) => navigate(`/${z.org_id}/${stripDot(z.name)}`)} />
      </LayerCard>
    </div>
  );
}
