import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Dialog, Input, InputGroup, LayerCard, Switch } from "@cloudflare/kumo";
import { MagnifyingGlassIcon, PlusIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys } from "../../lib/queries";
import { formatDate, formatNumber } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { AdminOrg, NameserverSet, PdnsServer } from "../../lib/types";

export default function Orgs() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const orgs = useQuery({ queryKey: keys.admin("orgs"), queryFn: () => api<AdminOrg[]>("/admin/orgs") });
  const servers = useQuery({ queryKey: keys.admin("servers"), queryFn: () => api<PdnsServer[]>("/admin/servers") });
  const nsSets = useQuery({ queryKey: keys.admin("nameserver-sets"), queryFn: () => api<NameserverSet[]>("/admin/nameserver-sets") });
  const [q, setQ] = useState("");
  const [editing, setEditing] = useState<AdminOrg | null>(null);
  const [limits, setLimits] = useState({ max_zones: "", nameserver_set_id: "", pdns_server_id: "", suspended: false });
  const [creating, setCreating] = useState(false);
  const [newOrg, setNewOrg] = useState({ name: "", owner_email: "" });

  const refresh = () => qc.invalidateQueries({ queryKey: keys.admin("orgs") });
  const save = useMutation({
    mutationFn: () =>
      api(`/admin/orgs/${editing!.id}`, {
        method: "PATCH",
        body: {
          max_zones: limits.max_zones === "" ? null : Number(limits.max_zones),
          nameserver_set_id: limits.nameserver_set_id || null,
          pdns_server_id: limits.pdns_server_id || null,
          suspended: limits.suspended,
        },
      }),
    onSuccess: () => {
      void refresh();
      setEditing(null);
      toast.success("Organization updated");
    },
  });
  const create = useMutation({
    mutationFn: () => api("/admin/orgs", { method: "POST", body: newOrg }),
    onSuccess: () => {
      void refresh();
      void qc.invalidateQueries({ queryKey: ["me"] });
      setCreating(false);
      setNewOrg({ name: "", owner_email: "" });
      toast.success("Organization created");
    },
  });

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (orgs.data ?? []).filter((o) => !query || o.name.toLowerCase().includes(query) || o.slug.includes(query));
  }, [orgs.data, q]);

  const open = (o: AdminOrg) => {
    setEditing(o);
    setLimits({ max_zones: o.max_zones === null ? "" : String(o.max_zones), nameserver_set_id: o.nameserver_set_id ?? "", pdns_server_id: o.pdns_server_id ?? "", suspended: o.suspended });
  };

  const columns: Column<AdminOrg>[] = [
    {
      key: "name",
      header: "Organization",
      width: "32%",
      render: (o) => (
        <span className="flex items-center gap-2 truncate font-medium">
          {o.name} {o.suspended && <Badge variant="error">Suspended</Badge>}
        </span>
      ),
    },
    { key: "members", header: "Members", width: "12%", render: (o) => formatNumber(o.member_count) },
    { key: "zones", header: "Zones", width: "16%", render: (o) => `${formatNumber(o.zone_count)}${o.max_zones !== null ? ` / ${formatNumber(o.max_zones)}` : ""}` },
    { key: "policy", header: "Policy", width: "20%", render: (o) => <span className="text-kumo-subtle">{[o.enforce_mfa && "2FA required", o.ip_allowlist.length > 0 && "IP rules"].filter(Boolean).join(", ") || "Default"}</span> },
    { key: "created", header: "Created", width: "14%", render: (o) => <span className="text-kumo-subtle">{formatDate(o.created_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "6%",
      align: "right",
      render: (o) => (
        <ActionMenu
          items={[
            { key: "open", label: "Open dashboard", onSelect: () => navigate(`/${o.id}`) },
            { key: "limits", label: "Limits and placement", onSelect: () => open(o) },
          ]}
        />
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Organizations"
        description="Tenants on this instance, their quotas and server placement."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => setCreating(true)}>
            Create organization
          </Button>
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="flex items-center gap-3 border-b border-kumo-line px-4 py-3">
          <InputGroup className="w-full max-w-sm">
            <InputGroup.Addon>
              <MagnifyingGlassIcon />
            </InputGroup.Addon>
            <InputGroup.Input placeholder="Search organizations" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search organizations" />
          </InputGroup>
        </div>
        <VirtualTable ariaLabel="Organizations" rows={rows} columns={columns} rowKey={(o) => o.id} loading={orgs.isLoading} onRowClick={open} />
      </LayerCard>

      <Dialog.Root open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{editing?.name}</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <div className="grid gap-4">
            <Input
              label="Zone limit"
              type="number"
              placeholder="Instance default"
              description="Leave blank to use the instance default. Zero means unlimited."
              value={limits.max_zones}
              onChange={(e) => setLimits({ ...limits, max_zones: e.target.value })}
            />
            <VirtualSelect
              label="DNS server for new zones"
              options={[{ value: "", label: "Instance default" }, ...(servers.data ?? []).map((s) => ({ value: s.id, label: s.name, description: s.api_url }))]}
              value={limits.pdns_server_id}
              onChange={(v) => setLimits({ ...limits, pdns_server_id: v })}
            />
            <VirtualSelect
              label="Nameserver set"
              options={[{ value: "", label: "Instance default" }, ...(nsSets.data ?? []).map((s) => ({ value: s.id, label: s.name }))]}
              value={limits.nameserver_set_id}
              onChange={(v) => setLimits({ ...limits, nameserver_set_id: v })}
            />
            <Switch label="Suspend organization (members lose access; DNS keeps resolving)" checked={limits.suspended} onCheckedChange={(v: boolean) => setLimits({ ...limits, suspended: v })} />
            {save.error && <Banner variant="error" size="sm" description={errorMessage(save.error)} />}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
                Save
              </Button>
            </div>
          </div>
        </Dialog>
      </Dialog.Root>

      <Dialog.Root open={creating} onOpenChange={setCreating}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Create organization</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <Input label="Name" value={newOrg.name} onChange={(e) => setNewOrg({ ...newOrg, name: e.target.value })} error={fieldError(create.error, "name")} autoFocus />
            <Input
              label="Owner email"
              required={false}
              description="An existing user who will own the organization. Leave blank to own it yourself."
              value={newOrg.owner_email}
              onChange={(e) => setNewOrg({ ...newOrg, owner_email: e.target.value })}
              error={fieldError(create.error, "owner_email")}
            />
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button type="submit" variant="primary" loading={create.isPending} disabled={!newOrg.name.trim()}>
                Create
              </Button>
            </div>
          </form>
        </Dialog>
      </Dialog.Root>
    </div>
  );
}
