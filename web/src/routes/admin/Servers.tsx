import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Dialog, Input, LayerCard, SensitiveInput, Switch, Tabs, Text, ClipboardText, InputGroup } from "@cloudflare/kumo";
import { MagnifyingGlassIcon, PlusIcon, XIcon, HardDrivesIcon, CheckCircleIcon, WarningCircleIcon } from "@phosphor-icons/react";
import { PageHeader, ConfirmDialog, Mono, KeyValueGrid } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys } from "../../lib/queries";
import { formatDuration, formatNumber, timeAgo, stripDot } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { AdminOrg, NameserverSet, PdnsServer, TSIGKey } from "../../lib/types";

interface ServerStatus {
  reachable: boolean;
  error?: string;
  info?: { version: string; daemon_type: string };
  statistics?: Record<string, number | string>;
  pdns_zone_count?: number;
}

const empty = { name: "", api_url: "", api_key: "", server_id: "localhost", description: "", is_default: false, enabled: true };

export default function Servers() {
  const qc = useQueryClient();
  const servers = useQuery({ queryKey: keys.admin("servers"), queryFn: () => api<PdnsServer[]>("/admin/servers") });
  const [editing, setEditing] = useState<PdnsServer | "new" | null>(null);
  const [form, setForm] = useState(empty);
  const [test, setTest] = useState<{ ok: boolean; version?: string; error?: string } | null>(null);
  const [detail, setDetail] = useState<PdnsServer | null>(null);
  const [deleting, setDeleting] = useState<PdnsServer | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: keys.admin("servers") });

  const save = useMutation({
    mutationFn: () => (editing === "new" ? api("/admin/servers", { method: "POST", body: form }) : api(`/admin/servers/${(editing as PdnsServer).id}`, { method: "PUT", body: form })),
    onSuccess: () => {
      void refresh();
      setEditing(null);
      toast.success("Server saved");
    },
  });
  const testConn = useMutation({
    mutationFn: () =>
      api<{ ok: boolean; version?: string; error?: string }>("/admin/servers/test", {
        method: "POST",
        body: form,
        query: editing && editing !== "new" ? { id: editing.id } : undefined,
      }),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, error: errorMessage(e) }),
  });
  const remove = useMutation({
    mutationFn: (s: PdnsServer) => api(`/admin/servers/${s.id}`, { method: "DELETE" }),
    onSuccess: () => {
      void refresh();
      setDeleting(null);
      toast.success("Server removed");
    },
    onError: (e) => toast.error(e),
  });

  const open = (s: PdnsServer | "new") => {
    setEditing(s);
    setTest(null);
    setForm(s === "new" ? empty : { name: s.name, api_url: s.api_url, api_key: "", server_id: s.server_id, description: s.description, is_default: s.is_default, enabled: s.enabled });
  };

  const columns: Column<PdnsServer>[] = [
    {
      key: "name",
      header: "Server",
      width: "28%",
      render: (s) => (
        <div className="grid min-w-0">
          <span className="flex items-center gap-2 truncate font-medium text-kumo-strong">
            {s.name} {s.is_default && <Badge variant="primary">Default</Badge>}
          </span>
          <Mono className="truncate text-kumo-subtle">{s.api_url}</Mono>
        </div>
      ),
    },
    {
      key: "status",
      header: "Health",
      width: "16%",
      render: (s) =>
        !s.enabled ? (
          <Badge variant="neutral">Disabled</Badge>
        ) : (
          <Badge variant={s.last_status === "healthy" ? "success" : s.last_status === "unreachable" ? "error" : "neutral"} appearance="dot">
            {s.last_status === "healthy" ? "Healthy" : s.last_status === "unreachable" ? "Unreachable" : "Unknown"}
          </Badge>
        ),
    },
    { key: "version", header: "Version", width: "14%", render: (s) => <span className="text-kumo-subtle">{s.version || "Unknown"}</span> },
    { key: "zones", header: "Zones", width: "10%", render: (s) => <span className="tabular-nums">{formatNumber(s.zone_count)}</span> },
    { key: "checked", header: "Checked", width: "14%", render: (s) => <span className="text-kumo-subtle">{timeAgo(s.last_checked_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "8%",
      align: "right",
      render: (s) => (
        <ActionMenu
          items={[
            { key: "details", label: "Details and statistics", onSelect: () => setDetail(s) },
            { key: "edit", label: "Edit", onSelect: () => open(s) },
            { key: "delete", label: "Remove", danger: true, separatorBefore: true, disabled: s.zone_count > 0, onSelect: () => setDeleting(s) },
          ]}
        />
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="DNS servers"
        description="PowerDNS Authoritative servers that host zones. New zones are created on the default server unless an organization is pinned to another."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => open("new")}>
            Add server
          </Button>
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <VirtualTable ariaLabel="DNS servers" rows={servers.data ?? []} columns={columns} rowKey={(s) => s.id} loading={servers.isLoading} rowHeight={60} onRowClick={setDetail} />
      </LayerCard>

      <Dialog.Root open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{editing === "new" ? "Add DNS server" : "Edit DNS server"}</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate();
            }}
          >
            <Input label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} error={fieldError(save.error, "name")} autoFocus />
            <Input label="API URL" placeholder="http://pdns:8081" value={form.api_url} onChange={(e) => setForm({ ...form, api_url: e.target.value })} error={fieldError(save.error, "api_url")} />
            <SensitiveInput
              label="API key"
              placeholder={editing !== "new" ? "Leave blank to keep the current key" : ""}
              value={form.api_key}
              onValueChange={(v: string) => setForm({ ...form, api_key: v })}
              error={fieldError(save.error, "api_key")}
            />
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="Server ID" value={form.server_id} onChange={(e) => setForm({ ...form, server_id: e.target.value })} />
              <Input label="Description" required={false} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <Switch label="Default server for new zones" checked={form.is_default} onCheckedChange={(v: boolean) => setForm({ ...form, is_default: v })} />
            {editing !== "new" && <Switch label="Enabled" checked={form.enabled} onCheckedChange={(v: boolean) => setForm({ ...form, enabled: v })} />}
            <div className="flex items-center gap-3">
              <Button type="button" icon={<HardDrivesIcon />} loading={testConn.isPending} onClick={() => testConn.mutate()}>
                Test connection
              </Button>
              {test?.ok && (
                <span className="flex items-center gap-1.5 text-kumo-success">
                  <CheckCircleIcon weight="fill" /> PowerDNS {test.version}
                </span>
              )}
              {test && !test.ok && (
                <span className="flex min-w-0 items-center gap-1.5 text-kumo-danger">
                  <WarningCircleIcon weight="fill" className="shrink-0" /> <span className="truncate">{test.error}</span>
                </span>
              )}
            </div>
            {save.error && Object.keys((save.error as { fields?: object }).fields ?? {}).length === 0 && <Banner variant="error" size="sm" description={errorMessage(save.error)} />}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button type="submit" variant="primary" loading={save.isPending}>
                Save server
              </Button>
            </div>
          </form>
        </Dialog>
      </Dialog.Root>

      <ServerDetail server={detail} onClose={() => setDetail(null)} />

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Remove DNS server"
        description="The server will no longer be used. Zones on the server itself are not affected."
        confirmLabel="Remove server"
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting)}
      />
    </div>
  );
}

function ServerDetail({ server, onClose }: { server: PdnsServer | null; onClose: () => void }) {
  const qc = useQueryClient();
  const id = server?.id ?? "";
  const status = useQuery({ queryKey: ["admin", "server-status", id], queryFn: () => api<ServerStatus>(`/admin/servers/${id}/status`), enabled: !!server });
  const unmanaged = useQuery({
    queryKey: ["admin", "unmanaged", id],
    queryFn: () => api<{ name: string; kind: string; serial: number; account: string }[]>(`/admin/servers/${id}/unmanaged-zones`),
    enabled: !!server,
  });
  const tsig = useQuery({ queryKey: ["admin", "tsig", id], queryFn: () => api<TSIGKey[]>(`/admin/servers/${id}/tsig-keys`), enabled: !!server });
  const orgs = useQuery({ queryKey: keys.admin("orgs"), queryFn: () => api<AdminOrg[]>("/admin/orgs"), enabled: !!server });
  const nsSets = useQuery({ queryKey: keys.admin("nameserver-sets"), queryFn: () => api<NameserverSet[]>("/admin/nameserver-sets"), enabled: !!server });
  const [adoptSel, setAdoptSel] = useState<string[]>([]);
  const [adoptOrg, setAdoptOrg] = useState("");
  const [adoptNs, setAdoptNs] = useState("");
  const [tsigName, setTsigName] = useState("");
  const [tsigAlg, setTsigAlg] = useState("hmac-sha256");
  const [revealed, setRevealed] = useState<TSIGKey | null>(null);
  const [tab, setTab] = useState("overview");

  const adopt = useMutation({
    mutationFn: () => api<{ adopted: number; failures: string[] }>(`/admin/servers/${id}/adopt`, { method: "POST", body: { org_id: adoptOrg, zones: adoptSel, nameserver_set_id: adoptNs || null, mark_active: true } }),
    onSuccess: (d) => {
      setAdoptSel([]);
      void unmanaged.refetch();
      void qc.invalidateQueries({ queryKey: keys.admin("servers") });
      toast.success(`${d.adopted} zones imported`, d.failures.length ? d.failures.join("; ") : undefined);
    },
    onError: (e) => toast.error(e),
  });
  const createTsig = useMutation({
    mutationFn: () => api<TSIGKey>(`/admin/servers/${id}/tsig-keys`, { method: "POST", body: { name: tsigName, algorithm: tsigAlg } }),
    onSuccess: (k) => {
      setTsigName("");
      void tsig.refetch();
      setRevealed(k);
    },
    onError: (e) => toast.error(e),
  });
  const tsigAction = useMutation({
    mutationFn: ({ k, a }: { k: TSIGKey; a: "reveal" | "delete" }) =>
      a === "reveal" ? api<TSIGKey>(`/admin/servers/${id}/tsig-keys/${encodeURIComponent(k.id)}`) : api(`/admin/servers/${id}/tsig-keys/${encodeURIComponent(k.id)}`, { method: "DELETE" }),
    onSuccess: (d, v) => {
      if (v.a === "reveal") setRevealed(d as TSIGKey);
      else void tsig.refetch();
    },
    onError: (e) => toast.error(e),
  });

  const st = status.data?.statistics ?? {};
  const num = (k: string) => Number(st[k] ?? 0);
  const hitRate = num("packetcache-hit") + num("packetcache-miss") > 0 ? Math.round((num("packetcache-hit") / (num("packetcache-hit") + num("packetcache-miss"))) * 100) : 0;

  return (
    <Dialog.Root open={!!server} onOpenChange={(o) => !o && onClose()}>
      <Dialog size="xl" className="max-h-[90vh] overflow-y-auto p-6">
        <div className="mb-4 flex items-start justify-between">
          <div className="grid gap-0.5">
            <Dialog.Title className="text-lg font-semibold">{server?.name}</Dialog.Title>
            <Text variant="secondary">{server?.api_url}</Text>
          </div>
          <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
        </div>
        <Tabs
          variant="underline"
          className="mb-5"
          value={tab}
          onValueChange={setTab}
          tabs={[
            { value: "overview", label: "Overview" },
            { value: "zones", label: "Unmanaged zones" },
            { value: "tsig", label: "TSIG keys" },
            { value: "config", label: "Configuration" },
          ]}
        />
        {tab === "overview" && (
          <>
        {status.data && !status.data.reachable && <Banner variant="error" description={status.data.error} />}
        {status.data?.reachable && (
          <div className="mb-6">
            <KeyValueGrid
              items={[
                { label: "Version", value: status.data.info?.version },
                { label: "Uptime", value: formatDuration(num("uptime")) },
                { label: "Zones on server", value: formatNumber(status.data.pdns_zone_count) },
                { label: "UDP queries", value: formatNumber(num("udp-queries")) },
                { label: "TCP queries", value: formatNumber(num("tcp-queries")) },
                { label: "Packet cache hit rate", value: `${hitRate}%` },
                { label: "Average latency", value: `${formatNumber(num("latency"))} us` },
                { label: "SERVFAIL responses", value: formatNumber(num("servfail-packets")) },
                { label: "Security status", value: num("security-status") === 1 ? "OK" : num("security-status") === 0 ? "Unknown" : "Upgrade advised" },
              ]}
            />
          </div>
        )}

          </>
        )}
        {tab === "zones" && (
        <div className="grid gap-3">
          <div className="grid gap-0.5">
            <Text variant="heading" as="h3">
              Unmanaged zones
            </Text>
            <Text variant="secondary">Zones that exist on this server but are not assigned to an organization. Import them to manage them here.</Text>
          </div>
          <LayerCard className="overflow-hidden bg-kumo-base p-0">
            <VirtualTable
              ariaLabel="Unmanaged zones"
              rows={unmanaged.data ?? []}
              rowKey={(z) => z.name}
              loading={unmanaged.isLoading}
              maxHeight="260px"
              selection={{ selected: new Set(adoptSel), onChange: (s) => setAdoptSel([...s]) }}
              columns={[
                { key: "name", header: "Zone", render: (z) => <Mono>{stripDot(z.name)}</Mono> },
                { key: "kind", header: "Type", width: "120px", render: (z) => z.kind },
                { key: "serial", header: "Serial", width: "140px", render: (z) => <Mono className="text-kumo-subtle">{z.serial}</Mono> },
              ]}
              empty={<div className="px-5 py-6 text-center text-kumo-subtle">Every zone on this server is managed.</div>}
            />
          </LayerCard>
          {(unmanaged.data?.length ?? 0) > 0 && (
            <div className="grid items-end gap-3 md:grid-cols-[1fr_1fr_auto]">
              <VirtualSelect label="Assign to organization" options={(orgs.data ?? []).map((o) => ({ value: o.id, label: o.name }))} value={adoptOrg} onChange={setAdoptOrg} placeholder="Choose organization" />
              <VirtualSelect
                label="Nameserver set"
                options={[{ value: "", label: "Keep existing NS records" }, ...(nsSets.data ?? []).map((s) => ({ value: s.id, label: s.name }))]}
                value={adoptNs}
                onChange={setAdoptNs}
              />
              <Button variant="primary" loading={adopt.isPending} disabled={!adoptOrg || adoptSel.length === 0} onClick={() => adopt.mutate()}>
                Import {adoptSel.length || ""}
              </Button>
            </div>
          )}
        </div>
        )}
        {tab === "tsig" && (
        <div className="grid gap-3">
          <div className="grid gap-0.5">
            <Text variant="heading" as="h3">
              TSIG keys
            </Text>
            <Text variant="secondary">Shared secrets that authenticate zone transfers and NOTIFY between servers.</Text>
          </div>
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              createTsig.mutate();
            }}
          >
            <Input label="Key name" placeholder="transfer-key" value={tsigName} onChange={(e) => setTsigName(e.target.value)} className="w-56" />
            <VirtualSelect
              label="Algorithm"
              className="w-48"
              options={["hmac-sha256", "hmac-sha512", "hmac-sha384", "hmac-sha224", "hmac-sha1", "hmac-md5"].map((a) => ({ value: a, label: a }))}
              value={tsigAlg}
              onChange={setTsigAlg}
            />
            <Button type="submit" icon={<PlusIcon />} loading={createTsig.isPending} disabled={!tsigName.trim()}>
              Generate key
            </Button>
          </form>
          <LayerCard className="overflow-hidden bg-kumo-base p-0">
            <VirtualTable
              ariaLabel="TSIG keys"
              rows={tsig.data ?? []}
              rowKey={(k) => k.id}
              loading={tsig.isLoading}
              maxHeight="240px"
              columns={[
                { key: "name", header: "Name", render: (k) => <Mono>{stripDot(k.name)}</Mono> },
                { key: "alg", header: "Algorithm", width: "160px", render: (k) => k.algorithm },
                {
                  key: "actions",
                  header: <span className="sr-only">Actions</span>,
                  width: "70px",
                  align: "right",
                  render: (k) => (
                    <ActionMenu
                      items={[
                        { key: "reveal", label: "Reveal secret", onSelect: () => tsigAction.mutate({ k, a: "reveal" }) },
                        { key: "delete", label: "Delete", danger: true, onSelect: () => tsigAction.mutate({ k, a: "delete" }) },
                      ]}
                    />
                  ),
                },
              ]}
              empty={<div className="px-5 py-6 text-center text-kumo-subtle">No TSIG keys.</div>}
            />
          </LayerCard>
          {revealed?.key && (
            <div className="grid gap-1.5">
              <Text bold>Secret for {stripDot(revealed.name)}</Text>
              <ClipboardText text={revealed.key} size="sm" />
            </div>
          )}
        </div>
        )}
        {tab === "config" && server && <ServerConfig id={server.id} />}
      </Dialog>
    </Dialog.Root>
  );
}

function ServerConfig({ id }: { id: string }) {
  const [q, setQ] = useState("");
  const config = useQuery({
    queryKey: ["admin", "servers", id, "config"],
    queryFn: () => api<{ name: string; value: string }[]>(`/admin/servers/${id}/config`),
  });
  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (config.data ?? []).filter((c) => !query || c.name.includes(query) || c.value.toLowerCase().includes(query));
  }, [config.data, q]);
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Text variant="secondary">Runtime settings reported by the server. Secrets are hidden.</Text>
        <InputGroup className="w-full max-w-xs">
          <InputGroup.Addon>
            <MagnifyingGlassIcon />
          </InputGroup.Addon>
          <InputGroup.Input placeholder="Filter settings" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter settings" />
        </InputGroup>
      </div>
      {config.error && <Banner variant="error" size="sm" description={errorMessage(config.error)} />}
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <VirtualTable
          ariaLabel="Server configuration"
          rows={rows}
          rowKey={(c) => c.name}
          loading={config.isLoading}
          maxHeight="420px"
          minWidth={560}
          columns={[
            { key: "name", header: "Setting", width: "40%", render: (c) => <Mono>{c.name}</Mono> },
            { key: "value", header: "Value", render: (c) => (c.value ? <Mono className="text-kumo-subtle">{c.value}</Mono> : <span className="text-kumo-inactive">Empty</span>) },
          ]}
        />
      </LayerCard>
    </div>
  );
}
