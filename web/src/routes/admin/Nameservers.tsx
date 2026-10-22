import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Dialog, Input, LayerCard, Switch, TagInput } from "@cloudflare/kumo";
import { PlusIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader, ConfirmDialog, Mono } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys } from "../../lib/queries";
import { stripDot, formatNumber } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { NameserverSet } from "../../lib/types";

export default function Nameservers() {
  const qc = useQueryClient();
  const sets = useQuery({ queryKey: keys.admin("nameserver-sets"), queryFn: () => api<NameserverSet[]>("/admin/nameserver-sets") });
  const [editing, setEditing] = useState<NameserverSet | "new" | null>(null);
  const [form, setForm] = useState({ name: "", nameservers: [] as string[], hostmaster: "", is_default: false });
  const [deleting, setDeleting] = useState<NameserverSet | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: keys.admin("nameserver-sets") });

  const save = useMutation({
    mutationFn: () =>
      api<{ zones_updated: number; zones_failed: string[] }>(editing === "new" ? "/admin/nameserver-sets" : `/admin/nameserver-sets/${(editing as NameserverSet).id}`, {
        method: editing === "new" ? "POST" : "PUT",
        body: form,
      }),
    onSuccess: (res) => {
      void refresh();
      void qc.invalidateQueries({ queryKey: ["org"] });
      setEditing(null);
      const failed = res.zones_failed ?? [];
      if (failed.length > 0) toast.error(`${failed.length} zones could not be updated`, failed.slice(0, 3).join("; "));
      toast.success(
        "Nameserver set saved",
        res.zones_updated > 0 ? `NS and SOA records updated in ${formatNumber(res.zones_updated)} ${res.zones_updated === 1 ? "zone" : "zones"}.` : undefined,
      );
    },
  });
  const current = editing && editing !== "new" ? editing : null;
  const willPropagate =
    !!current &&
    current.zone_count > 0 &&
    (current.nameservers.join(",") !== form.nameservers.join(",") || (current.hostmaster ?? "") !== form.hostmaster.trim());
  const remove = useMutation({
    mutationFn: (s: NameserverSet) => api(`/admin/nameserver-sets/${s.id}`, { method: "DELETE" }),
    onSuccess: () => {
      void refresh();
      setDeleting(null);
    },
    onError: (e) => toast.error(e),
  });

  const open = (s: NameserverSet | "new") => {
    setEditing(s);
    setForm(s === "new" ? { name: "", nameservers: [], hostmaster: "", is_default: false } : { name: s.name, nameservers: s.nameservers.map(stripDot), hostmaster: s.hostmaster, is_default: s.is_default });
  };

  const columns: Column<NameserverSet>[] = [
    {
      key: "name",
      header: "Name",
      width: "22%",
      render: (s) => (
        <span className="flex items-center gap-2 font-medium">
          {s.name} {s.is_default && <Badge variant="primary">Default</Badge>}
        </span>
      ),
    },
    { key: "ns", header: "Nameservers", render: (s) => <Mono className="text-kumo-subtle">{s.nameservers.map(stripDot).join(", ")}</Mono> },
    { key: "hostmaster", header: "Hostmaster", width: "22%", render: (s) => <span className="truncate text-kumo-subtle">{s.hostmaster || "Not set"}</span> },
    { key: "zones", header: "Zones", width: "90px", render: (s) => formatNumber(s.zone_count) },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "60px",
      align: "right",
      render: (s) => (
        <ActionMenu
          items={[
            { key: "edit", label: "Edit", onSelect: () => open(s) },
            { key: "delete", label: "Delete", danger: true, disabled: s.is_default, onSelect: () => setDeleting(s) },
          ]}
        />
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Nameservers"
        description="Preset nameserver sets. When someone adds a domain, they are told to delegate it to the default set (or the set assigned to their organization)."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => open("new")}>
            Add nameserver set
          </Button>
        }
      />
      <Banner
        variant="secondary"
        size="sm"
        description="Zones follow their set: editing a set's nameservers or hostmaster updates the NS and SOA records of every zone that uses it. Use Zone settings to move a single zone to another set."
      />
      <LayerCard className="mt-4 overflow-hidden">
        <VirtualTable ariaLabel="Nameserver sets" rows={sets.data ?? []} columns={columns} rowKey={(s) => s.id} loading={sets.isLoading} onRowClick={open} />
      </LayerCard>

      <Dialog.Root open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{editing === "new" ? "Add nameserver set" : "Edit nameserver set"}</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate();
            }}
          >
            <Input label="Name" placeholder="Anycast EU" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} error={fieldError(save.error, "name")} autoFocus />
            <TagInput
              label="Nameservers"
              description="At least two hostnames. The first is used as the SOA primary."
              placeholder="ns1.example.net"
              value={form.nameservers}
              onValueChange={(v: string[]) => setForm({ ...form, nameservers: v })}
              error={fieldError(save.error, "nameservers")}
            />
            <Input
              label="Hostmaster email"
              required={false}
              placeholder="hostmaster@example.net"
              value={form.hostmaster}
              onChange={(e) => setForm({ ...form, hostmaster: e.target.value })}
              error={fieldError(save.error, "hostmaster")}
            />
            {willPropagate && (
              <Banner
                variant="alert"
                size="sm"
                title={`Updates ${formatNumber(current!.zone_count)} ${current!.zone_count === 1 ? "zone" : "zones"}`}
                description="The NS and SOA records of every zone using this set change when you save. Domain owners whose registrar still points at removed nameservers must update their delegation."
              />
            )}
            <Switch label="Default for new zones" checked={form.is_default} onCheckedChange={(v: boolean) => setForm({ ...form, is_default: v })} />
            {save.error && Object.keys((save.error as { fields?: object }).fields ?? {}).length === 0 && <Banner variant="error" size="sm" description={errorMessage(save.error)} />}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button type="submit" variant="primary" loading={save.isPending}>
                {willPropagate ? "Save and update zones" : "Save"}
              </Button>
            </div>
          </form>
        </Dialog>
      </Dialog.Root>
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete nameserver set"
        description="Zones using this set keep their NS records but will no longer reference a set."
        confirmLabel="Delete"
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting)}
      />
    </div>
  );
}
