import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Code, Dialog, Input, LayerCard, Switch, Text } from "@cloudflare/kumo";
import { PlusIcon, WebhooksLogoIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader, SecretDialog, ConfirmDialog, Mono } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useOrgId } from "../../lib/queries";
import { formatDateTime, timeAgo } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { Webhook, WebhookDelivery } from "../../lib/types";

export default function Webhooks() {
  const orgId = useOrgId();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: keys.webhooks(orgId), queryFn: () => api<{ webhooks: Webhook[]; events: string[] }>(`/orgs/${orgId}/webhooks`) });
  const [editing, setEditing] = useState<Webhook | "new" | null>(null);
  const [form, setForm] = useState({ name: "", url: "", events: ["*"], enabled: true });
  const [secret, setSecret] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Webhook | null>(null);
  const [viewing, setViewing] = useState<Webhook | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: keys.webhooks(orgId) });

  const deliveries = useQuery({
    queryKey: ["webhook-deliveries", viewing?.id],
    queryFn: () => api<WebhookDelivery[]>(`/orgs/${orgId}/webhooks/${viewing!.id}/deliveries`),
    enabled: !!viewing,
    refetchInterval: viewing ? 5000 : false,
  });

  const save = useMutation({
    mutationFn: (): Promise<{ secret?: string }> =>
      editing === "new"
        ? api<{ webhook: Webhook; secret: string }>(`/orgs/${orgId}/webhooks`, { method: "POST", body: form })
        : api<Webhook>(`/orgs/${orgId}/webhooks/${(editing as Webhook).id}`, { method: "PUT", body: form }).then(() => ({})),
    onSuccess: (d) => {
      void refresh();
      if (d.secret) setSecret(d.secret);
      else toast.success("Webhook updated");
      setEditing(null);
    },
  });
  const action = useMutation({
    mutationFn: ({ w, a }: { w: Webhook; a: "test" | "rotate" | "delete" }) =>
      a === "test"
        ? api(`/orgs/${orgId}/webhooks/${w.id}/test`, { method: "POST" })
        : a === "rotate"
          ? api<{ secret: string }>(`/orgs/${orgId}/webhooks/${w.id}/rotate-secret`, { method: "POST" })
          : api(`/orgs/${orgId}/webhooks/${w.id}`, { method: "DELETE" }),
    onSuccess: (d, v) => {
      void refresh();
      if (v.a === "test") toast.success("Test event queued", "It will be delivered within a few seconds.");
      if (v.a === "rotate") setSecret((d as { secret: string }).secret);
      if (v.a === "delete") {
        setDeleting(null);
        toast.success("Webhook deleted");
      }
    },
    onError: (e) => toast.error(e),
  });

  const openEditor = (w: Webhook | "new") => {
    setEditing(w);
    setForm(w === "new" ? { name: "", url: "", events: ["*"], enabled: true } : { name: w.name, url: w.url, events: w.events, enabled: w.enabled });
  };

  const statusBadge = (s: string | null) =>
    s === "delivered" ? <Badge variant="success">Delivered</Badge> : s === "failed" ? <Badge variant="error">Failed</Badge> : s === "pending" ? <Badge variant="warning">Retrying</Badge> : <span className="text-kumo-subtle">None yet</span>;

  const columns: Column<Webhook>[] = [
    {
      key: "name",
      header: "Webhook",
      width: "36%",
      render: (w) => (
        <div className="grid min-w-0">
          <span className="truncate font-medium text-kumo-strong">{w.name}</span>
          <Mono className="truncate text-kumo-subtle">{w.url}</Mono>
        </div>
      ),
    },
    { key: "events", header: "Events", width: "22%", render: (w) => <span className="truncate text-kumo-subtle">{w.events.join(", ")}</span> },
    { key: "enabled", header: "Status", width: "12%", render: (w) => <Badge variant={w.enabled ? "success" : "neutral"}>{w.enabled ? "Enabled" : "Paused"}</Badge> },
    { key: "last", header: "Last delivery", width: "20%", render: (w) => <div className="flex items-center gap-2">{statusBadge(w.last_delivery_status)} <span className="text-xs text-kumo-subtle">{w.last_delivery_at ? timeAgo(w.last_delivery_at) : ""}</span></div> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "10%",
      align: "right",
      render: (w) => (
        <ActionMenu
          items={[
            { key: "deliveries", label: "View deliveries", onSelect: () => setViewing(w) },
            { key: "edit", label: "Edit", onSelect: () => openEditor(w) },
            { key: "test", label: "Send test event", onSelect: () => action.mutate({ w, a: "test" }) },
            { key: "rotate", label: "Rotate signing secret", onSelect: () => action.mutate({ w, a: "rotate" }) },
            { key: "delete", label: "Delete", danger: true, separatorBefore: true, onSelect: () => setDeleting(w) },
          ]}
        />
      ),
    },
  ];

  const deliveryCols: Column<WebhookDelivery>[] = [
    { key: "time", header: "Time", width: "22%", render: (d) => <span className="text-kumo-subtle">{formatDateTime(d.created_at)}</span> },
    { key: "event", header: "Event", width: "26%", render: (d) => <Mono>{d.event}</Mono> },
    { key: "status", header: "Status", width: "16%", render: (d) => statusBadge(d.status) },
    { key: "code", header: "Response", width: "14%", render: (d) => <Mono className="text-kumo-subtle">{d.response_status ?? "None"}</Mono> },
    { key: "attempts", header: "Attempts", width: "12%", render: (d) => <span className="text-kumo-subtle">{d.attempts}</span> },
  ];

  return (
    <div>
      <PageHeader
        title="Webhooks"
        description="Send signed HTTP notifications to your systems when DNS records, zones or members change."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => openEditor("new")}>
            Create webhook
          </Button>
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <VirtualTable
          ariaLabel="Webhooks"
          rows={list.data?.webhooks ?? []}
          columns={columns}
          rowKey={(w) => w.id}
          loading={list.isLoading}
          rowHeight={60}
          onRowClick={setViewing}
          empty={
            <div className="grid justify-items-center gap-2 px-5 py-12 text-center">
              <WebhooksLogoIcon size={36} className="text-kumo-inactive" />
              <Text bold>No webhooks</Text>
              <Text variant="secondary">Stream audit events to Slack, a SIEM, or your change-management system.</Text>
            </div>
          }
        />
      </LayerCard>

      <LayerCard className="mt-6 px-5 py-4">
        <div className="grid gap-2">
          <Text bold>Verifying signatures</Text>
          <Text variant="secondary">
            Each request carries an <Mono>X-Flare-Signature</Mono> header of the form <Mono>t=timestamp,v1=hex</Mono>. Compute HMAC-SHA256 over{" "}
            <Mono>timestamp + "." + body</Mono> with your signing secret and compare.
          </Text>
          <Code
            lang="ts"
            code={`const [t, v1] = header.split(",").map((p) => p.split("=")[1]);\nconst expected = createHmac("sha256", secret).update(\`\${t}.\${rawBody}\`).digest("hex");\nconst valid = timingSafeEqual(Buffer.from(v1), Buffer.from(expected));`}
          />
        </div>
      </LayerCard>

      <Dialog.Root open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{editing === "new" ? "Create webhook" : "Edit webhook"}</Dialog.Title>
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
            <Input label="Endpoint URL" placeholder="https://hooks.example.com/dns" value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} error={fieldError(save.error, "url")} />
            <VirtualSelect
              multiple
              label="Events"
              description="Wildcards like zone.* match every event in a category."
              options={(list.data?.events ?? ["*"]).map((e) => ({ value: e, label: e === "*" ? "All events (*)" : e }))}
              value={form.events}
              onChange={(v) => setForm({ ...form, events: v })}
              summarize={(s) => s.map((x) => x.value).join(", ")}
            />
            <Switch label="Enabled" checked={form.enabled} onCheckedChange={(v: boolean) => setForm({ ...form, enabled: v })} />
            {save.error && !fieldError(save.error, "url") && !fieldError(save.error, "name") && <Banner variant="error" size="sm" description={errorMessage(save.error)} />}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button type="submit" variant="primary" loading={save.isPending}>
                {editing === "new" ? "Create webhook" : "Save changes"}
              </Button>
            </div>
          </form>
        </Dialog>
      </Dialog.Root>

      <Dialog.Root open={!!viewing} onOpenChange={(o) => !o && setViewing(null)}>
        <Dialog size="xl" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <div className="grid gap-0.5">
              <Dialog.Title className="text-lg font-semibold">Recent deliveries</Dialog.Title>
              <Text variant="secondary">{viewing?.url}</Text>
            </div>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <VirtualTable
            ariaLabel="Deliveries"
            rows={deliveries.data ?? []}
            columns={deliveryCols}
            rowKey={(d) => String(d.id)}
            loading={deliveries.isLoading}
            maxHeight="420px"
            empty={<div className="px-5 py-8 text-center text-kumo-subtle">No deliveries yet. Send a test event to try it out.</div>}
          />
        </Dialog>
      </Dialog.Root>

      <SecretDialog
        open={!!secret}
        onOpenChange={(o) => !o && setSecret(null)}
        title="Signing secret"
        description="Use this secret to verify the X-Flare-Signature header on incoming requests."
        secret={secret ?? ""}
      />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete webhook"
        description={`Notifications to ${deleting?.url} will stop immediately.`}
        confirmLabel="Delete webhook"
        loading={action.isPending}
        onConfirm={() => deleting && action.mutate({ w: deleting, a: "delete" })}
      />
    </div>
  );
}
