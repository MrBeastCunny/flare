import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Dialog, Input, LayerCard, Text } from "@cloudflare/kumo";
import { CopySimpleIcon, PlusIcon, TrashIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader, ConfirmDialog, Mono } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { VirtualList } from "../../components/VirtualList";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError, ApiError } from "../../lib/api";
import { useOrgId, usePerms } from "../../lib/queries";
import { recordTypes, ttlOptions } from "../../lib/dns";
import { timeAgo } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { TemplateRecord, ZoneTemplate } from "../../lib/types";

const typeOptions = recordTypes.map((t) => ({ value: t.type, label: t.type, description: t.description, keywords: t.description }));
const ttlOpts = ttlOptions.filter((t) => t.value !== 1).map((t) => ({ value: t.value, label: t.label }));

type Row = TemplateRecord & { key: number };
let rowKey = 0;
const newRow = (r?: Partial<TemplateRecord>): Row => ({ key: ++rowKey, name: "@", type: "A", ttl: 3600, content: "", ...r });

function TemplateEditor({
  open,
  onOpenChange,
  initial,
  save,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  initial: ZoneTemplate | null;
  save: (body: { name: string; description: string; records: TemplateRecord[] }) => Promise<unknown>;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [rows, setRows] = useState<Row[]>(() => (initial?.records.length ? initial.records.map((r) => newRow(r)) : [newRow()]));
  const [error, setError] = useState<unknown>(null);
  const [saving, setSaving] = useState(false);
  const update = (key: number, patch: Partial<TemplateRecord>) => setRows((rs) => rs.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  const rowError = (i: number, f: string) => (error instanceof ApiError ? error.fields[`records.${i}.${f}`] : undefined);

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog size="xl" className="p-6">
        <div className="mb-4 flex items-start justify-between">
          <Dialog.Title className="text-lg font-semibold">{initial ? "Edit template" : "Create template"}</Dialog.Title>
          <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
        </div>
        <form
          className="grid gap-5"
          onSubmit={async (e) => {
            e.preventDefault();
            setSaving(true);
            setError(null);
            try {
              await save({ name, description, records: rows.map(({ key: _k, ...r }) => r) });
              onOpenChange(false);
            } catch (err) {
              setError(err);
            } finally {
              setSaving(false);
            }
          }}
        >
          <div className="grid gap-4 md:grid-cols-2">
            <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} error={fieldError(error, "name")} autoFocus />
            <Input label="Description" required={false} value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <div className="flex items-end justify-between">
              <div className="grid gap-0.5">
                <Text bold>Records</Text>
                <Text variant="secondary" size="sm">
                  Use names relative to the zone, such as @, www or _dmarc. Targets without a trailing dot are relative too.
                </Text>
              </div>
              <Button size="sm" icon={<PlusIcon />} onClick={() => setRows([...rows, newRow({ name: "" })])}>
                Add record
              </Button>
            </div>
            <div className="hidden grid-cols-[140px_110px_110px_minmax(0,1fr)_36px] gap-2 text-sm text-kumo-subtle md:grid">
              <span>Name</span>
              <span>Type</span>
              <span>TTL</span>
              <span>Content</span>
              <span />
            </div>
            <VirtualList
              ariaLabel="Template records"
              items={rows}
              itemKey={(r) => String(r.key)}
              divided={false}
              gap={8}
              estimateSize={44}
              maxHeight={380}
              renderItem={(r) => {
                const i = rows.indexOf(r);
                return (
                  <div className="grid gap-2 md:grid-cols-[140px_110px_110px_minmax(0,1fr)_36px]">
                    <Input aria-label="Name" value={r.name} onChange={(e) => update(r.key, { name: e.target.value })} placeholder="@" className="font-mono" error={rowError(i, "name")} />
                    <VirtualSelect aria-label="Type" options={typeOptions} value={r.type} onChange={(v) => update(r.key, { type: v })} searchable popupWidth={300} />
                    <VirtualSelect aria-label="TTL" options={ttlOpts} value={r.ttl} onChange={(v) => update(r.key, { ttl: v })} />
                    <Input aria-label="Content" value={r.content} onChange={(e) => update(r.key, { content: e.target.value })} className="font-mono" error={rowError(i, "content")} />
                    <Button variant="ghost" shape="square" icon={<TrashIcon />} aria-label="Remove record" onClick={() => setRows(rows.filter((x) => x.key !== r.key))} />
                  </div>
                );
              }}
            />
          </div>
          {error !== null && !fieldError(error, "name") && <Banner variant="error" size="sm" description={errorMessage(error)} />}
          <div className="flex justify-end gap-2 border-t border-kumo-line pt-4">
            <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
            <Button type="submit" variant="primary" loading={saving} disabled={!name.trim()}>
              Save template
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}

/** Zone templates for an organization, or instance-wide templates when admin is true. */
export function TemplatesView({ admin }: { admin?: boolean }) {
  const orgId = useOrgId();
  const qc = useQueryClient();
  const { can } = usePerms(orgId);
  const base = admin ? "/admin/templates" : `/orgs/${orgId}/templates`;
  const queryKey = admin ? ["admin", "templates"] : ["org", orgId, "templates"];
  const list = useQuery({ queryKey, queryFn: () => api<ZoneTemplate[]>(base) });
  const [editing, setEditingState] = useState<ZoneTemplate | "new">("new");
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorKey, setEditorKey] = useState(0);
  const setEditing = (t: ZoneTemplate | "new") => {
    setEditingState(t);
    setEditorKey((k) => k + 1);
    setEditorOpen(true);
  };
  const [deleting, setDeleting] = useState<ZoneTemplate | null>(null);
  const editable = admin || can("zones.create");
  const ownTemplate = (t: ZoneTemplate) => (admin ? t.org_id === null : t.org_id !== null);

  const remove = useMutation({
    mutationFn: (t: ZoneTemplate) => api(`${base}/${t.id}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey });
      setDeleting(null);
      toast.success("Template deleted");
    },
    onError: (e) => toast.error(e),
  });

  const save = async (body: { name: string; description: string; records: TemplateRecord[] }) => {
    const t = editing !== "new" ? editing : null;
    await api(t ? `${base}/${t.id}` : base, { method: t ? "PUT" : "POST", body });
    void qc.invalidateQueries({ queryKey });
    toast.success(t ? "Template updated" : "Template created");
  };

  const columns: Column<ZoneTemplate>[] = [
    {
      key: "name",
      header: "Template",
      width: "34%",
      render: (t) => (
        <div className="grid min-w-0">
          <span className="flex min-w-0 items-center gap-2">
            <span className="truncate font-medium text-kumo-strong">{t.name}</span>
            {!t.org_id && !admin && <Badge variant="neutral">Instance</Badge>}
          </span>
          {t.description && <span className="truncate text-sm text-kumo-subtle">{t.description}</span>}
        </div>
      ),
    },
    {
      key: "records",
      header: "Records",
      render: (t) => (
        <Mono className="truncate text-kumo-subtle">
          {t.records
            .slice(0, 4)
            .map((r) => `${r.type} ${r.name}`)
            .join(", ")}
          {t.records.length > 4 ? ` and ${t.records.length - 4} more` : ""}
        </Mono>
      ),
    },
    { key: "count", header: "Count", width: "90px", render: (t) => <span className="tabular-nums">{t.records.length}</span> },
    { key: "updated", header: "Updated", width: "130px", render: (t) => <span className="text-kumo-subtle">{timeAgo(t.updated_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "64px",
      align: "right",
      render: (t) =>
        editable && ownTemplate(t) ? (
          <ActionMenu
            items={[
              { key: "edit", label: "Edit", onSelect: () => setEditing(t) },
              { key: "delete", label: "Delete", danger: true, separatorBefore: true, onSelect: () => setDeleting(t) },
            ]}
          />
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title="Zone templates"
        description={
          admin
            ? "Instance-wide templates are available to every organization when adding a domain or applying records."
            : "Reusable record sets for new domains, such as mail, verification records or standard web hosting."
        }
        actions={
          editable && (
            <Button variant="primary" icon={<PlusIcon />} onClick={() => setEditing("new")}>
              Create template
            </Button>
          )
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <VirtualTable
          ariaLabel="Zone templates"
          rows={list.data ?? []}
          columns={columns}
          rowKey={(t) => t.id}
          loading={list.isLoading}
          rowHeight={60}
          onRowClick={(t) => editable && ownTemplate(t) && setEditing(t)}
          empty={
            <div className="grid justify-items-center gap-2 px-5 py-12 text-center">
              <CopySimpleIcon size={36} className="text-kumo-inactive" />
              <Text bold>No templates yet</Text>
              <Text variant="secondary">Create one here, or use "Save as template" on any domain's DNS records page.</Text>
            </div>
          }
        />
      </LayerCard>
      <TemplateEditor key={editorKey} open={editorOpen} onOpenChange={setEditorOpen} initial={editing === "new" ? null : editing} save={save} />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete template"
        description={`"${deleting?.name}" will no longer be available. Zones created from it are not affected.`}
        confirmLabel="Delete template"
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting)}
      />
    </div>
  );
}

export default function Templates() {
  return <TemplatesView />;
}
