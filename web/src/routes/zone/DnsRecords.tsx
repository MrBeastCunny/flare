import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Dialog, Input, InputArea, InputGroup, LayerCard, Text, Tooltip, LinkButton } from "@cloudflare/kumo";
import {
  PlusIcon,
  MagnifyingGlassIcon,
  DownloadSimpleIcon,
  UploadSimpleIcon,
  TrashIcon,
  XIcon,
  ChatTextIcon,
  ArrowsClockwiseIcon,
  WarningIcon,
  DotsThreeIcon,
  CopySimpleIcon,
  ClockCounterClockwiseIcon,
  StackIcon,
} from "@phosphor-icons/react";
import { PageHeader, ConfirmDialog, Mono, Section } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { RecordForm, draftFromRecord, type RecordDraft } from "../../components/RecordForm";
import { PendingDelegationBanner } from "../../components/NameserverInstructions";
import { api, download, errorMessage, fieldError } from "../../lib/api";
import { keys, useCurrentZone, useOrg, usePerms, useRecords, useZones } from "../../lib/queries";
import { displayContent, isReverseZone } from "../../lib/dns";
import { formatTTL, relativeName, stripDot } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { DnsRecord, ParsedRecord, ZoneTemplate } from "../../lib/types";
import { useQuery } from "@tanstack/react-query";
import { useIsNarrow } from "../../lib/media";

export default function DnsRecords() {
  const { zone, orgId } = useCurrentZone();
  const qc = useQueryClient();
  const { can } = usePerms(orgId);
  const records = useRecords(orgId, zone?.id);
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("search") ?? "");
  const [type, setType] = useState("all");
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<DnsRecord | null>(null);
  const [deleting, setDeleting] = useState<DnsRecord[] | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState("");
  const [importPreview, setImportPreview] = useState<{ records: ParsedRecord[]; warnings: string[] } | null>(null);
  const [replace, setReplace] = useState(false);
  const navigate = useNavigate();
  const narrow = useIsNarrow();
  const org = useOrg(orgId);
  const zones = useZones(orgId);
  const [templateOpen, setTemplateOpen] = useState(false);
  const [templateId, setTemplateId] = useState("");
  const [templateMode, setTemplateMode] = useState("merge");
  const [saveTplOpen, setSaveTplOpen] = useState(false);
  const [tplName, setTplName] = useState("");
  const templates = useQuery({
    queryKey: ["org", orgId, "templates"],
    queryFn: () => api<ZoneTemplate[]>(`/orgs/${orgId}/templates`),
    enabled: templateOpen,
  });
  const applyTemplate = useMutation({
    mutationFn: () => api<{ added: number }>(`/orgs/${orgId}/zones/${zone!.id}/apply-template`, { method: "POST", body: { template_id: templateId, mode: templateMode } }),
    onSuccess: (d) => {
      refresh();
      setTemplateOpen(false);
      toast.success("Template applied", `${d.added} records added.`);
    },
  });
  const saveTemplate = useMutation({
    mutationFn: () => api<ZoneTemplate>(`/orgs/${orgId}/zones/${zone!.id}/save-as-template`, { method: "POST", body: { name: tplName } }),
    onSuccess: (t) => {
      setSaveTplOpen(false);
      void qc.invalidateQueries({ queryKey: ["org", orgId, "templates"] });
      toast.success("Template saved", `${t.records.length} records in "${t.name}".`);
    },
  });

  const editable = can("dns.edit") && zone?.kind !== "Slave";
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: keys.records(orgId, zone?.id ?? "") });
    void qc.invalidateQueries({ queryKey: keys.zoneOverview(orgId, zone?.id ?? "") });
  };

  const create = useMutation({
    mutationFn: (d: RecordDraft) => api<{ record: DnsRecord; ptr?: { name?: string; error?: string; skipped?: string } }>(`/orgs/${orgId}/zones/${zone!.id}/records`, { method: "POST", body: d }),
    onSuccess: ({ record: r, ptr }) => {
      refresh();
      setAdding(false);
      toast.success("Record added", `${r.type} ${stripDot(r.name)}` + (ptr?.name ? `, PTR ${stripDot(ptr.name)} updated` : ""));
      if (ptr?.error || ptr?.skipped) toast.info("PTR not updated", ptr.error ?? ptr.skipped);
    },
  });
  const update = useMutation({
    mutationFn: (d: RecordDraft) => api<{ record: DnsRecord }>(`/orgs/${orgId}/zones/${zone!.id}/records/${editing!.id}`, { method: "PUT", body: d }),
    onSuccess: () => {
      refresh();
      setEditing(null);
      toast.success("Record updated");
    },
  });
  const remove = useMutation({
    mutationFn: (rs: DnsRecord[]) =>
      rs.length === 1
        ? api(`/orgs/${orgId}/zones/${zone!.id}/records/${rs[0].id}`, { method: "DELETE" })
        : api(`/orgs/${orgId}/zones/${zone!.id}/records/bulk-delete`, { method: "POST", body: { ids: rs.map((r) => r.id) } }),
    onSuccess: (_, rs) => {
      refresh();
      setDeleting(null);
      setSelected(new Set());
      toast.success(rs.length === 1 ? "Record deleted" : `${rs.length} records deleted`);
    },
    onError: (e) => toast.error(e, "Delete failed"),
  });
  const preview = useMutation({
    mutationFn: () => api<{ records: ParsedRecord[]; warnings: string[] }>(`/orgs/${orgId}/zones/${zone!.id}/import/preview`, { method: "POST", body: { text: importText } }),
    onSuccess: setImportPreview,
  });
  const doImport = useMutation({
    mutationFn: () => api<{ added: number }>(`/orgs/${orgId}/zones/${zone!.id}/import`, { method: "POST", body: { text: importText, mode: replace ? "replace" : "merge" } }),
    onSuccess: (d) => {
      refresh();
      setImportOpen(false);
      setImportText("");
      setImportPreview(null);
      toast.success("Import complete", `${d.added} records added.`);
    },
  });
  const toggle = useMutation({
    mutationFn: (r: DnsRecord) =>
      api(`/orgs/${orgId}/zones/${zone!.id}/records/${r.id}`, {
        method: "PUT",
        body: { ...draftFromRecord(r, zone!.name), content: r.content, disabled: !r.disabled },
      }),
    onSuccess: () => refresh(),
    onError: (e) => toast.error(e),
  });

  // The zone's own NS records follow its nameserver set (zone settings), so they are not listed here.
  // NS records for delegated subdomains are ordinary records and stay visible.
  const all = useMemo(
    () => (records.data?.records ?? []).filter((r) => !(r.type === "NS" && r.name.toLowerCase() === zone?.name.toLowerCase())),
    [records.data, zone?.name],
  );
  const typeCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of all) m[r.type] = (m[r.type] ?? 0) + 1;
    return m;
  }, [all]);

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return all.filter(
      (r) =>
        (type === "all" || r.type === type) &&
        (!query || r.name.includes(query) || r.content.toLowerCase().includes(query) || r.comment.toLowerCase().includes(query) || r.type.toLowerCase() === query),
    );
  }, [all, q, type]);

  if (!zone) return null;

  const recordMenu = (r: DnsRecord) => (
    <ActionMenu
      items={[
        { key: "edit", label: "Edit", hidden: !narrow, onSelect: () => setEditing(r) },
        { key: "toggle", label: r.disabled ? "Enable record" : "Disable record", onSelect: () => toggle.mutate(r) },
        { key: "copy", label: "Copy content", icon: <CopySimpleIcon />, onSelect: () => void navigator.clipboard.writeText(displayContent(r.type, r.content)) },
        {
          key: "history",
          label: "View history",
          icon: <ClockCounterClockwiseIcon />,
          hidden: !can("audit.read"),
          onSelect: () => navigate(`/${orgId}/${stripDot(zone.name)}/activity?q=${encodeURIComponent(stripDot(r.name))}`),
        },
        { key: "delete", label: "Delete", danger: true, separatorBefore: true, icon: <TrashIcon />, onSelect: () => setDeleting([r]) },
      ]}
    />
  );

  // Phones: one stacked cell per record instead of a wide table that scrolls sideways.
  const narrowColumns: Column<DnsRecord>[] = [
    { key: "type", header: "Type", width: "72px", render: (r) => <Badge variant={r.type === "SOA" || r.type === "NS" ? "neutral" : "outline"}>{r.type}</Badge> },
    {
      key: "record",
      header: "Record",
      render: (r) => (
        <div className="grid min-w-0 gap-0.5">
          <span className="flex min-w-0 items-center gap-2">
            <Mono className="truncate text-kumo-strong">{relativeName(r.name, zone.name)}</Mono>
            {r.disabled && <Badge variant="neutral">Disabled</Badge>}
          </span>
          <Mono className="truncate text-kumo-subtle">{displayContent(r.type, r.content)}</Mono>
        </div>
      ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "48px",
      align: "right",
      render: (r) =>
        r.type !== "SOA" && editable ? (
          <div onClick={(e) => e.stopPropagation()}>{recordMenu(r)}</div>
        ) : null,
    },
  ];

  const columns: Column<DnsRecord>[] = [
    { key: "type", header: "Type", width: "84px", render: (r) => <Badge variant={r.type === "SOA" || r.type === "NS" ? "neutral" : "outline"}>{r.type}</Badge> },
    {
      key: "name",
      header: "Name",
      width: "28%",
      render: (r) => (
        <div className="flex min-w-0 items-center gap-2">
          <Tooltip content={stripDot(r.name)}>
            <Mono className="truncate text-kumo-strong">{relativeName(r.name, zone.name)}</Mono>
          </Tooltip>
          {r.disabled && <Badge variant="neutral">Disabled</Badge>}
        </div>
      ),
    },
    {
      key: "content",
      header: "Content",
      render: (r) => (
        <div className="flex min-w-0 items-center gap-2">
          <Mono className="truncate">{displayContent(r.type, r.content)}</Mono>
          {r.comment && (
            <Tooltip content={r.comment}>
              <ChatTextIcon size={14} className="shrink-0 text-kumo-subtle" />
            </Tooltip>
          )}
        </div>
      ),
    },
    { key: "ttl", header: "TTL", width: "90px", render: (r) => <span className="text-kumo-subtle">{formatTTL(r.ttl)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "112px",
      align: "right",
      render: (r) =>
        r.type === "SOA" ? (
          <LinkButton size="sm" variant="ghost" href={`/${orgId}/${stripDot(zone.name)}/settings`}>
            Settings
          </LinkButton>
        ) : editable ? (
          <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
            <Button size="sm" variant="ghost" onClick={() => setEditing(r)}>
              Edit
            </Button>
            {recordMenu(r)}
          </div>
        ) : null,
    },
  ];

  const formExtras = {
    allowedTypes: isReverseZone(zone.name) ? org.data?.record_types.reverse : org.data?.record_types.forward,
    hasReverseZones: (zones.data ?? []).some((z) => isReverseZone(z.name)),
    autoPtrDefault: org.data?.auto_ptr,
  };

  const selectedRecords = all.filter((r) => selected.has(r.id));

  return (
    <div>
      <PageHeader
        title="DNS records"
        description={`Manage the records that ${stripDot(zone.name)} publishes.`}
        actions={
          <ActionMenu
            label="More actions"
            minWidth={230}
            trigger={<Button icon={<DotsThreeIcon weight="bold" />}>More</Button>}
            items={[
              { key: "import", label: "Import zone file", icon: <UploadSimpleIcon />, hidden: !editable, onSelect: () => setImportOpen(true) },
              {
                key: "export",
                label: "Export zone file",
                icon: <DownloadSimpleIcon />,
                onSelect: () => void download(`/orgs/${orgId}/zones/${zone.id}/export`).catch((e) => toast.error(e, "Export failed")),
              },
              { key: "apply", label: "Apply a template", icon: <StackIcon />, hidden: !editable, separatorBefore: true, onSelect: () => setTemplateOpen(true) },
              {
                key: "save",
                label: "Save as template",
                icon: <CopySimpleIcon />,
                hidden: !can("zones.create"),
                onSelect: () => {
                  setTplName(`${stripDot(zone.name)} template`);
                  setSaveTplOpen(true);
                },
              },
            ]}
          />
        }
      />

      <div className="mb-6 empty:hidden">
        <PendingDelegationBanner zone={zone} />
      </div>
      {zone.kind === "Slave" && (
        <div className="mb-6">
          <Banner variant="secondary" description="This is a secondary zone. Records are transferred from the primary servers and are read-only here." />
        </div>
      )}

      {adding && (
        <div className="mb-6">
          <Section title="Add record">
            <RecordForm
              zone={zone.name}
              onSubmit={(d) => create.mutate(d)}
              onCancel={() => setAdding(false)}
              submitting={create.isPending}
              error={create.error}
              submitLabel="Save record"
              {...formExtras}
            />
          </Section>
        </div>
      )}

      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-kumo-line px-4 py-3">
          <InputGroup className="min-w-0 flex-1 basis-56 sm:max-w-sm">
            <InputGroup.Addon>
              <MagnifyingGlassIcon />
            </InputGroup.Addon>
            <InputGroup.Input
              placeholder="Search name, content or comment"
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                if (params.get("search")) setParams({}, { replace: true });
              }}
              aria-label="Search records"
            />
          </InputGroup>
          <VirtualSelect
            aria-label="Filter by type"
            className="w-36 sm:w-40"
            options={[{ value: "all", label: `All types (${all.length})` }, ...Object.keys(typeCounts).sort().map((t) => ({ value: t, label: `${t} (${typeCounts[t]})` }))]}
            value={type}
            onChange={setType}
          />
          <Button variant="ghost" size="sm" shape="square" icon={<ArrowsClockwiseIcon />} aria-label="Refresh" onClick={() => records.refetch()} />
          <div className="ml-auto flex items-center gap-2">
            {selected.size > 0 && editable && (
              <>
                <Text variant="secondary">{selected.size} selected</Text>
                <Button size="sm" variant="secondary-destructive" icon={<TrashIcon />} onClick={() => setDeleting(selectedRecords)}>
                  Delete
                </Button>
              </>
            )}
            {editable && !adding && (
              <Button variant="primary" icon={<PlusIcon />} onClick={() => setAdding(true)}>
                Add record
              </Button>
            )}
          </div>
        </div>
        {records.error ? (
          <div className="p-5">
            <Banner variant="error" icon={<WarningIcon weight="fill" />} title="Could not load records" description={errorMessage(records.error)} />
          </div>
        ) : (
          <VirtualTable
            ariaLabel="DNS records"
            rows={rows}
            columns={narrow ? narrowColumns : columns}
            rowKey={(r) => r.id}
            loading={records.isLoading}
            selection={editable && !narrow ? { selected, onChange: setSelected, isSelectable: (id) => all.find((r) => r.id === id)?.type !== "SOA" } : undefined}
            onRowClick={editable ? (r) => r.type !== "SOA" && setEditing(r) : undefined}
            rowClassName={(r) => (r.disabled ? "opacity-60" : undefined)}
            minWidth={narrow ? 0 : 820}
            rowHeight={narrow ? 60 : 44}
            maxHeight="calc(100vh - 300px)"
            empty={
              <div className="px-5 py-12 text-center text-kumo-subtle">
                {all.length === 0 ? "This zone has no records yet." : "No records match your search."}
              </div>
            }
          />
        )}
        <div className="flex items-center justify-between border-t border-kumo-line px-4 py-2.5 text-sm text-kumo-subtle">
          <span>
            {rows.length} of {all.length} records
          </span>
          {records.data && <span>SOA serial {records.data.serial}</span>}
        </div>
      </LayerCard>

      <Dialog.Root open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <Dialog size="xl" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Edit record</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          {editing && (
            <RecordForm
              key={editing.id}
              zone={zone.name}
              initial={draftFromRecord(editing, zone.name)}
              onSubmit={(d) => update.mutate(d)}
              onCancel={() => setEditing(null)}
              submitting={update.isPending}
              error={update.error}
              submitLabel="Save changes"
              {...formExtras}
            />
          )}
        </Dialog>
      </Dialog.Root>

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={deleting && deleting.length > 1 ? `Delete ${deleting.length} records` : "Delete record"}
        description={
          deleting?.length === 1
            ? `${deleting[0].type} ${stripDot(deleting[0].name)} will stop resolving once caches expire.`
            : "These records will stop resolving once caches expire."
        }
        confirmLabel="Delete"
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting)}
      />

      <Dialog.Root
        open={importOpen}
        onOpenChange={(o) => {
          setImportOpen(o);
          if (!o) setImportPreview(null);
        }}
      >
        <Dialog size="xl" className="p-6">
          <div className="mb-2 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Import zone file</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <Dialog.Description className="mb-4 text-kumo-subtle">
            Paste a BIND-format zone file. SOA and apex NS records are ignored. Relative names use {stripDot(zone.name)} as the origin.
          </Dialog.Description>
          {importPreview ? (
            <div className="grid gap-4">
              <Text>
                {importPreview.records.length} records parsed{importPreview.warnings.length ? `, ${importPreview.warnings.length} skipped` : ""}.
              </Text>
              {importPreview.warnings.length > 0 && <Banner variant="alert" size="sm" description={importPreview.warnings.slice(0, 5).join(" ")} />}
              <LayerCard className="overflow-hidden bg-kumo-base p-0">
                <VirtualTable
                  ariaLabel="Import preview"
                  rows={importPreview.records}
                  rowKey={(r) => `${r.name}|${r.type}|${r.content}`}
                  maxHeight="320px"
                  columns={[
                    { key: "type", header: "Type", width: "80px", render: (r) => <Badge variant="outline">{r.type}</Badge> },
                    { key: "name", header: "Name", width: "30%", render: (r) => <Mono>{relativeName(r.name, zone.name)}</Mono> },
                    { key: "content", header: "Content", render: (r) => <Mono className="text-kumo-subtle">{r.content}</Mono> },
                    { key: "ttl", header: "TTL", width: "80px", render: (r) => formatTTL(r.ttl) },
                  ]}
                />
              </LayerCard>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
                Replace existing records (delete records not in this file)
              </label>
              {doImport.error && <Banner variant="error" size="sm" description={errorMessage(doImport.error)} />}
              <div className="flex justify-end gap-2">
                <Button onClick={() => setImportPreview(null)}>Back</Button>
                <Button variant={replace ? "destructive" : "primary"} loading={doImport.isPending} onClick={() => doImport.mutate()}>
                  {replace ? "Replace records" : `Import ${importPreview.records.length} records`}
                </Button>
              </div>
            </div>
          ) : (
            <div className="grid gap-4">
              <InputArea
                aria-label="Zone file"
                value={importText}
                onValueChange={setImportText}
                className="min-h-72 font-mono text-sm"
                placeholder={"$TTL 3600\n@     IN MX 10 mail\nwww   IN A     192.0.2.10\napi   IN CNAME www"}
                error={fieldError(preview.error, "text")}
              />
              <label className="inline-flex w-fit cursor-pointer items-center gap-2 text-sm text-kumo-link">
                <UploadSimpleIcon />
                Upload a file
                <input
                  type="file"
                  className="hidden"
                  accept=".zone,.txt,.db,text/plain"
                  onChange={async (e) => {
                    const f = e.target.files?.[0];
                    if (f) setImportText(await f.text());
                  }}
                />
              </label>
              <div className="flex justify-end gap-2">
                <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
                <Button variant="primary" loading={preview.isPending} disabled={!importText.trim()} onClick={() => preview.mutate()}>
                  Preview import
                </Button>
              </div>
            </div>
          )}
        </Dialog>
      </Dialog.Root>

      <Dialog.Root open={templateOpen} onOpenChange={setTemplateOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-2 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Apply a template</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <Dialog.Description className="mb-4 text-kumo-subtle">Add a predefined set of records to {stripDot(zone.name)}.</Dialog.Description>
          <div className="grid gap-4">
            <VirtualSelect
              label="Template"
              placeholder={templates.isLoading ? "Loading" : "Choose a template"}
              options={(templates.data ?? []).map((t) => ({ value: t.id, label: t.name, description: `${t.records.length} records${t.org_id ? "" : " · instance template"}` }))}
              value={templateId}
              onChange={setTemplateId}
              emptyText="No templates yet. Create one under Zone templates."
            />
            <VirtualSelect
              label="Mode"
              options={[
                { value: "merge", label: "Merge", description: "Add template records next to existing ones" },
                { value: "replace", label: "Replace", description: "Remove records not in the template (SOA and NS are kept)" },
              ]}
              value={templateMode}
              onChange={setTemplateMode}
            />
            {applyTemplate.error && <Banner variant="error" size="sm" description={errorMessage(applyTemplate.error)} />}
            <div className="flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button variant={templateMode === "replace" ? "destructive" : "primary"} disabled={!templateId} loading={applyTemplate.isPending} onClick={() => applyTemplate.mutate()}>
                Apply template
              </Button>
            </div>
          </div>
        </Dialog>
      </Dialog.Root>

      <Dialog.Root open={saveTplOpen} onOpenChange={setSaveTplOpen}>
        <Dialog size="base" className="p-6">
          <Dialog.Title className="mb-2 text-lg font-semibold">Save as template</Dialog.Title>
          <Dialog.Description className="mb-4 text-kumo-subtle">Records are saved with names relative to the zone so the template works for any domain.</Dialog.Description>
          <div className="grid gap-4">
            <Input label="Template name" value={tplName} onChange={(e) => setTplName(e.target.value)} error={fieldError(saveTemplate.error, "name")} autoFocus />
            <div className="flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button variant="primary" loading={saveTemplate.isPending} disabled={!tplName.trim()} onClick={() => saveTemplate.mutate()}>
                Save template
              </Button>
            </div>
          </div>
        </Dialog>
      </Dialog.Root>
    </div>
  );
}
