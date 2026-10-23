import { useMemo, useState } from "react";
import { Badge, Button, Dialog, InputGroup, LayerCard, Text, Tooltip } from "@cloudflare/kumo";
import { DownloadSimpleIcon, MagnifyingGlassIcon, XIcon, ArrowsClockwiseIcon, RobotIcon, UserIcon, KeyIcon, IdentificationCardIcon } from "@phosphor-icons/react";
import { VirtualTable, type Column } from "./VirtualTable";
import { VirtualSelect } from "./VirtualSelect";
import { Mono, DetailRow } from "./ui";
import { useAuditLog } from "../lib/queries";
import { download } from "../lib/api";
import { formatDateTime, timeAgo, stripDot, parseUA } from "../lib/format";
import { toast } from "../lib/toast";
import type { AuditEntry } from "../lib/types";

const actionLabels: Record<string, string> = {
  "auth.login": "Signed in",
  "auth.logout": "Signed out",
  "auth.mfa": "Two-factor verification",
  "auth.password_reset_requested": "Requested password reset",
  "auth.password_reset": "Reset password",
  "user.signup": "Created account",
  "user.update": "Updated profile",
  "user.password_change": "Changed password",
  "user.mfa_enable": "Enabled two-factor authentication",
  "user.mfa_disable": "Disabled two-factor authentication",
  "user.recovery_codes_regenerate": "Regenerated recovery codes",
  "user.session_revoke": "Revoked a session",
  "user.session_revoke_all": "Revoked all other sessions",
  "user.delete": "Deleted account",
  "org.create": "Created organization",
  "org.update": "Updated organization settings",
  "org.delete": "Deleted organization",
  "member.invite": "Invited member",
  "member.invite_resend": "Re-sent invitation",
  "member.invite_revoke": "Revoked invitation",
  "member.join": "Joined organization",
  "member.add": "Added member",
  "member.update": "Changed member role",
  "member.remove": "Removed member",
  "member.leave": "Left organization",
  "member.role_sync": "Synced role from identity provider",
  "token.create": "Created API token",
  "token.roll": "Rolled API token",
  "token.revoke": "Revoked API token",
  "zone.create": "Added domain",
  "zone.delete": "Deleted domain",
  "zone.adopt": "Imported existing zone",
  "zone.import": "Imported records",
  "zone.export": "Exported zone file",
  "zone.status_change": "Zone status changed",
  "zone.force_activate": "Activated zone manually",
  "zone.move_in": "Moved zone in",
  "zone.move_out": "Moved zone out",
  "zone.settings_update": "Updated zone settings",
  "zone.nameservers_change": "Changed nameservers",
  "zone.dnssec_enable": "Enabled DNSSEC",
  "zone.dnssec_disable": "Disabled DNSSEC",
  "zone.dnssec_key_add": "Added DNSSEC key",
  "zone.dnssec_key_update": "Updated DNSSEC key",
  "zone.dnssec_key_delete": "Deleted DNSSEC key",
  "zone.notify": "Sent NOTIFY",
  "zone.rectify": "Rectified zone",
  "zone.axfr_retrieve": "Retrieved zone transfer",
  "zone.flush_cache": "Flushed cache",
  "record.create": "Created DNS record",
  "record.api_patch": "Changed records via API",
  "record.dyndns_update": "Dynamic DNS update",
  "record.ptr_sync": "Updated PTR record",
  "template.create": "Created zone template",
  "template.update": "Updated zone template",
  "template.delete": "Deleted zone template",
  "zone.template_apply": "Applied template",
  "admin.user_create": "Created user",
  "admin.password": "Reset user password",
  "admin.email": "Sent test email",
  "record.update": "Updated DNS record",
  "record.delete": "Deleted DNS record",
  "record.bulk_delete": "Deleted DNS records",
  "sso.create": "Configured single sign-on",
  "sso.update": "Updated single sign-on",
  "sso.delete": "Removed single sign-on",
  "sso.domain_add": "Added SSO domain",
  "sso.domain_verify": "Verified SSO domain",
  "sso.domain_remove": "Removed SSO domain",
  "scim.token_create": "Created SCIM token",
  "scim.token_revoke": "Revoked SCIM token",
  "scim.user_create": "Provisioned user",
  "scim.user_update": "Updated provisioned user",
  "scim.user_deactivate": "Deactivated user",
  "scim.user_reactivate": "Reactivated user",
  "scim.user_delete": "Deprovisioned user",
  "scim.group_create": "Provisioned group",
  "scim.group_update": "Updated group",
  "scim.group_delete": "Deleted group",
  "scim.group_role": "Changed group role",
  "webhook.create": "Created webhook",
  "webhook.update": "Updated webhook",
  "webhook.delete": "Deleted webhook",
  "webhook.rotate_secret": "Rotated webhook secret",
  "audit.export": "Exported audit log",
  "instance.setup": "Completed instance setup",
  "admin.settings_update": "Updated instance settings",
  "admin.server_create": "Added DNS server",
  "admin.server_update": "Updated DNS server",
  "admin.server_delete": "Removed DNS server",
  "admin.nameserver_set_create": "Created nameserver set",
  "admin.nameserver_set_update": "Updated nameserver set",
  "admin.nameserver_set_delete": "Deleted nameserver set",
  "admin.user_update": "Updated user",
  "admin.user_delete": "Deleted user",
  "admin.org_update": "Updated organization limits",
  "admin.tsig_create": "Created TSIG key",
  "admin.tsig_delete": "Deleted TSIG key",
  "admin.tsig_reveal": "Revealed TSIG key",
  "admin.break_glass_reset": "Restored administrator access",
};

export function actionLabel(a: string) {
  return actionLabels[a] ?? a.replace(/[._]/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

function ActorIcon({ type }: { type: string }) {
  const cls = "shrink-0 text-kumo-subtle";
  if (type === "api_token") return <KeyIcon size={16} className={cls} />;
  if (type === "scim") return <IdentificationCardIcon size={16} className={cls} />;
  if (type === "system") return <RobotIcon size={16} className={cls} />;
  return <UserIcon size={16} className={cls} />;
}

function summarize(e: AuditEntry): string {
  const m = e.metadata as Record<string, unknown>;
  if (e.action.startsWith("record.") && m) {
    const after = m.after as Record<string, unknown> | undefined;
    if (after) return `${after.type} ${stripDot(String(after.name))}  ${after.content}`;
    if (m.type) return `${m.type} ${stripDot(e.resource_name)}  ${m.content ?? ""}`;
    if (m.count) return `${m.count} records in ${stripDot(e.resource_name)}`;
  }
  return stripDot(e.resource_name);
}

const categories = [
  { value: "", label: "All events" },
  { value: "record.", label: "DNS records" },
  { value: "zone.", label: "Zones" },
  { value: "member.", label: "Members" },
  { value: "auth.", label: "Sign-ins" },
  { value: "token.", label: "API tokens" },
  { value: "sso.", label: "Single sign-on" },
  { value: "scim.", label: "Provisioning (SCIM)" },
  { value: "webhook.", label: "Webhooks" },
  { value: "org.", label: "Organization" },
  { value: "user.", label: "User accounts" },
  { value: "admin.", label: "Instance administration" },
];

interface Props {
  path: string;
  exportPath?: string;
  scope: string;
  showOrg?: boolean;
  compact?: boolean;
  initialQuery?: string;
}

/** Filterable, infinitely scrolling audit log with a detail drawer. */
export function AuditLogView({ path, exportPath, scope, showOrg, compact, initialQuery = "" }: Props) {
  const [q, setQ] = useState(initialQuery);
  const [query, setQuery] = useState(initialQuery);
  const [action, setAction] = useState("");
  const [outcome, setOutcome] = useState("");
  const [range, setRange] = useState("30");
  const [selected, setSelected] = useState<AuditEntry | null>(null);

  const filters = useMemo(() => {
    const f: Record<string, string> = { q: query, action, outcome };
    if (range !== "all") f.since = new Date(Date.now() - Number(range) * 86400_000).toISOString();
    return f;
  }, [query, action, outcome, range]);

  const log = useAuditLog(path, scope, filters);
  const rows = useMemo(() => log.data?.pages.flatMap((p) => p.entries) ?? [], [log.data]);

  const columns: Column<AuditEntry>[] = [
    {
      key: "time",
      header: "Time",
      width: "150px",
      render: (e) => (
        <Tooltip content={formatDateTime(e.created_at)}>
          <span className="text-kumo-subtle">{timeAgo(e.created_at)}</span>
        </Tooltip>
      ),
    },
    {
      key: "actor",
      header: "Actor",
      width: "24%",
      render: (e) => (
        <div className="flex min-w-0 items-center gap-2">
          <ActorIcon type={e.actor_type} />
          <span className="truncate">{e.actor_label}</span>
        </div>
      ),
    },
    {
      key: "action",
      header: "Action",
      width: "24%",
      render: (e) => (
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate font-medium text-kumo-strong">{actionLabel(e.action)}</span>
          {e.outcome === "failure" && <Badge variant="error">Failed</Badge>}
        </div>
      ),
    },
    { key: "resource", header: "Resource", render: (e) => <Mono className="text-kumo-subtle">{summarize(e)}</Mono> },
    ...(showOrg ? [{ key: "org", header: "Organization", width: "160px", render: (e: AuditEntry) => <span className="truncate text-kumo-subtle">{e.org_name || "Instance"}</span> }] : []),
    ...(!compact ? [{ key: "ip", header: "IP address", width: "140px", render: (e: AuditEntry) => <Mono className="text-kumo-subtle">{e.ip}</Mono> }] : []),
  ];

  const doExport = async (format: "csv" | "json") => {
    if (!exportPath) return;
    try {
      await download(exportPath, { ...filters, format });
    } catch (e) {
      toast.error(e, "Export failed");
    }
  };

  return (
    <LayerCard className="overflow-hidden bg-kumo-base p-0">
      <form
        className="flex flex-wrap items-center gap-3 border-b border-kumo-line px-4 py-3"
        onSubmit={(e) => {
          e.preventDefault();
          setQuery(q);
        }}
      >
        <InputGroup className="w-full max-w-xs">
          <InputGroup.Addon>
            <MagnifyingGlassIcon />
          </InputGroup.Addon>
          <InputGroup.Input placeholder="Search actor, resource or IP" value={q} onChange={(e) => setQ(e.target.value)} onBlur={() => setQuery(q)} aria-label="Search audit log" />
        </InputGroup>
        <VirtualSelect aria-label="Event type" className="w-52" options={categories} value={action} onChange={setAction} />
        <VirtualSelect
          aria-label="Outcome"
          className="w-36"
          options={[
            { value: "", label: "Any outcome" },
            { value: "success", label: "Succeeded" },
            { value: "failure", label: "Failed" },
          ]}
          value={outcome}
          onChange={setOutcome}
        />
        <VirtualSelect
          aria-label="Time range"
          className="w-40"
          options={[
            { value: "1", label: "Last 24 hours" },
            { value: "7", label: "Last 7 days" },
            { value: "30", label: "Last 30 days" },
            { value: "90", label: "Last 90 days" },
            { value: "365", label: "Last year" },
            { value: "all", label: "All time" },
          ]}
          value={range}
          onChange={setRange}
        />
        <div className="ml-auto flex items-center gap-2">
          <Button variant="ghost" size="sm" shape="square" icon={<ArrowsClockwiseIcon />} aria-label="Refresh" onClick={() => log.refetch()} />
          {exportPath && (
            <>
              <Button size="sm" icon={<DownloadSimpleIcon />} onClick={() => doExport("csv")}>
                CSV
              </Button>
              <Button size="sm" icon={<DownloadSimpleIcon />} onClick={() => doExport("json")}>
                JSON
              </Button>
            </>
          )}
        </div>
      </form>
      <VirtualTable
        ariaLabel="Audit log"
        rows={rows}
        columns={columns}
        rowKey={(e) => String(e.id)}
        loading={log.isLoading}
        onRowClick={setSelected}
        onEndReached={() => log.fetchNextPage()}
        hasMore={log.hasNextPage}
        loadingMore={log.isFetchingNextPage}
        maxHeight={compact ? "560px" : "calc(100vh - 290px)"}
        minWidth={showOrg ? 1100 : 940}
        empty={<div className="px-5 py-12 text-center text-kumo-subtle">No events match these filters.</div>}
      />

      <Dialog.Root open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <Dialog size="xl" className="p-6">
          {selected && (
            <>
              <div className="mb-4 flex items-start justify-between gap-4">
                <div className="grid gap-1">
                  <Dialog.Title className="text-lg font-semibold">{actionLabel(selected.action)}</Dialog.Title>
                  <Text variant="secondary">{formatDateTime(selected.created_at)}</Text>
                </div>
                <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
              </div>
              <div className="divide-y divide-kumo-line">
                <DetailRow label="Event">
                  <Mono>{selected.action}</Mono>
                </DetailRow>
                <DetailRow label="Outcome">
                  <Badge variant={selected.outcome === "success" ? "success" : "error"}>{selected.outcome === "success" ? "Succeeded" : "Failed"}</Badge>
                </DetailRow>
                <DetailRow label="Actor">
                  {selected.actor_label} <span className="text-kumo-subtle">({selected.actor_type.replace("_", " ")})</span>
                </DetailRow>
                <DetailRow label="Resource">
                  <Mono>
                    {selected.resource_type} {stripDot(selected.resource_name)}
                  </Mono>
                </DetailRow>
                {selected.org_name && <DetailRow label="Organization">{selected.org_name}</DetailRow>}
                <DetailRow label="IP address">
                  <Mono>{selected.ip || "None"}</Mono>
                </DetailRow>
                <DetailRow label="Client">{parseUA(selected.user_agent)}</DetailRow>
                <DetailRow label="Event ID">
                  <Mono>{selected.id}</Mono>
                </DetailRow>
              </div>
              <div className="mt-4 grid gap-2">
                <Text bold>Details</Text>
                <pre className="max-h-80 overflow-auto rounded-lg bg-kumo-recessed p-4 font-mono text-xs leading-relaxed text-kumo-default">
                  {JSON.stringify(selected.metadata, null, 2)}
                </pre>
              </div>
            </>
          )}
        </Dialog>
      </Dialog.Root>
    </LayerCard>
  );
}
