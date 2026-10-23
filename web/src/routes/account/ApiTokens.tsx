import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Code, Dialog, Input, LayerCard, TagInput, Tabs, Text } from "@cloudflare/kumo";
import { KeyIcon, PlusIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader, SecretDialog, ConfirmDialog, Mono } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useOrgId, useZones } from "../../lib/queries";
import { formatDate, stripDot, timeAgo } from "../../lib/format";
import { toast } from "../../lib/toast";
import { tokenRoleLabel, tokenRoles } from "../../lib/tokens";
import type { ApiToken, TokenRole } from "../../lib/types";

export default function ApiTokens() {
  const orgId = useOrgId();
  const qc = useQueryClient();
  const zones = useZones(orgId);
  const tokens = useQuery({ queryKey: keys.tokens(orgId), queryFn: () => api<ApiToken[]>(`/orgs/${orgId}/tokens`) });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState<TokenRole>("editor");
  const [zoneIds, setZoneIds] = useState<string[]>([]);
  const [ips, setIps] = useState<string[]>([]);
  const [expiry, setExpiry] = useState("90");
  const [secret, setSecret] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: keys.tokens(orgId) });

  const create = useMutation({
    mutationFn: () =>
      api<{ token: ApiToken; secret: string }>(`/orgs/${orgId}/tokens`, {
        method: "POST",
        body: { name, role, zone_ids: zoneIds, ip_allowlist: ips, expires_in_days: expiry === "never" ? 0 : Number(expiry) },
      }),
    onSuccess: (d) => {
      void refresh();
      setOpen(false);
      setSecret(d.secret);
      setName("");
      setZoneIds([]);
      setIps([]);
    },
  });
  const roll = useMutation({
    mutationFn: (t: ApiToken) => api<{ secret: string }>(`/orgs/${orgId}/tokens/${t.id}/roll`, { method: "POST" }),
    onSuccess: (d) => {
      void refresh();
      setSecret(d.secret);
    },
    onError: (e) => toast.error(e, "Could not roll token"),
  });
  const revoke = useMutation({
    mutationFn: (t: ApiToken) => api(`/orgs/${orgId}/tokens/${t.id}`, { method: "DELETE" }),
    onSuccess: () => {
      void refresh();
      setRevoking(null);
      toast.success("Token revoked");
    },
    onError: (e) => toast.error(e, "Could not revoke token"),
  });

  const zoneName = (id: string) => stripDot(zones.data?.find((z) => z.id === id)?.name ?? id);

  const columns: Column<ApiToken>[] = [
    {
      key: "name",
      header: "Token",
      width: "28%",
      render: (t) => (
        <div className="grid min-w-0">
          <span className="truncate font-medium text-kumo-strong">{t.name}</span>
          <Mono className="text-kumo-subtle">{t.prefix}...</Mono>
        </div>
      ),
    },
    { key: "role", header: "Permissions", width: "14%", render: (t) => <Badge variant="neutral">{tokenRoleLabel(t.role)}</Badge> },
    {
      key: "scope",
      header: "Zones",
      width: "18%",
      render: (t) => <span className="truncate text-kumo-subtle">{t.zone_ids ? t.zone_ids.map(zoneName).join(", ") : "All zones"}</span>,
    },
    {
      key: "used",
      header: "Last used",
      width: "16%",
      render: (t) => (
        <div className="grid min-w-0">
          <span className="text-kumo-subtle">{timeAgo(t.last_used_at)}</span>
          {t.last_used_ip && <Mono className="text-xs text-kumo-subtle">{t.last_used_ip}</Mono>}
        </div>
      ),
    },
    {
      key: "expires",
      header: "Expires",
      width: "14%",
      render: (t) =>
        t.expires_at ? (
          new Date(t.expires_at) < new Date() ? (
            <Badge variant="error">Expired</Badge>
          ) : (
            <span className="text-kumo-subtle">{formatDate(t.expires_at)}</span>
          )
        ) : (
          <span className="text-kumo-subtle">Never</span>
        ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "10%",
      align: "right",
      render: (t) => (
        <ActionMenu
          items={[
            { key: "roll", label: "Roll secret", onSelect: () => roll.mutate(t) },
            { key: "revoke", label: "Revoke", danger: true, separatorBefore: true, onSelect: () => setRevoking(t) },
          ]}
        />
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="API tokens"
        description="Tokens let automation such as Terraform, cert-manager or CI pipelines manage DNS in this organization."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => setOpen(true)}>
            Create token
          </Button>
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <VirtualTable
          ariaLabel="API tokens"
          rows={tokens.data ?? []}
          columns={columns}
          rowKey={(t) => t.id}
          loading={tokens.isLoading}
          rowHeight={60}
          empty={
            <div className="grid justify-items-center gap-2 px-5 py-12 text-center">
              <KeyIcon size={36} className="text-kumo-inactive" />
              <Text bold>No API tokens</Text>
              <Text variant="secondary">Create a scoped token for each integration so you can revoke them independently.</Text>
            </div>
          }
        />
      </LayerCard>

      <TokenUsage orgId={orgId} />

      <Dialog.Root open={open} onOpenChange={setOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Create API token</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <Input label="Token name" placeholder="terraform-production" value={name} onChange={(e) => setName(e.target.value)} autoFocus error={fieldError(create.error, "name")} />
            <VirtualSelect label="Permissions" options={tokenRoles} value={role} onChange={(v) => setRole(v as TokenRole)} />
            <VirtualSelect
              multiple
              label="Zone resources"
              description="Leave empty to include all zones, including ones added later."
              placeholder="All zones"
              options={(zones.data ?? []).map((z) => ({ value: z.id, label: stripDot(z.name) }))}
              value={zoneIds}
              onChange={setZoneIds}
              summarize={(s) => (s.length === 1 ? s[0].label : `${s.length} zones`)}
            />
            <TagInput
              label="Client IP address filtering"
              description="Optional. Only allow requests from these IPs or CIDR ranges."
              placeholder="203.0.113.0/24"
              value={ips}
              onValueChange={(v: string[]) => setIps(v)}
              error={fieldError(create.error, "ip_allowlist")}
            />
            <VirtualSelect
              label="Expiration"
              options={[
                { value: "7", label: "7 days" },
                { value: "30", label: "30 days" },
                { value: "90", label: "90 days" },
                { value: "365", label: "1 year" },
                { value: "never", label: "No expiration" },
              ]}
              value={expiry}
              onChange={setExpiry}
            />
            {create.error && !fieldError(create.error, "name") && <Banner variant="error" size="sm" description={errorMessage(create.error)} />}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button type="submit" variant="primary" loading={create.isPending} disabled={!name.trim()}>
                Create token
              </Button>
            </div>
          </form>
        </Dialog>
      </Dialog.Root>

      <SecretDialog
        open={!!secret}
        onOpenChange={(o) => !o && setSecret(null)}
        title="Your API token"
        description="Use this token in the Authorization header as a Bearer token."
        secret={secret ?? ""}
      />
      <ConfirmDialog
        open={!!revoking}
        onOpenChange={(o) => !o && setRevoking(null)}
        title="Revoke API token"
        description={`Integrations using "${revoking?.name}" will stop working immediately.`}
        confirmLabel="Revoke token"
        loading={revoke.isPending}
        onConfirm={() => revoking && revoke.mutate(revoking)}
      />
    </div>
  );
}

function TokenUsage({ orgId }: { orgId: string }) {
  const [tab, setTab] = useState("rest");
  const origin = window.location.origin;
  const host = window.location.host;
  return (
    <div className="mt-8 grid gap-3">
      <div className="grid gap-0.5">
        <Text variant="heading" as="h2">
          Using a token
        </Text>
        <Text variant="secondary">Tokens work with the Flare API, with tools built for the PowerDNS API, and with dynamic DNS clients.</Text>
      </div>
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="border-b border-kumo-line px-5 pt-2">
          <Tabs
            variant="underline"
            value={tab}
            onValueChange={setTab}
            tabs={[
              { value: "rest", label: "Flare API" },
              { value: "pdns", label: "PowerDNS-compatible API" },
              { value: "dyndns", label: "Dynamic DNS" },
            ]}
          />
        </div>
        <div className="grid gap-3 px-5 py-4">
          {tab === "rest" && (
            <>
              <Text variant="secondary">Send the token as a bearer token. Every request is scoped to this organization and recorded in the audit log.</Text>
              <Code lang="bash" code={`curl -H "Authorization: Bearer $FLARE_TOKEN" \\\n  ${origin}/api/v1/orgs/${orgId}/zones`} />
            </>
          )}
          {tab === "pdns" && (
            <>
              <Text variant="secondary">
                Point tools written for the PowerDNS HTTP API, such as cert-manager, external-dns, octoDNS or Terraform, at Flare. The token only sees zones it is scoped to, and
                changes are validated and audited.
              </Text>
              <Code lang="bash" code={`# Base URL and server ID\nPDNS_API_URL=${origin}\nPDNS_SERVER_ID=localhost\n\ncurl -H "X-API-Key: $FLARE_TOKEN" ${origin}/api/v1/servers/localhost/zones`} />
            </>
          )}
          {tab === "dyndns" && (
            <>
              <Text variant="secondary">
                Routers and ddclient can update A and AAAA records with the dyndns2 protocol. Use any username and the token as the password. The token needs the Editor role.
              </Text>
              <Code lang="bash" code={`curl -u "flare:$FLARE_TOKEN" \\\n  "${origin}/nic/update?hostname=home.example.com&myip=203.0.113.7"`} />
              <Code lang="bash" code={`# ddclient.conf\nprotocol=dyndns2\nserver=${host}\nssl=yes\nlogin=flare\npassword=YOUR_TOKEN\nhome.example.com`} />
            </>
          )}
        </div>
      </LayerCard>
    </div>
  );
}
