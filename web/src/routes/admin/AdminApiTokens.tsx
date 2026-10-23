import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Code, Dialog, Input, LayerCard, TagInput, Tabs, Text } from "@cloudflare/kumo";
import { KeyIcon, PlusIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader, SecretDialog, ConfirmDialog, Mono } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys } from "../../lib/queries";
import { formatDate, timeAgo } from "../../lib/format";
import { instanceRoleLabel, instanceRoles, tokenRoleLabel, tokenRoles } from "../../lib/tokens";
import { toast } from "../../lib/toast";
import type { AdminOrg, ApiToken, InstanceRole, TokenRole } from "../../lib/types";

export default function AdminApiTokens() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: keys.admin("tokens"), queryFn: () => api<ApiToken[]>("/admin/tokens") });
  const orgs = useQuery({ queryKey: keys.admin("orgs"), queryFn: () => api<AdminOrg[]>("/admin/orgs") });
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState<TokenRole>("editor");
  const [instanceRole, setInstanceRole] = useState<InstanceRole>("none");
  const [orgIds, setOrgIds] = useState<string[]>([]);
  const [ips, setIps] = useState<string[]>([]);
  const [expiry, setExpiry] = useState("90");
  const [secret, setSecret] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);

  const refresh = () => qc.invalidateQueries({ queryKey: keys.admin("tokens") });

  const create = useMutation({
    mutationFn: () =>
      api<{ token: ApiToken; secret: string }>("/admin/tokens", {
        method: "POST",
        body: { name, role, instance_role: instanceRole, org_ids: orgIds, ip_allowlist: ips, expires_in_days: expiry === "never" ? 0 : Number(expiry) },
      }),
    onSuccess: (d) => {
      void refresh();
      setOpen(false);
      setSecret(d.secret);
      setName("");
      setOrgIds([]);
      setIps([]);
      setInstanceRole("none");
    },
  });
  const roll = useMutation({
    mutationFn: (t: ApiToken) => api<{ secret: string }>(`/admin/tokens/${t.id}/roll`, { method: "POST" }),
    onSuccess: (d) => {
      void refresh();
      setSecret(d.secret);
    },
    onError: (e) => toast.error(e, "Could not roll token"),
  });
  const revoke = useMutation({
    mutationFn: (t: ApiToken) => api(`/admin/tokens/${t.id}`, { method: "DELETE" }),
    onSuccess: () => {
      void refresh();
      setRevoking(null);
      toast.success("Token revoked");
    },
    onError: (e) => toast.error(e, "Could not revoke token"),
  });

  const orgName = (id: string) => orgs.data?.find((o) => o.id === id)?.name ?? "Deleted organization";

  const columns: Column<ApiToken>[] = [
    {
      key: "name",
      header: "Token",
      width: "24%",
      render: (t) => (
        <div className="grid min-w-0">
          <span className="truncate font-medium text-kumo-strong">{t.name}</span>
          <Mono className="text-kumo-subtle">{t.prefix}...</Mono>
        </div>
      ),
    },
    {
      key: "orgs",
      header: "Organizations",
      width: "22%",
      render: (t) => (
        <div className="grid min-w-0">
          <span className="truncate">{t.org_ids ? t.org_ids.map(orgName).join(", ") : "All organizations"}</span>
          <span className="truncate text-sm text-kumo-subtle">{tokenRoleLabel(t.role)}</span>
        </div>
      ),
    },
    {
      key: "instance",
      header: "Instance access",
      width: "18%",
      render: (t) =>
        t.instance_role === "none" ? (
          <span className="text-kumo-subtle">None</span>
        ) : (
          <Badge variant={t.instance_role === "admin" ? "primary" : "neutral"}>{instanceRoleLabel(t.instance_role)}</Badge>
        ),
    },
    {
      key: "used",
      header: "Last used",
      width: "14%",
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
      width: "8%",
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
        description="Global tokens work across organizations. Use them for automation that provisions tenants or manages DNS for several organizations."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => setOpen(true)}>
            Create token
          </Button>
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <VirtualTable
          ariaLabel="Global API tokens"
          rows={tokens.data ?? []}
          columns={columns}
          rowKey={(t) => t.id}
          loading={tokens.isLoading}
          rowHeight={60}
          minWidth={860}
          empty={
            <div className="grid justify-items-center gap-2 px-5 py-12 text-center">
              <KeyIcon size={36} className="text-kumo-inactive" />
              <Text bold>No global API tokens</Text>
              <Text variant="secondary">Tokens for a single organization are created on that organization's API tokens page.</Text>
            </div>
          }
        />
      </LayerCard>

      <GlobalTokenUsage />

      <Dialog.Root open={open} onOpenChange={setOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Create global API token</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <Input label="Token name" placeholder="tenant-provisioning" value={name} onChange={(e) => setName(e.target.value)} autoFocus error={fieldError(create.error, "name")} />
            <VirtualSelect
              multiple
              label="Organizations"
              description="Leave empty to include every organization, including ones created later."
              placeholder="All organizations"
              options={(orgs.data ?? []).map((o) => ({ value: o.id, label: o.name, description: o.slug }))}
              value={orgIds}
              onChange={setOrgIds}
              summarize={(s) => (s.length === 1 ? s[0].label : `${s.length} organizations`)}
            />
            <VirtualSelect label="Permissions in each organization" options={tokenRoles} value={role} onChange={(v) => setRole(v as TokenRole)} />
            <VirtualSelect
              label="Instance access"
              options={instanceRoles}
              value={instanceRole}
              onChange={(v) => setInstanceRole(v as InstanceRole)}
              error={fieldError(create.error, "instance_role")}
            />
            {instanceRole === "admin" && (
              <Banner
                variant="alert"
                size="sm"
                description="This token can manage servers, users and instance settings, and reaches suspended or IP-restricted organizations. Limit it to known IP addresses."
              />
            )}
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
        title="Your global API token"
        description="Use this token in the Authorization header as a Bearer token, or in X-API-Key for PowerDNS clients."
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

function GlobalTokenUsage() {
  const [tab, setTab] = useState("rest");
  const origin = window.location.origin;
  return (
    <div className="mt-8 grid gap-3">
      <div className="grid gap-0.5">
        <Text variant="heading" as="h2">
          Using a global token
        </Text>
        <Text variant="secondary">Global tokens use the same endpoints as organization tokens. They pick the organization from the request.</Text>
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
              { value: "orgs", label: "Organization management" },
            ]}
          />
        </div>
        <div className="grid gap-3 px-5 py-4">
          {tab === "rest" && (
            <>
              <Text variant="secondary">List the organizations the token can use, then call any organization endpoint with its ID.</Text>
              <Code
                lang="bash"
                code={`curl -H "Authorization: Bearer $FLARE_TOKEN" ${origin}/api/v1/orgs\n\ncurl -H "Authorization: Bearer $FLARE_TOKEN" \\\n  ${origin}/api/v1/orgs/$ORG_ID/zones`}
              />
            </>
          )}
          {tab === "pdns" && (
            <>
              <Text variant="secondary">
                Zones in every organization the token can use are listed, with the organization slug in <Mono className="text-[0.9em]">account</Mono>. To create a zone, set{" "}
                <Mono className="text-[0.9em]">account</Mono> to the organization slug or ID; it can be left out when the token is limited to one organization.
              </Text>
              <Code
                lang="bash"
                code={`curl -X POST -H "X-API-Key: $FLARE_TOKEN" -H "Content-Type: application/json" \\\n  -d '{"name": "example.com.", "kind": "Native", "account": "acme"}' \\\n  ${origin}/api/v1/servers/localhost/zones`}
              />
            </>
          )}
          {tab === "orgs" && (
            <>
              <Text variant="secondary">Tokens with Manage organizations or Full administrator access can create organizations and set their limits. The owner must be an existing user.</Text>
              <Code
                lang="bash"
                code={`curl -X POST -H "Authorization: Bearer $FLARE_TOKEN" -H "Content-Type: application/json" \\\n  -d '{"name": "Acme Corp", "owner_email": "ops@acme.example"}' \\\n  ${origin}/api/v1/admin/orgs`}
              />
            </>
          )}
        </div>
      </LayerCard>
    </div>
  );
}
