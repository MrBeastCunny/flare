import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, ClipboardText, Input, SensitiveInput, Switch, Tabs, TagInput, Text, LayerCard } from "@cloudflare/kumo";
import { PlusIcon, TrashIcon, CheckCircleIcon, ClockIcon, ShieldCheckIcon } from "@phosphor-icons/react";
import { PageHeader, Section, ConfirmDialog, SecretDialog, Mono, DetailRow } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { VirtualList } from "../../components/VirtualList";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useOrgId } from "../../lib/queries";
import { roleLabels, timeAgo } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { Role, RoleMapping, SCIMGroup, SCIMToken, SSOConnection, SSODomain } from "../../lib/types";

interface SSOResponse {
  connection: SSOConnection | null;
  domains: SSODomain[];
  redirect_uri: string;
  login_url: string;
}

const assignable: Role[] = ["admin", "editor", "viewer", "auditor"];
const roleOptions = assignable.map((r) => ({ value: r, label: roleLabels[r] }));

function ConnectionForm({ orgId, data }: { orgId: string; data: SSOResponse }) {
  const qc = useQueryClient();
  const c = data.connection;
  const [form, setForm] = useState({
    name: "",
    issuer: "",
    client_id: "",
    client_secret: "",
    scopes: ["openid", "email", "profile"],
    groups_claim: "groups",
    default_role: "viewer" as Role,
    jit_provisioning: true,
    enforce_sso: false,
    enabled: true,
  });
  const [mappings, setMappings] = useState<RoleMapping[]>([]);
  const [removing, setRemoving] = useState(false);

  useEffect(() => {
    if (c) {
      setForm({
        name: c.name,
        issuer: c.issuer,
        client_id: c.client_id,
        client_secret: "",
        scopes: c.scopes,
        groups_claim: c.groups_claim,
        default_role: c.default_role,
        jit_provisioning: c.jit_provisioning,
        enforce_sso: c.enforce_sso,
        enabled: c.enabled,
      });
      setMappings(c.role_mappings);
    }
  }, [c]);

  const save = useMutation({
    mutationFn: () => api<SSOConnection>(`/orgs/${orgId}/sso`, { method: "PUT", body: { ...form, role_mappings: mappings.filter((m) => m.group.trim()) } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.sso(orgId) });
      toast.success("Single sign-on saved");
    },
  });
  const del = useMutation({
    mutationFn: () => api(`/orgs/${orgId}/sso`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.sso(orgId) });
      setRemoving(false);
      toast.success("Single sign-on removed");
    },
  });
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));
  const verified = data.domains.some((d) => d.verified_at);

  return (
    <div className="grid gap-6">
      <Section title="Identity provider details" description="Register an OpenID Connect application in Okta, Microsoft Entra ID, Google Workspace, Keycloak or Authentik with these values.">
        <div className="divide-y divide-kumo-line">
          <DetailRow label="Redirect URI">
            <ClipboardText text={data.redirect_uri} size="sm" />
          </DetailRow>
          {data.login_url && (
            <DetailRow label="Direct sign-in URL">
              <ClipboardText text={data.login_url} size="sm" />
            </DetailRow>
          )}
        </div>
      </Section>

      <Section
        title="OpenID Connect"
        description="Members sign in through your identity provider. Accounts are matched by verified email domain."
        actions={c ? <Badge variant={c.enabled ? "success" : "neutral"}>{c.enabled ? "Enabled" : "Disabled"}</Badge> : undefined}
        footer={
          <>
            {c && (
              <Button variant="secondary-destructive" icon={<TrashIcon />} onClick={() => setRemoving(true)} className="mr-auto">
                Remove connection
              </Button>
            )}
            <Button variant="primary" loading={save.isPending} onClick={() => save.mutate()}>
              Save connection
            </Button>
          </>
        }
      >
        <div className="grid gap-4">
          {save.error && Object.keys((save.error as { fields?: object }).fields ?? {}).length === 0 && (
            <Banner variant="error" size="sm" description={errorMessage(save.error)} />
          )}
          <div className="grid gap-4 md:grid-cols-2">
            <Input label="Display name" placeholder="Okta" value={form.name} onChange={(e) => set("name", e.target.value)} />
            <Input
              label="Issuer URL"
              placeholder="https://company.okta.com"
              value={form.issuer}
              onChange={(e) => set("issuer", e.target.value)}
              error={fieldError(save.error, "issuer")}
            />
            <Input label="Client ID" value={form.client_id} onChange={(e) => set("client_id", e.target.value)} error={fieldError(save.error, "client_id")} />
            <SensitiveInput
              label="Client secret"
              placeholder={c ? "Leave blank to keep the current secret" : ""}
              value={form.client_secret}
              onValueChange={(v: string) => set("client_secret", v)}
              error={fieldError(save.error, "client_secret")}
            />
          </div>
          <TagInput label="Scopes" value={form.scopes} onValueChange={(v: string[]) => set("scopes", v)} description="Add a groups scope if your provider requires one." />
          <div className="grid gap-4 md:grid-cols-2">
            <Input label="Groups claim" value={form.groups_claim} onChange={(e) => set("groups_claim", e.target.value)} description="Claim containing the user's groups." />
            <VirtualSelect
              label="Default role"
              description="Used when no group mapping matches."
              options={roleOptions}
              value={form.default_role}
              onChange={(v) => set("default_role", v as Role)}
              error={fieldError(save.error, "default_role")}
            />
          </div>

          <div className="grid gap-2">
            <Text bold>Group to role mappings</Text>
            <Text variant="secondary" size="sm">
              The highest matching role is applied each time a member signs in. Owners are never changed automatically.
            </Text>
            <div className="grid gap-2">
              <VirtualList
                ariaLabel="Group to role mappings"
                items={mappings.map((m, i) => ({ ...m, i }))}
                itemKey={(m) => String(m.i)}
                divided={false}
                gap={8}
                estimateSize={44}
                maxHeight={400}
                renderItem={(m) => {
                  const i = m.i;
                  return (
                <div className="grid grid-cols-[1fr_200px_auto] items-start gap-2">
                  <Input
                    aria-label="Group"
                    placeholder="dns-admins"
                    value={m.group}
                    onChange={(e) => setMappings(mappings.map((x, j) => (j === i ? { ...x, group: e.target.value } : x)))}
                  />
                  <VirtualSelect aria-label="Role" options={roleOptions} value={m.role} onChange={(v) => setMappings(mappings.map((x, j) => (j === i ? { ...x, role: v as Role } : x)))} />
                  <Button variant="ghost" shape="square" icon={<TrashIcon />} aria-label="Remove mapping" onClick={() => setMappings(mappings.filter((_, j) => j !== i))} />
                </div>
                  );
                }}
              />
              <div>
                <Button size="sm" icon={<PlusIcon />} onClick={() => setMappings([...mappings, { group: "", role: "viewer" }])}>
                  Add mapping
                </Button>
              </div>
              {fieldError(save.error, "role_mappings") && <Text variant="error">{fieldError(save.error, "role_mappings")}</Text>}
            </div>
          </div>

          <div className="grid gap-3 border-t border-kumo-line pt-4">
            <Switch label="Enable this connection" checked={form.enabled} onCheckedChange={(v: boolean) => set("enabled", v)} />
            <Switch
              label="Just-in-time provisioning: create members automatically on first sign-in"
              checked={form.jit_provisioning}
              onCheckedChange={(v: boolean) => set("jit_provisioning", v)}
            />
            <Switch
              label="Require single sign-on for verified domains (password sign-in is blocked)"
              checked={form.enforce_sso}
              disabled={!verified}
              onCheckedChange={(v: boolean) => set("enforce_sso", v)}
            />
            {!verified && <Text variant="secondary" size="sm">Verify a domain before enforcing single sign-on.</Text>}
            {fieldError(save.error, "enforce_sso") && <Text variant="error">{fieldError(save.error, "enforce_sso")}</Text>}
          </div>
        </div>
      </Section>
      <ConfirmDialog
        open={removing}
        onOpenChange={setRemoving}
        title="Remove single sign-on"
        description="Members will need a password to sign in. Members without a password must use the reset password flow."
        confirmLabel="Remove connection"
        loading={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}

function Domains({ orgId, domains }: { orgId: string; domains: SSODomain[] }) {
  const qc = useQueryClient();
  const [domain, setDomain] = useState("");
  const refresh = () => qc.invalidateQueries({ queryKey: keys.sso(orgId) });
  const add = useMutation({
    mutationFn: () => api(`/orgs/${orgId}/sso/domains`, { method: "POST", body: { domain } }),
    onSuccess: () => {
      setDomain("");
      void refresh();
    },
  });
  const verify = useMutation({
    mutationFn: (d: SSODomain) => api(`/orgs/${orgId}/sso/domains/${d.id}/verify`, { method: "POST" }),
    onSuccess: () => {
      void refresh();
      toast.success("Domain verified");
    },
    onError: (e) => toast.error(e, "Not verified yet"),
  });
  const remove = useMutation({
    mutationFn: (d: SSODomain) => api(`/orgs/${orgId}/sso/domains/${d.id}`, { method: "DELETE" }),
    onSuccess: () => void refresh(),
    onError: (e) => toast.error(e),
  });

  const columns: Column<SSODomain>[] = [
    { key: "domain", header: "Domain", width: "26%", render: (d) => <span className="font-medium">{d.domain}</span> },
    {
      key: "status",
      header: "Status",
      width: "16%",
      render: (d) =>
        d.verified_at ? (
          <Badge variant="success" icon={<CheckCircleIcon />}>
            Verified
          </Badge>
        ) : (
          <Badge variant="warning" icon={<ClockIcon />}>
            Unverified
          </Badge>
        ),
    },
    {
      key: "record",
      header: "Verification record",
      render: (d) =>
        d.verified_at ? (
          <span className="text-kumo-subtle">Verified {timeAgo(d.verified_at)}</span>
        ) : (
          <Mono className="text-kumo-subtle">
            TXT _flare-challenge.{d.domain} "{d.verification_token}"
          </Mono>
        ),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "130px",
      align: "right",
      render: (d) => (
        <div className="flex items-center justify-end gap-1">
          {!d.verified_at && (
            <Button size="sm" loading={verify.isPending && verify.variables?.id === d.id} onClick={() => verify.mutate(d)}>
              Verify
            </Button>
          )}
          <ActionMenu items={[{ key: "remove", label: "Remove domain", danger: true, onSelect: () => remove.mutate(d) }]} />
        </div>
      ),
    },
  ];

  return (
    <Section
      padded={false}
      title="Verified domains"
      description="Users with email addresses on these domains are routed to your identity provider. Add a TXT record to prove ownership. Domains active in this organization are verified automatically."
    >
      <form
        className="flex flex-wrap items-start gap-2 border-b border-kumo-line px-5 py-4"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate();
        }}
      >
        <Input aria-label="Domain" placeholder="company.com" value={domain} onChange={(e) => setDomain(e.target.value)} className="w-72" error={fieldError(add.error, "domain")} />
        <Button type="submit" icon={<PlusIcon />} loading={add.isPending} disabled={!domain.includes(".")}>
          Add domain
        </Button>
      </form>
      <VirtualTable
        ariaLabel="SSO domains"
        rows={domains}
        columns={columns}
        rowKey={(d) => d.id}
        empty={<div className="px-5 py-10 text-center text-kumo-subtle">No domains yet.</div>}
        maxHeight="360px"
      />
    </Section>
  );
}

function Scim({ orgId }: { orgId: string }) {
  const qc = useQueryClient();
  const scim = useQuery({ queryKey: keys.scim(orgId), queryFn: () => api<{ tokens: SCIMToken[]; groups: SCIMGroup[]; base_url: string }>(`/orgs/${orgId}/scim`) });
  const [name, setName] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: keys.scim(orgId) });
  const create = useMutation({
    mutationFn: () => api<{ secret: string }>(`/orgs/${orgId}/scim/tokens`, { method: "POST", body: { name } }),
    onSuccess: (d) => {
      setSecret(d.secret);
      setName("");
      void refresh();
    },
    onError: (e) => toast.error(e),
  });
  const revoke = useMutation({
    mutationFn: (t: SCIMToken) => api(`/orgs/${orgId}/scim/tokens/${t.id}`, { method: "DELETE" }),
    onSuccess: () => void refresh(),
    onError: (e) => toast.error(e),
  });
  const setRole = useMutation({
    mutationFn: ({ g, role }: { g: SCIMGroup; role: string }) =>
      api(`/orgs/${orgId}/scim/groups/${g.id}/role`, { method: "PUT", body: { role: role === "none" ? null : role } }),
    onSuccess: () => {
      void refresh();
      void qc.invalidateQueries({ queryKey: keys.members(orgId) });
      toast.success("Group role updated");
    },
    onError: (e) => toast.error(e),
  });

  const tokenCols: Column<SCIMToken>[] = [
    { key: "name", header: "Name", width: "34%", render: (t) => <span className="font-medium">{t.name}</span> },
    { key: "prefix", header: "Token", width: "22%", render: (t) => <Mono className="text-kumo-subtle">{t.prefix}...</Mono> },
    { key: "used", header: "Last used", width: "22%", render: (t) => <span className="text-kumo-subtle">{timeAgo(t.last_used_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "22%",
      align: "right",
      render: (t) => <ActionMenu items={[{ key: "revoke", label: "Revoke", danger: true, onSelect: () => revoke.mutate(t) }]} />,
    },
  ];
  const groupCols: Column<SCIMGroup>[] = [
    { key: "name", header: "Group", width: "40%", render: (g) => <span className="font-medium">{g.display_name}</span> },
    { key: "members", header: "Members", width: "20%", render: (g) => <span className="text-kumo-subtle">{g.member_ids.length}</span> },
    {
      key: "role",
      header: "Grants role",
      width: "40%",
      render: (g) => (
        <div onClick={(e) => e.stopPropagation()}>
          <VirtualSelect
            aria-label={`Role for ${g.display_name}`}
            size="sm"
            options={[{ value: "none", label: "Use SSO mappings" }, ...roleOptions]}
            value={g.role ?? "none"}
            onChange={(v) => setRole.mutate({ g, role: v })}
          />
        </div>
      ),
    },
  ];

  return (
    <div className="grid gap-6">
      <Section title="SCIM endpoint" description="Configure your identity provider to provision and deprovision members automatically.">
        <div className="divide-y divide-kumo-line">
          <DetailRow label="SCIM base URL">
            <ClipboardText text={scim.data?.base_url ?? ""} size="sm" />
          </DetailRow>
          <DetailRow label="Authentication">HTTP header, Bearer token</DetailRow>
          <DetailRow label="Supported">Users (create, update, deactivate, delete) and Groups (membership drives roles)</DetailRow>
        </div>
      </Section>
      <Section padded={false} title="Provisioning tokens">
        <form
          className="flex flex-wrap items-start gap-2 border-b border-kumo-line px-5 py-4"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Input aria-label="Token name" placeholder="Okta provisioning" value={name} onChange={(e) => setName(e.target.value)} className="w-72" />
          <Button type="submit" icon={<PlusIcon />} loading={create.isPending} disabled={!name.trim()}>
            Generate token
          </Button>
        </form>
        <VirtualTable
          ariaLabel="SCIM tokens"
          rows={scim.data?.tokens ?? []}
          columns={tokenCols}
          rowKey={(t) => t.id}
          loading={scim.isLoading}
          maxHeight="300px"
          empty={<div className="px-5 py-8 text-center text-kumo-subtle">No tokens yet.</div>}
        />
      </Section>
      <Section padded={false} title="Provisioned groups" description="Groups pushed by your identity provider. Assign a role to grant it to every member of the group.">
        <VirtualTable
          ariaLabel="SCIM groups"
          rows={scim.data?.groups ?? []}
          columns={groupCols}
          rowKey={(g) => g.id}
          loading={scim.isLoading}
          maxHeight="420px"
          empty={<div className="px-5 py-8 text-center text-kumo-subtle">No groups have been pushed yet.</div>}
        />
      </Section>
      <SecretDialog
        open={!!secret}
        onOpenChange={(o) => !o && setSecret(null)}
        title="SCIM token"
        description="Paste this token into your identity provider's provisioning settings."
        secret={secret ?? ""}
      />
    </div>
  );
}

export default function SSO() {
  const orgId = useOrgId();
  const [tab, setTab] = useState("sso");
  const sso = useQuery({ queryKey: keys.sso(orgId), queryFn: () => api<SSOResponse>(`/orgs/${orgId}/sso`) });

  return (
    <div>
      <PageHeader title="Single sign-on" description="Centralize authentication and user lifecycle with your identity provider." />
      <div className="mb-6 flex flex-wrap items-center gap-4">
        <Tabs
          variant="underline"
          value={tab}
          onValueChange={setTab}
          tabs={[
            { value: "sso", label: "OpenID Connect" },
            { value: "domains", label: `Domains (${sso.data?.domains.length ?? 0})` },
            { value: "scim", label: "SCIM provisioning" },
          ]}
        />
      </div>
      {sso.data?.connection?.enforce_sso && (
        <LayerCard className="mb-6 flex items-center gap-3 px-5 py-3">
          <ShieldCheckIcon size={20} weight="fill" className="text-kumo-success" />
          <Text>Single sign-on is enforced for verified domains.</Text>
        </LayerCard>
      )}
      {sso.isLoading ? null : sso.error ? (
        <Banner variant="error" description={errorMessage(sso.error)} />
      ) : tab === "sso" ? (
        <ConnectionForm orgId={orgId} data={sso.data!} />
      ) : tab === "domains" ? (
        <Domains orgId={orgId} domains={sso.data!.domains} />
      ) : (
        <Scim orgId={orgId} />
      )}
    </div>
  );
}
