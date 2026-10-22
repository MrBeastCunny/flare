import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input, SensitiveInput, Switch, Tabs, Text, InputArea } from "@cloudflare/kumo";
import { VirtualList } from "../../components/VirtualList";
import { EnvelopeSimpleIcon, PlusIcon, TrashIcon } from "@phosphor-icons/react";
import { PageHeader, Section } from "../../components/ui";
import { VirtualSelect } from "../../components/VirtualSelect";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys } from "../../lib/queries";
import { toast } from "../../lib/toast";
import type { AdminOrg, InstanceSettings, LDAPSettings, Role } from "../../lib/types";
import { recordTypes } from "../../lib/dns";
import { roleLabels } from "../../lib/format";
import type { UseMutationResult } from "@tanstack/react-query";

const allTypes = recordTypes.map((t) => ({ value: t.type, label: t.type, description: t.description }));
const assignableRoles: Role[] = ["admin", "editor", "viewer", "auditor"];

function LdapSettings({
  s,
  set,
  save,
}: {
  s: InstanceSettings;
  set: <K extends keyof InstanceSettings>(k: K, v: InstanceSettings[K]) => void;
  save: UseMutationResult<InstanceSettings, Error, Record<string, unknown>>;
}) {
  const l = s.ldap;
  const upd = (patch: Partial<LDAPSettings>) => set("ldap", { ...l, ...patch });
  const [bindPassword, setBindPassword] = useState<string | undefined>(undefined);
  const [testUser, setTestUser] = useState("");
  const [testPass, setTestPass] = useState("");
  const orgs = useQuery({ queryKey: keys.admin("orgs"), queryFn: () => api<AdminOrg[]>("/admin/orgs") });
  const test = useMutation({
    mutationFn: () =>
      api<{ ok: boolean; error?: string; dn?: string; email?: string; name?: string; groups?: string[]; admin?: boolean }>("/admin/settings/test-ldap", {
        method: "POST",
        body: { username: testUser, password: testPass },
      }),
  });
  const fe = (f: string) => fieldError(save.error, f);
  return (
    <div className="grid gap-6">
      <Section
        title="LDAP and Active Directory"
        description="Let directory users sign in with their username and password. Accounts are created on first sign-in."
        footer={
          <Button
            variant="primary"
            loading={save.isPending}
            onClick={() => save.mutate({ ldap: { ...l, group_roles: l.group_roles ?? [], bind_password: bindPassword } })}
          >
            Save changes
          </Button>
        }
      >
        <div className="grid gap-4">
          <Switch label="Enable directory sign-in" checked={l.enabled} onCheckedChange={(v: boolean) => upd({ enabled: v })} />
          <div className="grid gap-4 md:grid-cols-2">
            <Input label="Server URL" placeholder="ldaps://dc1.corp.example.com:636" value={l.url} onChange={(e) => upd({ url: e.target.value })} error={fe("ldap.url")} />
            <Input label="Search base DN" placeholder="dc=corp,dc=example,dc=com" value={l.base_dn} onChange={(e) => upd({ base_dn: e.target.value })} error={fe("ldap.base_dn")} />
            <Input label="Bind DN" required={false} placeholder="cn=flare,ou=services,dc=corp,dc=example,dc=com" value={l.bind_dn} onChange={(e) => upd({ bind_dn: e.target.value })} />
            <SensitiveInput
              label="Bind password"
              placeholder={l.bind_password_set ? "Unchanged" : ""}
              value={bindPassword ?? ""}
              onValueChange={(v: string) => setBindPassword(v)}
            />
          </div>
          <Input
            label="User filter"
            description="{username} is replaced with what the user types. The default matches OpenLDAP uid, email and Active Directory sAMAccountName."
            value={l.user_filter}
            onChange={(e) => upd({ user_filter: e.target.value })}
            className="font-mono"
            error={fe("ldap.user_filter")}
          />
          <div className="grid gap-4 md:grid-cols-3">
            <Input label="Email attribute" value={l.email_attribute} onChange={(e) => upd({ email_attribute: e.target.value })} />
            <Input label="Name attribute" value={l.name_attribute} onChange={(e) => upd({ name_attribute: e.target.value })} />
            <Input label="Group attribute" value={l.group_attribute} onChange={(e) => upd({ group_attribute: e.target.value })} />
          </div>
          <div className="flex flex-wrap gap-x-6 gap-y-3">
            <Switch label="Use StartTLS" checked={l.start_tls} onCheckedChange={(v: boolean) => upd({ start_tls: v })} />
            <Switch label="Skip certificate verification (lab only)" checked={l.insecure_skip_verify} onCheckedChange={(v: boolean) => upd({ insecure_skip_verify: v })} />
          </div>
        </div>
      </Section>
      <Section title="Access" description="Where directory users land and what they can do.">
        <div className="grid gap-4">
          <Input
            label="Instance administrator group DN"
            required={false}
            placeholder="cn=dns-admins,ou=groups,dc=corp,dc=example,dc=com"
            value={l.admin_group_dn}
            onChange={(e) => upd({ admin_group_dn: e.target.value })}
          />
          <div className="grid gap-4 md:grid-cols-2">
            <VirtualSelect
              label="Default organization"
              description="Directory users join this organization on first sign-in."
              options={[{ value: "", label: "None" }, ...(orgs.data ?? []).map((o) => ({ value: o.id, label: o.name }))]}
              value={l.default_org_id ?? ""}
              onChange={(v) => upd({ default_org_id: v || null })}
              error={fe("ldap.default_org_id")}
            />
            <VirtualSelect
              label="Default role"
              options={assignableRoles.map((r) => ({ value: r, label: roleLabels[r] }))}
              value={l.default_role || "viewer"}
              onChange={(v) => upd({ default_role: v as Role })}
              error={fe("ldap.default_role")}
            />
          </div>
          <div className="grid gap-2">
            <Text bold>Group to role mappings</Text>
            <VirtualList
              ariaLabel="LDAP group mappings"
              items={(l.group_roles ?? []).map((m, i) => ({ ...m, i }))}
              itemKey={(m) => String(m.i)}
              divided={false}
              gap={8}
              estimateSize={44}
              maxHeight={300}
              renderItem={(m) => (
                <div className="grid grid-cols-[minmax(0,1fr)_180px_36px] gap-2">
                  <Input
                    aria-label="Group DN"
                    placeholder="cn=dns-editors,ou=groups,dc=corp,dc=example,dc=com"
                    value={m.group}
                    onChange={(e) => upd({ group_roles: l.group_roles.map((x, j) => (j === m.i ? { ...x, group: e.target.value } : x)) })}
                  />
                  <VirtualSelect
                    aria-label="Role"
                    options={assignableRoles.map((r) => ({ value: r, label: roleLabels[r] }))}
                    value={m.role}
                    onChange={(v) => upd({ group_roles: l.group_roles.map((x, j) => (j === m.i ? { ...x, role: v as Role } : x)) })}
                  />
                  <Button
                    variant="ghost"
                    shape="square"
                    icon={<TrashIcon />}
                    aria-label="Remove mapping"
                    onClick={() => upd({ group_roles: l.group_roles.filter((_, j) => j !== m.i) })}
                  />
                </div>
              )}
            />
            <div>
              <Button size="sm" icon={<PlusIcon />} onClick={() => upd({ group_roles: [...(l.group_roles ?? []), { group: "", role: "editor" }] })}>
                Add mapping
              </Button>
            </div>
          </div>
        </div>
      </Section>
      <Section title="Test the connection" description="Save first, then sign in as a directory user to check the configuration.">
        <div className="grid gap-4">
          <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] md:items-end">
            <Input label="Username" value={testUser} onChange={(e) => setTestUser(e.target.value)} autoComplete="off" />
            <Input label="Password" type="password" value={testPass} onChange={(e) => setTestPass(e.target.value)} autoComplete="new-password" />
            <Button loading={test.isPending} disabled={!testUser || !testPass} onClick={() => test.mutate()}>
              Test sign-in
            </Button>
          </div>
          {test.data?.ok && (
            <Banner
              variant="default"
              size="sm"
              title={`Found ${test.data.email}`}
              description={`${test.data.dn}. ${test.data.groups?.length ?? 0} groups${test.data.admin ? ", instance administrator" : ""}.`}
            />
          )}
          {test.data && !test.data.ok && <Banner variant="error" size="sm" description={test.data.error} />}
        </div>
      </Section>
    </div>
  );
}

export default function Settings() {
  const qc = useQueryClient();
  const settings = useQuery({ queryKey: keys.admin("settings"), queryFn: () => api<InstanceSettings>("/admin/settings") });
  const [tab, setTab] = useState("general");
  const [s, setS] = useState<InstanceSettings | null>(null);
  const [smtpPassword, setSmtpPassword] = useState<string | undefined>(undefined);

  useEffect(() => {
    if (settings.data) setS(settings.data);
  }, [settings.data]);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => api<InstanceSettings>("/admin/settings", { method: "PATCH", body }),
    onSuccess: (d) => {
      qc.setQueryData(keys.admin("settings"), d);
      void qc.invalidateQueries({ queryKey: keys.config });
      void qc.invalidateQueries({ queryKey: ["me"] });
      setSmtpPassword(undefined);
      toast.success("Settings saved");
    },
  });
  const testEmail = useMutation({
    mutationFn: () => api<{ ok: boolean; error?: string; to?: string }>("/admin/settings/test-email", { method: "POST" }),
    onSuccess: (d) => (d.ok ? toast.success("Test email sent", `Check ${d.to}`) : toast.error(new Error(d.error), "Email failed")),
  });

  if (!s) return null;
  const set = <K extends keyof InstanceSettings>(k: K, v: InstanceSettings[K]) => setS({ ...s, [k]: v });
  const err = save.error && Object.keys((save.error as { fields?: object }).fields ?? {}).length === 0 ? errorMessage(save.error) : null;
  const saveButton = (body: () => Record<string, unknown>) => (
    <Button variant="primary" loading={save.isPending} onClick={() => save.mutate(body())}>
      Save changes
    </Button>
  );

  return (
    <div className="max-w-4xl">
      <PageHeader title="Instance settings" description="Global configuration that applies to every organization." />
      <div className="mb-6">
        <Tabs
          variant="underline"
          value={tab}
          onValueChange={setTab}
          tabs={[
            { value: "general", label: "General" },
            { value: "security", label: "Security" },
            { value: "dns", label: "DNS defaults" },
            { value: "email", label: "Email" },
            { value: "ldap", label: "Directory (LDAP)" },
          ]}
        />
      </div>
      {err && (
        <div className="mb-4">
          <Banner variant="error" description={err} />
        </div>
      )}

      {tab === "general" && (
        <div className="grid gap-6">
          <Section
            title="Branding and access"
            footer={saveButton(() => ({
              instance_name: s.instance_name,
              support_email: s.support_email,
              signup_enabled: s.signup_enabled,
              allow_org_creation: s.allow_org_creation,
              default_max_zones: s.default_max_zones,
              announcement_banner: s.announcement_banner,
            }))}
          >
            <div className="grid gap-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Input label="Product name" value={s.instance_name} onChange={(e) => set("instance_name", e.target.value)} error={fieldError(save.error, "instance_name")} />
                <Input label="Support email" required={false} value={s.support_email} onChange={(e) => set("support_email", e.target.value)} error={fieldError(save.error, "support_email")} />
              </div>
              <Input
                label="Default zone limit per organization"
                type="number"
                description="Zero means unlimited. Override per organization from the Organizations page."
                value={String(s.default_max_zones)}
                onChange={(e) => set("default_max_zones", Number(e.target.value))}
                error={fieldError(save.error, "default_max_zones")}
              />
              <Switch label="Allow self-service sign up" checked={s.signup_enabled} onCheckedChange={(v: boolean) => set("signup_enabled", v)} />
              <Switch label="Allow any user to create organizations" checked={s.allow_org_creation} onCheckedChange={(v: boolean) => set("allow_org_creation", v)} />
              <InputArea
                label="Announcement banner"
                description="Shown at the top of every page, for maintenance windows or policy notices. Leave empty to hide."
                value={s.announcement_banner}
                onValueChange={(v) => set("announcement_banner", v)}
              />
            </div>
          </Section>
        </div>
      )}

      {tab === "security" && (
        <Section
          title="Authentication policy"
          footer={saveButton(() => ({
            require_mfa: s.require_mfa,
            password_min_length: s.password_min_length,
            session_ttl_hours: s.session_ttl_hours,
            audit_retention_days: s.audit_retention_days,
          }))}
        >
          <div className="grid gap-4">
            <Switch label="Require two-factor authentication for every password-based account" checked={s.require_mfa} onCheckedChange={(v: boolean) => set("require_mfa", v)} />
            <div className="grid gap-4 md:grid-cols-3">
              <Input label="Minimum password length" type="number" value={String(s.password_min_length)} onChange={(e) => set("password_min_length", Number(e.target.value))} error={fieldError(save.error, "password_min_length")} />
              <Input label="Session lifetime (hours)" type="number" value={String(s.session_ttl_hours)} onChange={(e) => set("session_ttl_hours", Number(e.target.value))} error={fieldError(save.error, "session_ttl_hours")} />
              <Input
                label="Audit log retention (days)"
                type="number"
                description="Zero keeps events forever."
                value={String(s.audit_retention_days)}
                onChange={(e) => set("audit_retention_days", Number(e.target.value))}
                error={fieldError(save.error, "audit_retention_days")}
              />
            </div>
          </div>
        </Section>
      )}

      {tab === "dns" && (
        <Section
          title="New zone defaults"
          description="Applied when zones are created. Existing zones are not changed."
          footer={saveButton(() => ({
            default_ttl: s.default_ttl,
            soa: s.soa,
            soa_edit_api: s.soa_edit_api,
            default_dnssec: s.default_dnssec,
            forward_record_types: s.forward_record_types,
            reverse_record_types: s.reverse_record_types,
            auto_ptr: s.auto_ptr,
            dyndns_ttl: s.dyndns_ttl,
          }))}
        >
          <div className="grid gap-4">
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="Default record TTL (seconds)" type="number" description="Used when a record's TTL is Auto." value={String(s.default_ttl)} onChange={(e) => set("default_ttl", Number(e.target.value))} error={fieldError(save.error, "default_ttl")} />
              <VirtualSelect
                label="SOA serial policy"
                options={["DEFAULT", "INCREASE", "EPOCH", "INCEPTION-INCREMENT", "OFF"].map((v) => ({ value: v, label: v }))}
                value={s.soa_edit_api}
                onChange={(v) => set("soa_edit_api", v)}
              />
            </div>
            <div className="grid gap-4 md:grid-cols-5">
              {(["refresh", "retry", "expire", "minimum", "ttl"] as const).map((k) => (
                <Input key={k} label={k === "minimum" ? "Negative TTL" : k === "ttl" ? "SOA TTL" : k[0].toUpperCase() + k.slice(1)} type="number" value={String(s.soa[k])} onChange={(e) => set("soa", { ...s.soa, [k]: Number(e.target.value) })} />
              ))}
            </div>
            {fieldError(save.error, "soa") && <Text variant="error">{fieldError(save.error, "soa")}</Text>}
            <Switch label="Sign new zones with DNSSEC by default" checked={s.default_dnssec} onCheckedChange={(v: boolean) => set("default_dnssec", v)} />
            <div className="grid gap-4 border-t border-kumo-line pt-4 md:grid-cols-2">
              <VirtualSelect
                multiple
                label="Record types for forward zones"
                description="Leave empty to allow every supported type."
                placeholder="All types"
                options={allTypes}
                value={s.forward_record_types ?? []}
                onChange={(v) => set("forward_record_types", v)}
                summarize={(sel) => sel.map((x) => x.value).join(", ")}
              />
              <VirtualSelect
                multiple
                label="Record types for reverse zones"
                description="Applies to in-addr.arpa and ip6.arpa zones."
                placeholder="All types"
                options={allTypes}
                value={s.reverse_record_types ?? []}
                onChange={(v) => set("reverse_record_types", v)}
                summarize={(sel) => sel.map((x) => x.value).join(", ")}
              />
            </div>
            <Switch
              label="Create PTR records automatically when adding A and AAAA records (when a matching reverse zone exists)"
              checked={s.auto_ptr}
              onCheckedChange={(v: boolean) => set("auto_ptr", v)}
            />
            <Input
              label="DynDNS record TTL (seconds)"
              type="number"
              className="max-w-xs"
              description="TTL for addresses updated through /nic/update."
              value={String(s.dyndns_ttl)}
              onChange={(e) => set("dyndns_ttl", Number(e.target.value))}
              error={fieldError(save.error, "dyndns_ttl")}
            />
          </div>
        </Section>
      )}

      {tab === "ldap" && <LdapSettings s={s} set={set} save={save} />}

      {tab === "email" && (
        <Section
          title="SMTP"
          description={s.env_smtp_configured ? "SMTP is configured through environment variables. Settings saved here take precedence." : "Used for invitations, password resets and notifications."}
          footer={
            <>
              <Button icon={<EnvelopeSimpleIcon />} loading={testEmail.isPending} onClick={() => testEmail.mutate()} className="mr-auto">
                Send test email
              </Button>
              {saveButton(() => ({ smtp: { host: s.smtp.host, port: s.smtp.port, username: s.smtp.username, from: s.smtp.from, tls: s.smtp.tls, password: smtpPassword } }))}
            </>
          }
        >
          <div className="grid gap-4">
            {fieldError(save.error, "smtp") && <Banner variant="error" size="sm" description={fieldError(save.error, "smtp")} />}
            <div className="grid gap-4 md:grid-cols-[1fr_140px]">
              <Input label="Host" placeholder="smtp.example.com" value={s.smtp.host} onChange={(e) => set("smtp", { ...s.smtp, host: e.target.value })} />
              <Input label="Port" type="number" value={String(s.smtp.port)} onChange={(e) => set("smtp", { ...s.smtp, port: Number(e.target.value) })} />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="Username" required={false} value={s.smtp.username} onChange={(e) => set("smtp", { ...s.smtp, username: e.target.value })} />
              <SensitiveInput label="Password" placeholder={s.smtp.password_set ? "Unchanged" : ""} value={smtpPassword ?? ""} onValueChange={(v: string) => setSmtpPassword(v)} />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="From address" placeholder="DNS <dns@example.com>" value={s.smtp.from} onChange={(e) => set("smtp", { ...s.smtp, from: e.target.value })} />
              <VirtualSelect
                label="Encryption"
                options={[
                  { value: "starttls", label: "STARTTLS (port 587)" },
                  { value: "tls", label: "Implicit TLS (port 465)" },
                  { value: "none", label: "None (local relay only)" },
                ]}
                value={s.smtp.tls || "starttls"}
                onChange={(v) => set("smtp", { ...s.smtp, tls: v })}
              />
            </div>
          </div>
        </Section>
      )}
    </div>
  );
}
