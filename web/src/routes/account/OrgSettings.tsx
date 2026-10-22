import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, ClipboardText, Input, Switch, TagInput, Text } from "@cloudflare/kumo";
import { TrashIcon } from "@phosphor-icons/react";
import { PageHeader, Section, ConfirmDialog, DetailRow } from "../../components/ui";
import { VirtualSelect } from "../../components/VirtualSelect";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useOrg, useOrgId, usePerms } from "../../lib/queries";
import { formatDate, formatNumber } from "../../lib/format";
import { toast } from "../../lib/toast";

const sessionOptions = [
  { value: "0", label: "Instance default" },
  { value: "60", label: "1 hour" },
  { value: "480", label: "8 hours" },
  { value: "1440", label: "24 hours" },
  { value: "10080", label: "7 days" },
  { value: "43200", label: "30 days" },
];

export default function OrgSettings() {
  const orgId = useOrgId();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const org = useOrg(orgId);
  const { can } = usePerms(orgId);
  const [name, setName] = useState("");
  const [enforceMfa, setEnforceMfa] = useState(false);
  const [ttl, setTtl] = useState("0");
  const [ips, setIps] = useState<string[]>([]);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    if (org.data) {
      setName(org.data.org.name);
      setEnforceMfa(org.data.org.enforce_mfa);
      setTtl(String(org.data.org.session_ttl_minutes ?? 0));
      setIps(org.data.org.ip_allowlist);
    }
  }, [org.data]);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: keys.org(orgId) });
    void qc.invalidateQueries({ queryKey: ["me"] });
  };

  const saveGeneral = useMutation({
    mutationFn: () => api(`/orgs/${orgId}`, { method: "PATCH", body: { name } }),
    onSuccess: () => {
      refresh();
      toast.success("Organization updated");
    },
  });
  const saveSecurity = useMutation({
    mutationFn: () => api(`/orgs/${orgId}`, { method: "PATCH", body: { enforce_mfa: enforceMfa, session_ttl_minutes: Number(ttl), ip_allowlist: ips } }),
    onSuccess: () => {
      refresh();
      toast.success("Security policy updated");
    },
  });
  const del = useMutation({
    mutationFn: () => api(`/orgs/${orgId}`, { method: "DELETE", body: { confirm: org.data?.org.name } }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate("/", { replace: true });
    },
    onError: (e) => toast.error(e, "Could not delete organization"),
  });

  if (!org.data) return null;
  const editable = can("org.update");

  return (
    <div className="grid max-w-4xl gap-6">
      <PageHeader title="Organization settings" />

      <Section
        title="General"
        footer={
          editable && (
            <Button variant="primary" loading={saveGeneral.isPending} onClick={() => saveGeneral.mutate()} disabled={name === org.data.org.name}>
              Save
            </Button>
          )
        }
      >
        <div className="grid gap-4">
          <Input label="Organization name" value={name} onChange={(e) => setName(e.target.value)} disabled={!editable} error={fieldError(saveGeneral.error, "name")} />
          <div className="divide-y divide-kumo-line">
            <DetailRow label="Organization ID">
              <ClipboardText text={orgId} size="sm" />
            </DetailRow>
            <DetailRow label="Zones">
              {formatNumber(org.data.zone_count)} of {org.data.max_zones > 0 ? formatNumber(org.data.max_zones) : "unlimited"}
            </DetailRow>
            <DetailRow label="Created">{formatDate(org.data.org.created_at)}</DetailRow>
          </div>
        </div>
      </Section>

      <Section
        title="Security policy"
        description="Applies to every member of this organization."
        footer={
          editable && (
            <Button variant="primary" loading={saveSecurity.isPending} onClick={() => saveSecurity.mutate()}>
              Save policy
            </Button>
          )
        }
      >
        <div className="grid gap-5">
          {saveSecurity.error && <Banner variant="error" size="sm" description={errorMessage(saveSecurity.error)} />}
          <div className="grid gap-1.5">
            <Switch
              label="Require two-factor authentication"
              checked={enforceMfa}
              disabled={!editable}
              onCheckedChange={(v: boolean) => setEnforceMfa(v)}
            />
            <Text variant="secondary" size="sm">
              Members without an authenticator app are blocked until they enroll. Members who sign in with SSO rely on your identity provider instead.
            </Text>
          </div>
          <VirtualSelect
            label="Maximum session length"
            description="Members must sign in again after this long, even if active."
            options={sessionOptions}
            value={sessionOptions.some((o) => o.value === ttl) ? ttl : "0"}
            onChange={setTtl}
            disabled={!editable}
          />
          <TagInput
            label="IP access rules"
            description="Restrict dashboard and API access to these IP addresses or CIDR ranges. Leave empty to allow any network. Your current address must be included."
            placeholder="203.0.113.0/24"
            value={ips}
            onValueChange={(v: string[]) => setIps(v)}
            disabled={!editable}
            error={fieldError(saveSecurity.error, "ip_allowlist")}
          />
        </div>
      </Section>

      {can("org.delete") && (
        <Section danger title="Delete organization" description="Permanently delete this organization, its members, tokens and audit history. All zones must be deleted or moved first.">
          <Button variant="destructive" icon={<TrashIcon />} onClick={() => setDeleting(true)}>
            Delete organization
          </Button>
        </Section>
      )}
      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title="Delete organization"
        description="This cannot be undone."
        confirmText={org.data.org.name}
        confirmLabel="Delete organization"
        loading={del.isPending}
        onConfirm={() => del.mutate()}
      />
    </div>
  );
}
