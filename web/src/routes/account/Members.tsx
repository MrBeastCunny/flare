import { useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, ClipboardText, Dialog, InputGroup, LayerCard, TagInput, Tabs, Text, Tooltip } from "@cloudflare/kumo";
import { UserPlusIcon, MagnifyingGlassIcon, ShieldCheckIcon, XIcon, ShieldSlashIcon } from "@phosphor-icons/react";
import { PageHeader, RoleBadge, Avatar, ConfirmDialog } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { VirtualList } from "../../components/VirtualList";
import { api, errorMessage } from "../../lib/api";
import { keys, useInvites, useMe, useMembers, useOrgId, usePerms, useZones } from "../../lib/queries";
import { roleDescriptions, roleLabels, stripDot, timeAgo } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { Invitation, Member, Role } from "../../lib/types";

const ROLES: Role[] = ["owner", "admin", "editor", "viewer", "auditor"];

function RoleSelect({ value, onChange, allowOwner }: { value: Role; onChange: (r: Role) => void; allowOwner: boolean }) {
  return (
    <VirtualSelect
      label="Role"
      options={ROLES.filter((r) => allowOwner || r !== "owner").map((r) => ({ value: r, label: roleLabels[r], description: roleDescriptions[r] }))}
      value={value}
      onChange={(v) => onChange(v as Role)}
    />
  );
}

function ZoneScope({ orgId, value, onChange, disabled }: { orgId: string; value: string[]; onChange: (v: string[]) => void; disabled?: boolean }) {
  const zones = useZones(orgId);
  return (
    <VirtualSelect
      multiple
      label="Zone access"
      description={disabled ? "Owners and administrators always have access to every zone." : "Leave empty to grant access to all current and future zones."}
      placeholder="All zones"
      disabled={disabled}
      options={(zones.data ?? []).map((z) => ({ value: z.id, label: stripDot(z.name) }))}
      value={value}
      onChange={onChange}
      searchable
      summarize={(sel) => (sel.length === 1 ? sel[0].label : `${sel.length} zones`)}
    />
  );
}

export default function Members() {
  const orgId = useOrgId();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const me = useMe();
  const { can, role: myRole } = usePerms(orgId);
  const members = useMembers(orgId);
  const invites = useInvites(orgId, can("members.manage"));
  const [tab, setTab] = useState("members");
  const [q, setQ] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [emails, setEmails] = useState<string[]>([]);
  const [inviteRole, setInviteRole] = useState<Role>("editor");
  const [inviteZones, setInviteZones] = useState<string[]>([]);
  const [inviteLinks, setInviteLinks] = useState<{ email: string; url: string; emailed: boolean }[] | null>(null);
  const [editing, setEditing] = useState<Member | null>(null);
  const [editRole, setEditRole] = useState<Role>("viewer");
  const [editZones, setEditZones] = useState<string[]>([]);
  const [removing, setRemoving] = useState<Member | null>(null);
  const [leaving, setLeaving] = useState(false);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: keys.members(orgId) });
    void qc.invalidateQueries({ queryKey: keys.invites(orgId) });
  };

  const invite = useMutation({
    mutationFn: () =>
      api<{ results: { email: string; status: string; invite_url?: string; emailed: boolean; error?: string }[] }>(`/orgs/${orgId}/invites`, {
        method: "POST",
        body: { emails, role: inviteRole, zone_ids: inviteZones },
      }),
    onSuccess: (d) => {
      refresh();
      const ok = d.results.filter((r) => r.status === "invited");
      const failed = d.results.filter((r) => r.status !== "invited");
      failed.forEach((f) => toast.error(new Error(`${f.email}: ${f.error}`), "Not invited"));
      if (ok.some((r) => !r.emailed)) {
        setInviteLinks(ok.map((r) => ({ email: r.email, url: r.invite_url ?? "", emailed: r.emailed })));
      } else {
        toast.success(`${ok.length} invitation${ok.length === 1 ? "" : "s"} sent`);
        setInviteOpen(false);
      }
      setEmails([]);
    },
    onError: (e) => toast.error(e, "Could not send invitations"),
  });

  const update = useMutation({
    mutationFn: () => api(`/orgs/${orgId}/members/${editing!.id}`, { method: "PATCH", body: { role: editRole, zone_ids: editZones } }),
    onSuccess: () => {
      refresh();
      toast.success("Member updated");
      setEditing(null);
    },
    onError: (e) => toast.error(e, "Could not update member"),
  });

  const remove = useMutation({
    mutationFn: (m: Member) => api(`/orgs/${orgId}/members/${m.id}`, { method: "DELETE" }),
    onSuccess: () => {
      refresh();
      toast.success("Member removed");
      setRemoving(null);
    },
    onError: (e) => toast.error(e, "Could not remove member"),
  });

  const leave = useMutation({
    mutationFn: () => api(`/orgs/${orgId}/leave`, { method: "POST" }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate("/");
    },
    onError: (e) => toast.error(e, "Could not leave organization"),
  });

  const inviteAction = useMutation({
    mutationFn: ({ inv, action }: { inv: Invitation; action: "resend" | "revoke" }) =>
      action === "resend"
        ? api<{ invite_url: string; emailed: boolean }>(`/orgs/${orgId}/invites/${inv.id}/resend`, { method: "POST" })
        : api(`/orgs/${orgId}/invites/${inv.id}`, { method: "DELETE" }),
    onSuccess: (d, v) => {
      refresh();
      if (v.action === "revoke") toast.success("Invitation revoked");
      else {
        const r = d as { invite_url: string; emailed: boolean };
        if (r.emailed) toast.success("Invitation re-sent");
        else setInviteLinks([{ email: v.inv.email, url: r.invite_url, emailed: false }]);
      }
    },
    onError: (e) => toast.error(e),
  });

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (members.data ?? []).filter((m) => !query || m.user_email.includes(query) || m.user_name.toLowerCase().includes(query));
  }, [members.data, q]);

  const manage = can("members.manage");
  const columns: Column<Member>[] = [
    {
      key: "user",
      header: "Member",
      render: (m) => (
        <div className="flex min-w-0 items-center gap-3">
          <Avatar name={m.user_name || m.user_email} />
          <div className="grid min-w-0">
            <span className="truncate font-medium text-kumo-strong">
              {m.user_name || m.user_email}
              {m.user_id === me.data?.user.id && <span className="ml-1.5 font-normal text-kumo-subtle">(you)</span>}
              {(m.source === "scim" || m.source === "sso") && (
                <Badge variant="outline" className="ml-2 align-middle">
                  {m.source.toUpperCase()}
                </Badge>
              )}
            </span>
            <span className="truncate text-sm text-kumo-subtle">{m.user_email}</span>
          </div>
        </div>
      ),
    },
    {
      key: "role",
      header: "Role",
      width: "150px",
      render: (m) => (
        <div className="flex items-center gap-1.5">
          <RoleBadge role={m.role} />
          {m.suspended && <Badge variant="error">Deactivated</Badge>}
        </div>
      ),
    },
    {
      key: "scope",
      header: "Access",
      width: "110px",
      render: (m) => <span className="text-kumo-subtle">{m.zone_ids ? `${m.zone_ids.length} zone${m.zone_ids.length === 1 ? "" : "s"}` : "All zones"}</span>,
    },
    {
      key: "mfa",
      header: "2FA",
      width: "64px",
      render: (m) =>
        m.user_totp_enabled ? (
          <Tooltip content="Authenticator app enabled">
            <ShieldCheckIcon size={18} weight="fill" className="text-kumo-success" />
          </Tooltip>
        ) : (
          <Tooltip content="No two-factor authentication">
            <ShieldSlashIcon size={18} className="text-kumo-inactive" />
          </Tooltip>
        ),
    },
    { key: "seen", header: "Last sign-in", width: "130px", render: (m) => <span className="text-kumo-subtle">{timeAgo(m.user_last_login_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "56px",
      align: "right",
      render: (m) => (
        <ActionMenu
          items={[
            {
              key: "edit",
              label: "Change role and access",
              hidden: !manage || (m.role === "owner" && myRole !== "owner"),
              onSelect: () => {
                setEditing(m);
                setEditRole(m.role);
                setEditZones(m.zone_ids ?? []);
              },
            },
            { key: "remove", label: "Remove from organization", danger: true, separatorBefore: true, hidden: !manage || m.user_id === me.data?.user.id, onSelect: () => setRemoving(m) },
            { key: "leave", label: "Leave organization", danger: true, hidden: m.user_id !== me.data?.user.id, onSelect: () => setLeaving(true) },
          ]}
        />
      ),
    },
  ];

  const inviteColumns: Column<Invitation>[] = [
    { key: "email", header: "Email", width: "34%", render: (i) => <span className="truncate font-medium">{i.email}</span> },
    { key: "role", header: "Role", width: "16%", render: (i) => <RoleBadge role={i.role} /> },
    { key: "by", header: "Invited by", width: "20%", render: (i) => <span className="text-kumo-subtle">{i.inviter_name || "Unknown"}</span> },
    { key: "exp", header: "Expires", width: "20%", render: (i) => <span className="text-kumo-subtle">{timeAgo(i.expires_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "10%",
      align: "right",
      render: (i) => (
        <ActionMenu
          items={[
            { key: "resend", label: "Resend invitation", onSelect: () => inviteAction.mutate({ inv: i, action: "resend" }) },
            { key: "revoke", label: "Revoke", danger: true, onSelect: () => inviteAction.mutate({ inv: i, action: "revoke" }) },
          ]}
        />
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Members"
        description="People with access to this organization and what they can do."
        actions={
          manage && (
            <Button
              variant="primary"
              icon={<UserPlusIcon />}
              onClick={() => {
                setInviteLinks(null);
                setInviteOpen(true);
              }}
            >
              Invite members
            </Button>
          )
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-kumo-line px-4 py-3">
          {manage && (
            <Tabs
              variant="segmented"
              value={tab}
              onValueChange={setTab}
              tabs={[
                { value: "members", label: `Members (${members.data?.length ?? 0})` },
                { value: "invites", label: `Pending invitations (${invites.data?.length ?? 0})` },
              ]}
            />
          )}
          {tab === "members" && (
            <InputGroup className="ml-auto w-full max-w-xs">
              <InputGroup.Addon>
                <MagnifyingGlassIcon />
              </InputGroup.Addon>
              <InputGroup.Input placeholder="Search members" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search members" />
            </InputGroup>
          )}
        </div>
        {tab === "members" ? (
          <VirtualTable ariaLabel="Members" rows={rows} columns={columns} rowKey={(m) => m.id} loading={members.isLoading} rowHeight={60} maxHeight="calc(100vh - 320px)" minWidth={700} />
        ) : (
          <VirtualTable
            ariaLabel="Pending invitations"
            rows={invites.data ?? []}
            columns={inviteColumns}
            rowKey={(i) => i.id}
            loading={invites.isLoading}
            empty={<div className="px-5 py-10 text-center text-kumo-subtle">No pending invitations.</div>}
          />
        )}
      </LayerCard>

      <Dialog.Root open={inviteOpen} onOpenChange={setInviteOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{inviteLinks ? "Share invitation links" : "Invite members"}</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          {inviteLinks ? (
            <div className="grid gap-4">
              <Banner variant="secondary" size="sm" description="Email delivery is not configured. Send these single-use links to each person. They expire in 7 days." />
              <VirtualList
                ariaLabel="Invitation links"
                items={inviteLinks}
                itemKey={(l) => l.email}
                divided={false}
                gap={12}
                estimateSize={64}
                maxHeight={360}
                renderItem={(l) => (
                  <div className="grid gap-1.5">
                    <Text bold>{l.email}</Text>
                    <ClipboardText text={l.url} size="sm" />
                  </div>
                )}
              />
              <div className="flex justify-end">
                <Button variant="primary" onClick={() => setInviteOpen(false)}>
                  Done
                </Button>
              </div>
            </div>
          ) : (
            <form
              className="grid gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                invite.mutate();
              }}
            >
              <TagInput
                label="Email addresses"
                description="Press Enter or paste a list separated by commas."
                placeholder="name@company.com"
                value={emails}
                onValueChange={(v: string[]) => setEmails(v)}
                validateValue={(v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)}
              />
              <RoleSelect value={inviteRole} onChange={setInviteRole} allowOwner={myRole === "owner"} />
              <ZoneScope orgId={orgId} value={inviteZones} onChange={setInviteZones} disabled={inviteRole === "owner" || inviteRole === "admin"} />
              {invite.error && <Banner variant="error" size="sm" description={errorMessage(invite.error)} />}
              <div className="mt-2 flex justify-end gap-2">
                <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
                <Button type="submit" variant="primary" loading={invite.isPending} disabled={emails.length === 0}>
                  Send {emails.length > 1 ? `${emails.length} invitations` : "invitation"}
                </Button>
              </div>
            </form>
          )}
        </Dialog>
      </Dialog.Root>

      <Dialog.Root open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <Dialog size="lg" className="p-6">
          <div className="mb-1 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">Edit member</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <Dialog.Description className="mb-4 text-kumo-subtle">{editing?.user_email}</Dialog.Description>
          <div className="grid gap-4">
            <RoleSelect value={editRole} onChange={setEditRole} allowOwner={myRole === "owner"} />
            <ZoneScope orgId={orgId} value={editZones} onChange={setEditZones} disabled={editRole === "owner" || editRole === "admin"} />
            {editing?.source === "scim" || editing?.source === "sso" ? (
              <Banner variant="secondary" size="sm" description="This member is managed by your identity provider. Group mappings may change their role on next sync." />
            ) : null}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button variant="primary" loading={update.isPending} onClick={() => update.mutate()}>
                Save changes
              </Button>
            </div>
          </div>
        </Dialog>
      </Dialog.Root>

      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title="Remove member"
        description={`${removing?.user_email} will immediately lose access to every zone in this organization.`}
        confirmLabel="Remove member"
        loading={remove.isPending}
        onConfirm={() => removing && remove.mutate(removing)}
      />
      <ConfirmDialog
        open={leaving}
        onOpenChange={setLeaving}
        title="Leave organization"
        description="You will lose access to this organization's zones until someone invites you again."
        confirmLabel="Leave organization"
        loading={leave.isPending}
        onConfirm={() => leave.mutate()}
      />
    </div>
  );
}
