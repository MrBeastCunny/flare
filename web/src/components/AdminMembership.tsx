import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Dialog, Text } from "@cloudflare/kumo";
import { TrashIcon, XIcon } from "@phosphor-icons/react";
import { VirtualList } from "./VirtualList";
import { VirtualSelect } from "./VirtualSelect";
import { api, errorMessage } from "../lib/api";
import { keys } from "../lib/queries";
import { roleDescriptions, roleLabels } from "../lib/format";
import { toast } from "../lib/toast";
import type { AdminOrg, AdminUser, MeOrg, Role } from "../lib/types";

const ROLES: Role[] = ["owner", "admin", "editor", "viewer", "auditor"];
const roleOptions = ROLES.map((r) => ({ value: r, label: roleLabels[r], description: roleDescriptions[r] }));

interface UserDetail {
  user: AdminUser;
  orgs: MeOrg[];
}

/** Lets an instance administrator place a user in organizations directly, without an invitation. */
export function UserOrganizationsDialog({ user, onOpenChange }: { user: AdminUser | null; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient();
  const detailKey = [...keys.admin("users"), user?.id ?? ""];
  const detail = useQuery({ queryKey: detailKey, queryFn: () => api<UserDetail>(`/admin/users/${user!.id}`), enabled: !!user });
  const orgs = useQuery({ queryKey: keys.admin("orgs"), queryFn: () => api<AdminOrg[]>("/admin/orgs"), enabled: !!user });
  const [orgId, setOrgId] = useState("");
  const [role, setRole] = useState<Role>("editor");

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: keys.admin("users") });
    void qc.invalidateQueries({ queryKey: keys.admin("orgs") });
    void qc.invalidateQueries({ queryKey: ["me"] });
  };
  const setMember = useMutation({
    mutationFn: (v: { orgId: string; role: Role }) => api(`/admin/orgs/${v.orgId}/members/${user!.id}`, { method: "PUT", body: { role: v.role } }),
    onSuccess: (_, v) => {
      refresh();
      if (v.orgId === orgId) setOrgId("");
      toast.success("Membership saved");
    },
    onError: (e) => toast.error(e, "Could not save membership"),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/admin/orgs/${id}/members/${user!.id}`, { method: "DELETE" }),
    onSuccess: () => {
      refresh();
      toast.success("Removed from organization");
    },
    onError: (e) => toast.error(e, "Could not remove membership"),
  });

  const memberships = detail.data?.orgs ?? [];
  const joined = new Set(memberships.map((m) => m.id));
  const available = (orgs.data ?? []).filter((o) => !joined.has(o.id)).map((o) => ({ value: o.id, label: o.name, description: o.slug }));

  return (
    <Dialog.Root open={!!user} onOpenChange={onOpenChange}>
      <Dialog size="lg" className="p-6">
        <div className="mb-1 flex items-start justify-between gap-4">
          <Dialog.Title className="text-lg font-semibold">Organizations</Dialog.Title>
          <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
        </div>
        <Dialog.Description className="mb-4 text-kumo-subtle">
          {user ? `Add ${user.name || user.email} to organizations or change their role. Changes apply immediately, without an invitation.` : ""}
        </Dialog.Description>

        <div className="grid gap-5">
          <div className="overflow-hidden rounded-lg ring ring-kumo-line">
            <VirtualList
              ariaLabel="Memberships"
              items={memberships}
              itemKey={(m) => m.id}
              estimateSize={60}
              maxHeight={300}
              divided
              empty={<div className="px-4 py-6 text-center text-kumo-subtle">{detail.isLoading ? "Loading" : "Not a member of any organization."}</div>}
              renderItem={(m) => (
                <div className="flex min-h-15 items-center gap-3 px-4 py-2.5">
                  <div className="grid min-w-0 flex-1">
                    <span className="truncate font-medium text-kumo-strong">{m.name}</span>
                    <span className="truncate text-sm text-kumo-subtle">
                      {m.slug}
                      {m.zone_ids ? ` · ${m.zone_ids.length} zones` : ""}
                    </span>
                  </div>
                  <VirtualSelect
                    aria-label={`Role in ${m.name}`}
                    size="sm"
                    className="w-40 shrink-0"
                    popupWidth={300}
                    align="end"
                    options={roleOptions}
                    value={m.role}
                    onChange={(v) => v !== m.role && setMember.mutate({ orgId: m.id, role: v as Role })}
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    shape="square"
                    icon={<TrashIcon />}
                    aria-label={`Remove from ${m.name}`}
                    loading={remove.isPending && remove.variables === m.id}
                    onClick={() => remove.mutate(m.id)}
                  />
                </div>
              )}
            />
          </div>

          <form
            className="grid gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (orgId) setMember.mutate({ orgId, role });
            }}
          >
            <Text bold>Add to an organization</Text>
            <div className="grid gap-3 sm:grid-cols-[1fr_11rem]">
              <VirtualSelect
                aria-label="Organization"
                searchable
                placeholder={available.length ? "Choose an organization" : "Already in every organization"}
                disabled={!available.length}
                options={available}
                value={orgId}
                onChange={setOrgId}
              />
              <VirtualSelect aria-label="Role" popupWidth={300} align="end" options={roleOptions} value={role} onChange={(v) => setRole(v as Role)} />
            </div>
            {setMember.error && <Banner variant="error" size="sm" description={errorMessage(setMember.error)} />}
            <div className="flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Done</Button>} />
              <Button type="submit" variant="primary" disabled={!orgId} loading={setMember.isPending && setMember.variables?.orgId === orgId}>
                Add to organization
              </Button>
            </div>
          </form>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}

/** Adds an existing user to one organization from the organizations list. */
export function AddOrgMemberDialog({ org, onOpenChange }: { org: AdminOrg | null; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: keys.admin("users"), queryFn: () => api<AdminUser[]>("/admin/users"), enabled: !!org });
  const [userId, setUserId] = useState("");
  const [role, setRole] = useState<Role>("editor");
  const add = useMutation({
    mutationFn: () => api(`/admin/orgs/${org!.id}/members/${userId}`, { method: "PUT", body: { role } }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.admin("orgs") });
      void qc.invalidateQueries({ queryKey: keys.admin("users") });
      void qc.invalidateQueries({ queryKey: ["me"] });
      const u = users.data?.find((x) => x.id === userId);
      toast.success("Member added", `${u?.name || u?.email} is now ${roleLabels[role]} of ${org?.name}.`);
      setUserId("");
      onOpenChange(false);
    },
  });

  return (
    <Dialog.Root
      open={!!org}
      onOpenChange={(o) => {
        if (!o) add.reset();
        onOpenChange(o);
      }}
    >
      <Dialog size="lg" className="p-6">
        <div className="mb-1 flex items-start justify-between gap-4">
          <Dialog.Title className="text-lg font-semibold">Add member to {org?.name}</Dialog.Title>
          <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
        </div>
        <Dialog.Description className="mb-4 text-kumo-subtle">
          The user gets access immediately, without an invitation. If they are already a member, their role is changed.
        </Dialog.Description>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <VirtualSelect
            label="User"
            searchable
            searchPlaceholder="Search by name or email"
            placeholder="Choose a user"
            options={(users.data ?? []).map((u) => ({ value: u.id, label: u.name || u.email, description: u.name ? u.email : undefined, keywords: u.email }))}
            value={userId}
            onChange={setUserId}
          />
          <VirtualSelect label="Role" options={roleOptions} value={role} onChange={(v) => setRole(v as Role)} />
          {add.error && <Banner variant="error" size="sm" description={errorMessage(add.error)} />}
          <div className="mt-2 flex justify-end gap-2">
            <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
            <Button type="submit" variant="primary" disabled={!userId} loading={add.isPending}>
              Add member
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}
