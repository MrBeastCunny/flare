import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Checkbox, Dialog, Input, InputGroup, LayerCard, Tooltip } from "@cloudflare/kumo";
import { MagnifyingGlassIcon, PlusIcon, ShieldCheckIcon, ShieldSlashIcon, XIcon } from "@phosphor-icons/react";
import { PageHeader, Avatar, ConfirmDialog } from "../../components/ui";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { ActionMenu } from "../../components/VirtualMenu";
import { api, errorMessage, fieldError } from "../../lib/api";
import { keys, useMe } from "../../lib/queries";
import { formatDate, timeAgo } from "../../lib/format";
import { toast } from "../../lib/toast";
import type { AdminUser } from "../../lib/types";

export default function Users() {
  const qc = useQueryClient();
  const me = useMe();
  const users = useQuery({ queryKey: keys.admin("users"), queryFn: () => api<AdminUser[]>("/admin/users") });
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("all");
  const [deleting, setDeleting] = useState<AdminUser | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<AdminUser | null>(null);
  const [form, setForm] = useState({ email: "", name: "", password: "", is_superadmin: false, send_email: true });
  const openDialog = (u: AdminUser | null) => {
    setEditingUser(u);
    setForm({ email: u?.email ?? "", name: u?.name ?? "", password: "", is_superadmin: u?.is_superadmin ?? false, send_email: true });
    saveUser.reset();
    setDialogOpen(true);
  };
  const saveUser = useMutation({
    mutationFn: () =>
      editingUser
        ? api(`/admin/users/${editingUser.id}`, { method: "PATCH", body: { email: form.email, name: form.name } })
        : api<{ setup_url?: string }>("/admin/users", { method: "POST", body: form }),
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: keys.admin("users") });
      setDialogOpen(false);
      const url = (res as { setup_url?: string } | undefined)?.setup_url;
      if (url) {
        void navigator.clipboard?.writeText(url).catch(() => {});
        toast.success("User created", form.send_email ? "A link to set a password was emailed and copied to your clipboard." : "The set-password link was copied to your clipboard.");
      } else toast.success(editingUser ? "User updated" : "User created");
    },
  });

  const update = useMutation({
    mutationFn: ({ u, body }: { u: AdminUser; body: Record<string, unknown> }) => api(`/admin/users/${u.id}`, { method: "PATCH", body }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.admin("users") });
      toast.success("User updated");
    },
    onError: (e) => toast.error(e),
  });
  const remove = useMutation({
    mutationFn: (u: AdminUser) => api(`/admin/users/${u.id}`, { method: "DELETE" }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.admin("users") });
      setDeleting(null);
      toast.success("User deleted");
    },
    onError: (e) => toast.error(e),
  });

  const rows = useMemo(() => {
    const query = q.trim().toLowerCase();
    return (users.data ?? []).filter(
      (u) =>
        (!query || u.email.includes(query) || u.name.toLowerCase().includes(query)) &&
        (filter === "all" ||
          (filter === "admins" && u.is_superadmin) ||
          (filter === "disabled" && u.disabled) ||
          (filter === "nomfa" && !u.totp_enabled) ||
          (filter === "sso" && u.created_via === "sso") ||
          (filter === "scim" && u.created_via === "scim") ||
          (filter === "ldap" && u.created_via === "ldap")),
    );
  }, [users.data, q, filter]);

  const columns: Column<AdminUser>[] = [
    {
      key: "user",
      header: "User",
      width: "36%",
      render: (u) => (
        <div className="flex min-w-0 items-center gap-3">
          <Avatar name={u.name || u.email} />
          <div className="grid min-w-0">
            <span className="flex min-w-0 items-center gap-2 font-medium">
              <span className="truncate">{u.name || u.email}</span>
              {u.is_superadmin && <Badge variant="primary">Admin</Badge>}
              {u.disabled && <Badge variant="error">Disabled</Badge>}
            </span>
            <span className="truncate text-sm text-kumo-subtle">{u.email}</span>
          </div>
        </div>
      ),
    },
    {
      key: "mfa",
      header: "2FA",
      width: "64px",
      render: (u) =>
        u.totp_enabled ? (
          <Tooltip content="Enabled">
            <ShieldCheckIcon size={18} weight="fill" className="text-kumo-success" />
          </Tooltip>
        ) : (
          <Tooltip content="Not enabled">
            <ShieldSlashIcon size={18} className="text-kumo-inactive" />
          </Tooltip>
        ),
    },
    { key: "source", header: "Created via", width: "110px", render: (u) => <span className="capitalize text-kumo-subtle">{u.created_via}</span> },
    { key: "orgs", header: "Orgs", width: "72px", render: (u) => u.org_count },
    { key: "login", header: "Last sign-in", width: "140px", render: (u) => <span className="text-kumo-subtle">{timeAgo(u.last_login_at)}</span> },
    { key: "created", header: "Joined", width: "130px", render: (u) => <span className="text-kumo-subtle">{formatDate(u.created_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "56px",
      align: "right",
      render: (u) => {
        const self = u.id === me.data?.user.id;
        return (
          <ActionMenu
            items={[
              { key: "edit", label: "Edit details", onSelect: () => openDialog(u) },
              { key: "admin", label: u.is_superadmin ? "Remove administrator" : "Make administrator", hidden: self, onSelect: () => update.mutate({ u, body: { is_superadmin: !u.is_superadmin } }) },
              { key: "mfa", label: "Reset two-factor authentication", hidden: !u.totp_enabled, onSelect: () => update.mutate({ u, body: { reset_mfa: true } }) },
              { key: "logout", label: "Sign out everywhere", onSelect: () => update.mutate({ u, body: { logout: true } }) },
              { key: "disable", label: u.disabled ? "Enable account" : "Disable account", hidden: self, danger: !u.disabled, separatorBefore: true, onSelect: () => update.mutate({ u, body: { disabled: !u.disabled } }) },
              { key: "delete", label: "Delete user", hidden: self, danger: true, onSelect: () => setDeleting(u) },
            ]}
          />
        );
      },
    },
  ];

  return (
    <div>
      <PageHeader
        title="Users"
        description="Every account on this instance."
        actions={
          <Button variant="primary" icon={<PlusIcon />} onClick={() => openDialog(null)}>
            Create user
          </Button>
        }
      />
      <LayerCard className="overflow-hidden bg-kumo-base p-0">
        <div className="flex flex-wrap items-center gap-3 border-b border-kumo-line px-4 py-3">
          <InputGroup className="w-full max-w-sm">
            <InputGroup.Addon>
              <MagnifyingGlassIcon />
            </InputGroup.Addon>
            <InputGroup.Input placeholder="Search by name or email" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search users" />
          </InputGroup>
          <VirtualSelect
            aria-label="Filter"
            className="w-52"
            options={[
              { value: "all", label: "All users" },
              { value: "admins", label: "Administrators" },
              { value: "nomfa", label: "Without 2FA" },
              { value: "disabled", label: "Disabled" },
              { value: "sso", label: "Created by SSO" },
              { value: "scim", label: "Created by SCIM" },
              { value: "ldap", label: "Created by LDAP" },
            ]}
            value={filter}
            onChange={setFilter}
          />
          <span className="ml-auto text-sm text-kumo-subtle">{rows.length} users</span>
        </div>
        <VirtualTable ariaLabel="Users" rows={rows} columns={columns} rowKey={(u) => u.id} loading={users.isLoading} rowHeight={60} minWidth={880} onRowClick={openDialog} />
      </LayerCard>
      <Dialog.Root open={dialogOpen} onOpenChange={setDialogOpen}>
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{editingUser ? "Edit user" : "Create user"}</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              saveUser.mutate();
            }}
          >
            <Input label="Email" type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} error={fieldError(saveUser.error, "email")} autoFocus />
            <Input label="Name" required={false} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} error={fieldError(saveUser.error, "name")} />
            {!editingUser && (
              <>
                <Input
                  label="Password"
                  type="password"
                  required={false}
                  autoComplete="new-password"
                  description="Leave blank to send a link where the user chooses their own password."
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  error={fieldError(saveUser.error, "password")}
                />
                {!form.password && <Checkbox label="Email the set-password link" checked={form.send_email} onCheckedChange={(v: boolean) => setForm({ ...form, send_email: v })} />}
                <Checkbox label="Instance administrator" checked={form.is_superadmin} onCheckedChange={(v: boolean) => setForm({ ...form, is_superadmin: v })} />
              </>
            )}
            {editingUser && editingUser.created_via !== "password" && editingUser.created_via !== "admin" && (
              <Banner variant="alert" size="sm" description={`This account is managed by ${editingUser.created_via.toUpperCase()}. Changes may be overwritten at the next sign-in or sync.`} />
            )}
            {saveUser.error && !fieldError(saveUser.error, "email") && !fieldError(saveUser.error, "password") && <Banner variant="error" size="sm" description={errorMessage(saveUser.error)} />}
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
              <Button type="submit" variant="primary" loading={saveUser.isPending} disabled={!form.email.trim()}>
                {editingUser ? "Save changes" : "Create user"}
              </Button>
            </div>
          </form>
        </Dialog>
      </Dialog.Root>
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete user"
        description={`${deleting?.email} will be removed from every organization. Audit history is kept.`}
        confirmText={deleting?.email}
        confirmLabel="Delete user"
        loading={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting)}
      />
    </div>
  );
}
