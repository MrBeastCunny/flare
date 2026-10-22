import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, Dialog, Input, Tabs, Text } from "@cloudflare/kumo";
import { ShieldCheckIcon, ShieldSlashIcon, XIcon, DesktopIcon } from "@phosphor-icons/react";
import { PageHeader, Section, ConfirmDialog, RoleBadge, DetailRow } from "../../components/ui";
import { MfaSetup, RecoveryCodes } from "../../components/MfaSetup";
import { VirtualTable, type Column } from "../../components/VirtualTable";
import { VirtualSelect } from "../../components/VirtualSelect";
import { api, errorMessage, fieldError } from "../../lib/api";
import { useMe } from "../../lib/queries";
import { formatDateTime, parseUA, timeAgo } from "../../lib/format";
import { useTheme } from "../../lib/theme";
import { toast } from "../../lib/toast";
import type { MeOrg } from "../../lib/types";

interface SessionRow {
  id: string;
  auth_method: string;
  ip: string;
  user_agent: string;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

export default function Profile() {
  const me = useMe();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { pref, setPref } = useTheme();
  const [tab, setTab] = useState("profile");
  const [name, setName] = useState("");
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [mfaOpen, setMfaOpen] = useState(false);
  const [codeDialog, setCodeDialog] = useState<"disable" | "regen" | null>(null);
  const [code, setCode] = useState("");
  const [newCodes, setNewCodes] = useState<string[] | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);

  useEffect(() => {
    if (me.data) setName(me.data.user.name);
  }, [me.data]);

  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => api<SessionRow[]>("/me/sessions"), enabled: tab === "sessions" });
  const refreshMe = () => qc.invalidateQueries({ queryKey: ["me"] });

  const saveName = useMutation({
    mutationFn: () => api("/me", { method: "PATCH", body: { name } }),
    onSuccess: () => {
      void refreshMe();
      toast.success("Profile updated");
    },
  });
  const changePw = useMutation({
    mutationFn: () => api("/me/password", { method: "POST", body: { current_password: current, new_password: next } }),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      toast.success("Password changed", "Other sessions have been signed out.");
    },
  });
  const secondFactor = useMutation({
    mutationFn: () =>
      codeDialog === "disable"
        ? api("/me/mfa/disable", { method: "POST", body: { code } })
        : api<{ recovery_codes: string[] }>("/me/mfa/recovery-codes", { method: "POST", body: { code } }),
    onSuccess: (d) => {
      void refreshMe();
      setCode("");
      if (codeDialog === "regen") setNewCodes((d as { recovery_codes: string[] }).recovery_codes);
      else {
        setCodeDialog(null);
        toast.success("Two-factor authentication disabled");
      }
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api(`/me/sessions/${id}`, { method: "DELETE" }),
    onSuccess: () => void sessions.refetch(),
    onError: (e) => toast.error(e),
  });
  const revokeOthers = useMutation({
    mutationFn: () => api("/me/sessions/revoke-others", { method: "POST" }),
    onSuccess: () => {
      void sessions.refetch();
      toast.success("Signed out of all other sessions");
    },
  });
  const deleteAccount = useMutation({
    mutationFn: () => api("/me", { method: "DELETE", body: { confirm: me.data?.user.email } }),
    onSuccess: () => {
      qc.clear();
      navigate("/login", { replace: true });
    },
    onError: (e) => toast.error(e, "Could not delete account"),
  });

  if (!me.data) return null;
  const u = me.data.user;

  const sessionCols: Column<SessionRow>[] = [
    {
      key: "device",
      header: "Device",
      width: "32%",
      render: (s) => (
        <div className="flex min-w-0 items-center gap-2.5">
          <DesktopIcon size={18} className="shrink-0 text-kumo-subtle" />
          <div className="grid min-w-0">
            <span className="truncate font-medium">{parseUA(s.user_agent)}</span>
            <span className="truncate text-sm text-kumo-subtle">{s.auth_method === "sso" ? "Single sign-on" : "Password"}</span>
          </div>
          {s.current && <Badge variant="primary">This device</Badge>}
        </div>
      ),
    },
    { key: "ip", header: "IP address", width: "18%", render: (s) => <span className="font-mono text-[0.9em]">{s.ip}</span> },
    { key: "seen", header: "Last active", width: "18%", render: (s) => <span className="text-kumo-subtle">{timeAgo(s.last_seen_at)}</span> },
    { key: "created", header: "Signed in", width: "20%", render: (s) => <span className="text-kumo-subtle">{formatDateTime(s.created_at)}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      width: "12%",
      align: "right",
      render: (s) =>
        !s.current && (
          <Button size="sm" variant="secondary-destructive" loading={revoke.isPending && revoke.variables === s.id} onClick={() => revoke.mutate(s.id)}>
            Revoke
          </Button>
        ),
    },
  ];

  const orgCols: Column<MeOrg>[] = [
    { key: "name", header: "Organization", width: "50%", render: (o) => <span className="font-medium">{o.name}</span> },
    { key: "role", header: "Role", width: "25%", render: (o) => <RoleBadge role={o.role} /> },
    { key: "zones", header: "Zones", width: "25%", render: (o) => <span className="text-kumo-subtle">{o.zone_count}</span> },
  ];

  return (
    <div className="max-w-5xl">
      <PageHeader title="My profile" description={u.email} />
      <div className="mb-6">
        <Tabs
          variant="underline"
          value={tab}
          onValueChange={setTab}
          tabs={[
            { value: "profile", label: "Profile" },
            { value: "security", label: "Security" },
            { value: "sessions", label: "Sessions" },
            { value: "orgs", label: "Organizations" },
          ]}
        />
      </div>

      {tab === "profile" && (
        <div className="grid gap-6">
          <Section
            title="Personal information"
            footer={
              <Button variant="primary" loading={saveName.isPending} disabled={name === u.name} onClick={() => saveName.mutate()}>
                Save
              </Button>
            }
          >
            <div className="grid gap-4 md:grid-cols-2">
              <Input label="Full name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" error={fieldError(saveName.error, "name")} />
              <Input label="Email" value={u.email} disabled description="Contact an administrator to change your email." />
            </div>
          </Section>
          <Section title="Preferences">
            <VirtualSelect
              label="Appearance"
              className="max-w-xs"
              options={[
                { value: "system", label: "Match system" },
                { value: "light", label: "Light" },
                { value: "dark", label: "Dark" },
              ]}
              value={pref}
              onChange={(v) => setPref(v as typeof pref)}
            />
          </Section>
          <Section title="Account">
            <div className="divide-y divide-kumo-line">
              <DetailRow label="User ID">
                <span className="font-mono text-[0.9em]">{u.id}</span>
              </DetailRow>
              <DetailRow label="Member since">{formatDateTime(u.created_at)}</DetailRow>
              <DetailRow label="Last sign-in">{formatDateTime(u.last_login_at)}</DetailRow>
              {u.is_superadmin && (
                <DetailRow label="Instance role">
                  <Badge variant="primary">Instance administrator</Badge>
                </DetailRow>
              )}
            </div>
          </Section>
          <Section danger title="Delete account" description="Permanently delete your account and leave every organization.">
            <Button variant="destructive" onClick={() => setDeleteOpen(true)}>
              Delete my account
            </Button>
          </Section>
        </div>
      )}

      {tab === "security" && (
        <div className="grid gap-6">
          <Section
            title="Two-factor authentication"
            actions={
              u.totp_enabled ? (
                <Badge variant="success" icon={<ShieldCheckIcon />}>
                  Enabled
                </Badge>
              ) : (
                <Badge variant="warning" icon={<ShieldSlashIcon />}>
                  Not enabled
                </Badge>
              )
            }
          >
            {u.totp_enabled ? (
              <div className="grid gap-4">
                <Text variant="secondary">Your account is protected with an authenticator app.</Text>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={() => setCodeDialog("regen")}>Regenerate recovery codes</Button>
                  <Button variant="secondary-destructive" onClick={() => setCodeDialog("disable")}>
                    Disable two-factor authentication
                  </Button>
                </div>
              </div>
            ) : mfaOpen ? (
              <MfaSetup
                account={u.email}
                onDone={() => {
                  setMfaOpen(false);
                  void refreshMe();
                }}
              />
            ) : (
              <div className="grid gap-4">
                <Text variant="secondary">Require a code from your phone in addition to your password when you sign in.</Text>
                <div>
                  <Button variant="primary" onClick={() => setMfaOpen(true)}>
                    Enable two-factor authentication
                  </Button>
                </div>
              </div>
            )}
          </Section>

          {me.data.has_password ? (
            <Section
              title="Password"
              footer={
                <Button variant="primary" loading={changePw.isPending} disabled={!current || !next} onClick={() => changePw.mutate()}>
                  Change password
                </Button>
              }
            >
              <div className="grid gap-4 md:grid-cols-2">
                <Input label="Current password" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} error={fieldError(changePw.error, "current_password")} />
                <Input label="New password" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} error={fieldError(changePw.error, "new_password")} />
              </div>
            </Section>
          ) : (
            <Section title="Password">
              <Text variant="secondary">You sign in with single sign-on, so there is no password on this account.</Text>
            </Section>
          )}
        </div>
      )}

      {tab === "sessions" && (
        <Section
          padded={false}
          title="Active sessions"
          description="Devices currently signed in to your account."
          actions={
            <Button size="sm" loading={revokeOthers.isPending} onClick={() => revokeOthers.mutate()}>
              Sign out other sessions
            </Button>
          }
        >
          <VirtualTable ariaLabel="Sessions" rows={sessions.data ?? []} columns={sessionCols} rowKey={(s) => s.id} loading={sessions.isLoading} rowHeight={60} maxHeight="520px" />
        </Section>
      )}

      {tab === "orgs" && (
        <Section padded={false} title="Organizations" description="Organizations you belong to.">
          <VirtualTable ariaLabel="Organizations" rows={me.data.orgs} columns={orgCols} rowKey={(o) => o.id} onRowClick={(o) => navigate(`/${o.id}`)} maxHeight="520px" />
        </Section>
      )}

      <Dialog.Root
        open={!!codeDialog}
        onOpenChange={(o) => {
          if (!o) {
            setCodeDialog(null);
            setNewCodes(null);
            setCode("");
          }
        }}
      >
        <Dialog size="lg" className="p-6">
          <div className="mb-4 flex items-start justify-between">
            <Dialog.Title className="text-lg font-semibold">{codeDialog === "disable" ? "Disable two-factor authentication" : "Regenerate recovery codes"}</Dialog.Title>
            <Dialog.Close render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
          </div>
          {newCodes ? (
            <div className="grid gap-4">
              <RecoveryCodes codes={newCodes} account={u.email} />
              <div className="flex justify-end">
                <Dialog.Close render={(p) => <Button {...p} variant="primary">Done</Button>} />
              </div>
            </div>
          ) : (
            <form
              className="grid gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                secondFactor.mutate();
              }}
            >
              <Text variant="secondary">Enter a code from your authenticator app, or a recovery code, to confirm.</Text>
              <Input label="Code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" className="font-mono" autoFocus error={fieldError(secondFactor.error, "code")} />
              {secondFactor.error && !fieldError(secondFactor.error, "code") && <Banner variant="error" size="sm" description={errorMessage(secondFactor.error)} />}
              <div className="flex justify-end gap-2">
                <Dialog.Close render={(p) => <Button {...p}>Cancel</Button>} />
                <Button type="submit" variant={codeDialog === "disable" ? "destructive" : "primary"} loading={secondFactor.isPending} disabled={!code}>
                  {codeDialog === "disable" ? "Disable" : "Generate new codes"}
                </Button>
              </div>
            </form>
          )}
        </Dialog>
      </Dialog.Root>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete your account"
        description="You will lose access to every organization. This cannot be undone."
        confirmText={u.email}
        confirmLabel="Delete account"
        loading={deleteAccount.isPending}
        onConfirm={() => deleteAccount.mutate()}
      />
    </div>
  );
}
