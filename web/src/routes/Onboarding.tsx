import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input, TagInput, Text, LayerCard } from "@cloudflare/kumo";
import {
  GlobeHemisphereWestIcon,
  ShieldCheckIcon,
  UsersThreeIcon,
  BuildingsIcon,
  HandWavingIcon,
  ArrowRightIcon,
  CheckCircleIcon,
} from "@phosphor-icons/react";
import { Steps } from "../components/Steps";
import { MfaSetup } from "../components/MfaSetup";
import { Logo, FullPageLoader } from "../components/ui";
import { VirtualSelect } from "../components/VirtualSelect";
import { VirtualList } from "../components/VirtualList";
import { api, errorMessage, fieldError } from "../lib/api";
import { useMe } from "../lib/queries";
import { roleLabels, roleDescriptions } from "../lib/format";
import type { Org } from "../lib/types";

type StepKey = "welcome" | "org" | "security" | "team" | "domain";

export default function Onboarding() {
  const me = useMe();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [idx, setIdx] = useState(0);
  const [name, setName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [orgId, setOrgId] = useState("");
  const [emails, setEmails] = useState<string[]>([]);
  const [role, setRole] = useState("editor");
  const [domain, setDomain] = useState("");
  const [inviteResult, setInviteResult] = useState<string | null>(null);

  useEffect(() => {
    if (me.data) {
      setName(me.data.user.name);
      if (me.data.orgs.length > 0 && !orgId) setOrgId(me.data.orgs[0].id);
    }
  }, [me.data, orgId]);

  const steps = useMemo<StepKey[]>(() => {
    if (!me.data) return [];
    const s: StepKey[] = ["welcome"];
    if (me.data.orgs.length === 0) s.push("org");
    if (!me.data.user.totp_enabled && me.data.auth_method !== "sso") s.push("security");
    const canInvite = me.data.orgs.length === 0 || me.data.orgs.some((o) => o.permissions.includes("members.manage"));
    if (canInvite) s.push("team");
    s.push("domain");
    return s;
    // Steps are computed once per load so the flow does not shift under the user.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me.isSuccess]);

  const saveProfile = useMutation({ mutationFn: () => api("/me", { method: "PATCH", body: { name } }) });
  const createOrg = useMutation({
    mutationFn: () => api<Org>("/orgs", { method: "POST", body: { name: orgName } }),
    onSuccess: (o) => {
      setOrgId(o.id);
      void qc.invalidateQueries({ queryKey: ["me"] });
    },
  });
  const invite = useMutation({
    mutationFn: () =>
      api<{ results: { email: string; status: string; emailed: boolean }[] }>(`/orgs/${orgId}/invites`, { method: "POST", body: { emails, role } }),
    onSuccess: (d) => {
      const sent = d.results.filter((r) => r.status === "invited");
      const emailed = sent.filter((r) => r.emailed).length;
      setInviteResult(
        emailed === sent.length
          ? `${sent.length} invitation${sent.length === 1 ? "" : "s"} sent.`
          : `${sent.length} invitation${sent.length === 1 ? "" : "s"} created. Email delivery is not configured, so share the links from the Members page.`,
      );
    },
  });
  const complete = useMutation({ mutationFn: () => api("/me/onboarding/complete", { method: "POST" }) });

  if (!me.data || steps.length === 0) return <FullPageLoader />;
  const step = steps[idx];
  const next = () => setIdx((i) => Math.min(steps.length - 1, i + 1));

  const finish = async (to?: string) => {
    await complete.mutateAsync().catch(() => undefined);
    await qc.invalidateQueries({ queryKey: ["me"] });
    const target = orgId || me.data?.orgs[0]?.id;
    navigate(to ?? (target ? `/${target}` : "/"), { replace: true });
  };

  const labels: Record<StepKey, string> = { welcome: "Welcome", org: "Organization", security: "Security", team: "Team", domain: "First domain" };
  const icons: Record<StepKey, React.ReactNode> = {
    welcome: <HandWavingIcon size={28} />,
    org: <BuildingsIcon size={28} />,
    security: <ShieldCheckIcon size={28} />,
    team: <UsersThreeIcon size={28} />,
    domain: <GlobeHemisphereWestIcon size={28} />,
  };

  return (
    <div className="min-h-full bg-kumo-canvas">
      <div className="border-b border-kumo-line bg-kumo-base">
        <div className="mx-auto flex h-14 max-w-4xl items-center justify-between px-6">
          <Logo name={me.data.instance_name || "Flare"} />
          <Button variant="ghost" size="sm" onClick={() => finish()}>
            Skip setup
          </Button>
        </div>
      </div>
      <div className="mx-auto max-w-2xl px-4 py-10">
        <div className="mb-8">
          <Steps steps={steps.map((s) => labels[s])} current={idx} />
        </div>
        <LayerCard className="px-6 py-6 md:px-8 md:py-8">
          <div className="mb-6 grid gap-3">
            <span className="flex size-12 items-center justify-center rounded-xl bg-brand-tint text-brand">{icons[step]}</span>
            <div className="grid gap-1.5">
              <Text variant="heading" size="lg" as="h1">
                {step === "welcome" && `Welcome to ${me.data.instance_name || "Flare"}`}
                {step === "org" && "Create your organization"}
                {step === "security" && "Protect your account"}
                {step === "team" && "Invite your team"}
                {step === "domain" && "Add your first domain"}
              </Text>
              <Text variant="secondary">
                {step === "welcome" && "Authoritative DNS with audit trails, SSO and fine-grained access. Let us get you set up."}
                {step === "org" && "Organizations hold your domains, members and access policies."}
                {step === "security" && "Add an authenticator app so a stolen password is not enough to change your DNS."}
                {step === "team" && "Collaborate with roles that limit who can change what. You can always do this later."}
                {step === "domain" && "Enter a domain you own. We will scan its existing records and give you nameservers to switch to."}
              </Text>
            </div>
          </div>

          {step === "welcome" && (
            <form
              className="grid gap-5"
              onSubmit={async (e) => {
                e.preventDefault();
                if (name !== me.data!.user.name) await saveProfile.mutateAsync().catch(() => undefined);
                next();
              }}
            >
              <Input label="What should we call you?" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" autoFocus />
              <VirtualList
                ariaLabel="Highlights"
                items={[
                  "Add domains and import their existing DNS records automatically",
                  "Every change is recorded in a searchable, exportable audit log",
                  "Sign in with your company identity provider and provision users with SCIM",
                ]}
                itemKey={(t) => t}
                divided={false}
                gap={10}
                estimateSize={22}
                renderItem={(t) => (
                  <div className="flex items-start gap-2">
                    <span className="flex h-lh items-center">
                      <CheckCircleIcon size={16} weight="fill" className="text-brand" />
                    </span>
                    <Text>{t}</Text>
                  </div>
                )}
              />
              <div>
                <Button type="submit" variant="primary" icon={<ArrowRightIcon />} loading={saveProfile.isPending}>
                  Get started
                </Button>
              </div>
            </form>
          )}

          {step === "org" && (
            <form
              className="grid gap-5"
              onSubmit={async (e) => {
                e.preventDefault();
                await createOrg.mutateAsync();
                next();
              }}
            >
              <Input
                label="Organization name"
                placeholder="Acme Inc"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                autoFocus
                error={fieldError(createOrg.error, "name")}
              />
              {createOrg.error && !fieldError(createOrg.error, "name") && <Banner variant="error" size="sm" description={errorMessage(createOrg.error)} />}
              <div>
                <Button type="submit" variant="primary" loading={createOrg.isPending} disabled={!orgName.trim()}>
                  Create organization
                </Button>
              </div>
            </form>
          )}

          {step === "security" && (
            <div className="grid gap-5">
              <MfaSetup
                account={me.data.user.email}
                onDone={() => {
                  void qc.invalidateQueries({ queryKey: ["me"] });
                  next();
                }}
              />
              <div className="border-t border-kumo-line pt-4">
                <Button variant="ghost" onClick={next}>
                  Remind me later
                </Button>
              </div>
            </div>
          )}

          {step === "team" && (
            <div className="grid gap-5">
              {me.data.orgs.length > 1 && (
                <VirtualSelect
                  label="Organization"
                  options={me.data.orgs.filter((o) => o.permissions.includes("members.manage")).map((o) => ({ value: o.id, label: o.name }))}
                  value={orgId}
                  onChange={setOrgId}
                />
              )}
              <TagInput
                label="Email addresses"
                description="Press Enter or paste a comma-separated list."
                placeholder="teammate@company.com"
                value={emails}
                onValueChange={(v: string[]) => setEmails(v)}
                validateValue={(v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)}
              />
              <VirtualSelect
                label="Role"
                options={["admin", "editor", "viewer", "auditor"].map((r) => ({ value: r, label: roleLabels[r], description: roleDescriptions[r] }))}
                value={role}
                onChange={setRole}
              />
              {inviteResult && <Banner variant="default" size="sm" icon={<CheckCircleIcon weight="fill" />} description={inviteResult} />}
              {invite.error && <Banner variant="error" size="sm" description={errorMessage(invite.error)} />}
              <div className="flex gap-2">
                {inviteResult ? (
                  <Button variant="primary" onClick={next}>
                    Continue
                  </Button>
                ) : (
                  <>
                    <Button variant="primary" disabled={emails.length === 0 || !orgId} loading={invite.isPending} onClick={() => invite.mutate()}>
                      Send invitations
                    </Button>
                    <Button variant="ghost" onClick={next}>
                      Skip for now
                    </Button>
                  </>
                )}
              </div>
            </div>
          )}

          {step === "domain" && (
            <form
              className="grid gap-5"
              onSubmit={(e) => {
                e.preventDefault();
                const target = orgId || me.data!.orgs[0]?.id;
                void finish(`/${target}/add-site?domain=${encodeURIComponent(domain.trim())}`);
              }}
            >
              <Input label="Domain" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} autoFocus />
              <div className="flex gap-2">
                <Button type="submit" variant="primary" disabled={!domain.includes(".")} loading={complete.isPending}>
                  Continue
                </Button>
                <Button variant="ghost" onClick={() => finish()}>
                  Go to dashboard
                </Button>
              </div>
            </form>
          )}
        </LayerCard>
      </div>
    </div>
  );
}
