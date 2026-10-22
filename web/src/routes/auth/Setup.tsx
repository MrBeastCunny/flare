import { useEffect, useState } from "react";
import { Navigate, useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input, SensitiveInput, TagInput, Text, Switch } from "@cloudflare/kumo";
import { CheckCircleIcon, HardDrivesIcon, WarningCircleIcon } from "@phosphor-icons/react";
import { AuthLayout } from "../../layouts/AuthLayout";
import { Steps } from "../../components/Steps";
import { VirtualList } from "../../components/VirtualList";
import { api, ApiError, errorMessage, primeCsrf } from "../../lib/api";
import { useConfig } from "../../lib/queries";
import { FullPageLoader, Mono } from "../../components/ui";

const STEPS = ["Instance", "Administrator", "DNS server", "Nameservers", "Review"];

export default function Setup() {
  const config = useConfig();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [step, setStep] = useState(0);
  const [instanceName, setInstanceName] = useState("Flare");
  const [orgName, setOrgName] = useState("");
  const [adminName, setAdminName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [useBootstrap, setUseBootstrap] = useState(true);
  const [server, setServer] = useState({ name: "Primary", api_url: "", api_key: "", server_id: "localhost" });
  const [nsName, setNsName] = useState("Default");
  const [nameservers, setNameservers] = useState<string[]>([]);
  const [hostmaster, setHostmaster] = useState("");
  const [testResult, setTestResult] = useState<{ ok: boolean; version?: string; error?: string } | null>(null);

  useEffect(() => {
    void primeCsrf();
  }, []);

  const test = useMutation({
    mutationFn: () =>
      api<{ ok: boolean; version?: string; error?: string }>("/setup/test-server", {
        method: "POST",
        body: useBootstrap && config.data?.bootstrap_server ? {} : { api_url: server.api_url, api_key: server.api_key, server_id: server.server_id },
      }),
    onSuccess: setTestResult,
    onError: (e) => setTestResult({ ok: false, error: errorMessage(e) }),
  });

  const submit = useMutation({
    mutationFn: () =>
      api("/setup", {
        method: "POST",
        body: {
          instance_name: instanceName,
          admin: { name: adminName, email, password },
          org_name: orgName,
          server: useBootstrap && config.data?.bootstrap_server ? null : server,
          nameservers: { name: nsName, nameservers, hostmaster },
        },
      }),
    onSuccess: async () => {
      await qc.invalidateQueries();
      navigate("/onboarding", { replace: true });
    },
  });

  useEffect(() => {
    if (step === 2 && config.data?.bootstrap_server && useBootstrap && !testResult) test.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step]);

  if (config.isLoading) return <FullPageLoader />;
  if (!config.data?.setup_required) return <Navigate to="/login" replace />;

  const min = config.data.password_min_length;
  const canNext = [
    instanceName.trim().length > 0 && orgName.trim().length > 0,
    adminName.trim() && /\S+@\S+\.\S+/.test(email) && password.length >= min,
    testResult?.ok === true,
    nameservers.length >= 2,
    true,
  ][step];

  const fieldErr = (f: string) => (submit.error instanceof ApiError ? submit.error.fields[f] : undefined);

  return (
    <AuthLayout wide title="Set up your DNS platform" description="A few details and you are ready to host zones.">
      <div className="mb-6">
        <Steps steps={STEPS} current={step} />
      </div>

      {step === 0 && (
        <div className="grid gap-4">
          <Input
            label="Product name"
            description="Shown in the dashboard header, emails and authenticator apps."
            value={instanceName}
            onChange={(e) => setInstanceName(e.target.value)}
            autoFocus
          />
          <Input
            label="Your organization"
            description="The first organization. You can create more, and invite teammates, later."
            placeholder="Acme Inc"
            value={orgName}
            onChange={(e) => setOrgName(e.target.value)}
          />
        </div>
      )}

      {step === 1 && (
        <div className="grid gap-4">
          <Text variant="secondary">This account becomes the instance administrator, with access to global settings and all DNS servers.</Text>
          <Input label="Full name" value={adminName} onChange={(e) => setAdminName(e.target.value)} autoComplete="name" autoFocus />
          <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" error={fieldErr("admin.email")} />
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            description={`At least ${min} characters. You will be prompted to add two-factor authentication.`}
            error={fieldErr("admin.password")}
          />
        </div>
      )}

      {step === 2 && (
        <div className="grid gap-4">
          <Text variant="secondary">Connect the PowerDNS Authoritative Server that will host your zones. You can add more servers later.</Text>
          {config.data.bootstrap_server && (
            <Switch
              label="Use the server configured by the deployment (recommended)"
              checked={useBootstrap}
              onCheckedChange={(v: boolean) => {
                setUseBootstrap(v);
                setTestResult(null);
              }}
            />
          )}
          {(!config.data.bootstrap_server || !useBootstrap) && (
            <>
              <Input label="Server name" value={server.name} onChange={(e) => setServer({ ...server, name: e.target.value })} />
              <Input
                label="API URL"
                placeholder="http://pdns:8081"
                value={server.api_url}
                onChange={(e) => {
                  setServer({ ...server, api_url: e.target.value });
                  setTestResult(null);
                }}
                error={fieldErr("server.api_url")}
              />
              <SensitiveInput
                label="API key"
                value={server.api_key}
                onValueChange={(v: string) => {
                  setServer({ ...server, api_key: v });
                  setTestResult(null);
                }}
              />
              <Input label="Server ID" value={server.server_id} onChange={(e) => setServer({ ...server, server_id: e.target.value })} />
            </>
          )}
          <div className="flex items-center gap-3">
            <Button icon={<HardDrivesIcon />} loading={test.isPending} onClick={() => test.mutate()}>
              Test connection
            </Button>
            {testResult?.ok && (
              <span className="flex items-center gap-1.5 text-kumo-success">
                <CheckCircleIcon weight="fill" /> Connected to PowerDNS {testResult.version}
              </span>
            )}
          </div>
          {testResult && !testResult.ok && <Banner variant="error" size="sm" icon={<WarningCircleIcon weight="fill" />} description={testResult.error} />}
        </div>
      )}

      {step === 3 && (
        <div className="grid gap-4">
          <Text variant="secondary">
            When someone adds a domain, they are asked to point it at these nameservers at their registrar. Use hostnames that resolve to your
            PowerDNS servers.
          </Text>
          <Input label="Set name" value={nsName} onChange={(e) => setNsName(e.target.value)} />
          <TagInput
            label="Nameservers"
            description="Press Enter after each hostname. At least two are required."
            placeholder="ns1.example.net"
            value={nameservers}
            onValueChange={(v: string[]) => setNameservers(v)}
            validateValue={(v: string) => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(v.trim())}
            error={fieldErr("nameservers.nameservers")}
          />
          <Input
            label="Hostmaster email"
            description="Used in SOA records as the zone contact."
            placeholder="hostmaster@example.net"
            type="email"
            value={hostmaster}
            onChange={(e) => setHostmaster(e.target.value)}
            required={false}
          />
        </div>
      )}

      {step === 4 && (
        <div className="grid gap-3">
          <VirtualList
            ariaLabel="Review"
            divided={false}
            gap={8}
            estimateSize={24}
            itemKey={([k]) => k}
            items={[
              ["Product name", instanceName],
              ["Organization", orgName],
              ["Administrator", `${adminName} (${email})`],
              ["DNS server", useBootstrap && config.data.bootstrap_server ? "Deployment default" : server.api_url],
              ["Nameservers", nameservers.join(", ")],
            ]}
            renderItem={([k, v]) => (
              <div className="grid grid-cols-[140px_1fr] gap-3 text-sm">
                <span className="text-kumo-subtle">{k}</span>
                <span className="min-w-0 break-all">{k === "Nameservers" ? <Mono>{v}</Mono> : v}</span>
              </div>
            )}
          />
          {submit.error && <Banner variant="error" size="sm" description={errorMessage(submit.error)} />}
        </div>
      )}

      <div className="mt-8 flex justify-between gap-2 border-t border-kumo-line pt-5">
        <Button variant="ghost" disabled={step === 0} onClick={() => setStep(step - 1)}>
          Back
        </Button>
        {step < STEPS.length - 1 ? (
          <Button variant="primary" disabled={!canNext} onClick={() => setStep(step + 1)}>
            Continue
          </Button>
        ) : (
          <Button variant="primary" loading={submit.isPending} onClick={() => submit.mutate()}>
            Complete setup
          </Button>
        )}
      </div>
    </AuthLayout>
  );
}
