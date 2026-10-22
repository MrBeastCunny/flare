import { useEffect, useState } from "react";
import { Link, Navigate, useNavigate, useSearchParams } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input, Text } from "@cloudflare/kumo";
import { ShieldCheckIcon, WarningCircleIcon } from "@phosphor-icons/react";
import { AuthLayout } from "../../layouts/AuthLayout";
import { api, ApiError, errorMessage, primeCsrf } from "../../lib/api";
import { useConfig, useMe } from "../../lib/queries";

type Step = "credentials" | "mfa" | "sso";

export default function Login() {
  const [params] = useSearchParams();
  const next = params.get("next") || "/";
  const navigate = useNavigate();
  const qc = useQueryClient();
  const config = useConfig();
  const me = useMe();
  const [step, setStep] = useState<Step>("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [error, setError] = useState<string | null>(params.get("error"));

  useEffect(() => {
    void primeCsrf();
  }, []);

  const finish = async () => {
    await qc.invalidateQueries({ queryKey: ["me"] });
    navigate(next.startsWith("/") && !next.startsWith("//") ? next : "/", { replace: true });
  };

  const login = useMutation({
    mutationFn: () => api<{ mfa_required: boolean; mfa_token?: string }>("/auth/login", { method: "POST", body: { email, password } }),
    onSuccess: async (d) => {
      setError(null);
      if (d.mfa_required && d.mfa_token) {
        setMfaToken(d.mfa_token);
        setStep("mfa");
      } else {
        await finish();
      }
    },
    onError: (err) => {
      if (err instanceof ApiError && err.code === "sso_required" && typeof err.extra.sso_url === "string") {
        window.location.href = err.extra.sso_url as string;
        return;
      }
      setError(errorMessage(err));
    },
  });

  const verify = useMutation({
    mutationFn: () => api("/auth/login/mfa", { method: "POST", body: { mfa_token: mfaToken, code } }),
    onSuccess: finish,
    onError: (err) => {
      if (err instanceof ApiError && (err.code === "mfa_expired" || err.code === "mfa_locked")) {
        setStep("credentials");
        setPassword("");
        setCode("");
      }
      setError(errorMessage(err));
    },
  });

  const discover = useMutation({
    mutationFn: () => api<{ sso: boolean; url?: string }>("/auth/sso/discover", { method: "POST", body: { email, redirect: next } }),
    onSuccess: (d) => {
      if (d.sso && d.url) window.location.href = d.url;
      else setError("Single sign-on is not configured for this email domain. Sign in with your password instead.");
    },
    onError: (err) => setError(errorMessage(err)),
  });

  if (me.data) return <Navigate to={next} replace />;

  return (
    <AuthLayout
      title={step === "mfa" ? "Two-factor authentication" : `Sign in to ${config.data?.instance_name ?? "Flare"}`}
      description={
        step === "mfa"
          ? useRecovery
            ? "Enter one of your saved recovery codes."
            : "Enter the 6-digit code from your authenticator app."
          : step === "sso"
            ? "Enter your work email to continue with your identity provider."
            : "Manage your DNS zones, records and team."
      }
      footer={
        config.data?.signup_enabled && step === "credentials" ? (
          <>
            New here?{" "}
            <Link to="/signup" className="text-kumo-link underline">
              Create an account
            </Link>
          </>
        ) : undefined
      }
    >
      {error && (
        <div className="mb-4">
          <Banner variant="error" size="sm" icon={<WarningCircleIcon weight="fill" />} description={error} />
        </div>
      )}

      {step === "credentials" && (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            login.mutate();
          }}
        >
          <Input label={config.data?.ldap_enabled ? "Email or username" : "Email"} type={config.data?.ldap_enabled ? "text" : "email"} autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
          <div className="grid gap-1.5">
            <Input
              label="Password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <div className="text-right">
              <Link to="/forgot-password" className="text-sm text-kumo-link hover:underline">
                Forgot password?
              </Link>
            </div>
          </div>
          <Button type="submit" variant="primary" loading={login.isPending} className="w-full justify-center">
            Sign in
          </Button>
          <div className="flex items-center gap-3 text-xs text-kumo-subtle">
            <span className="h-px flex-1 bg-kumo-line" />
            or
            <span className="h-px flex-1 bg-kumo-line" />
          </div>
          <Button
            type="button"
            icon={<ShieldCheckIcon />}
            className="w-full justify-center"
            onClick={() => {
              setError(null);
              setStep("sso");
            }}
          >
            Continue with single sign-on
          </Button>
        </form>
      )}

      {step === "sso" && (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            discover.mutate();
          }}
        >
          <Input label="Work email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus />
          <Button type="submit" variant="primary" loading={discover.isPending} className="w-full justify-center">
            Continue
          </Button>
          <Button type="button" variant="ghost" onClick={() => setStep("credentials")} className="w-full justify-center">
            Sign in with password instead
          </Button>
        </form>
      )}

      {step === "mfa" && (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            verify.mutate();
          }}
        >
          <Input
            label={useRecovery ? "Recovery code" : "Authentication code"}
            value={code}
            onChange={(e) => setCode(useRecovery ? e.target.value : e.target.value.replace(/\D/g, "").slice(0, 6))}
            inputMode={useRecovery ? "text" : "numeric"}
            autoComplete="one-time-code"
            placeholder={useRecovery ? "xxxxx-xxxxx" : "123456"}
            className="font-mono"
            autoFocus
            required
          />
          <Button type="submit" variant="primary" loading={verify.isPending} className="w-full justify-center">
            Verify
          </Button>
          <button
            type="button"
            className="text-sm text-kumo-link hover:underline"
            onClick={() => {
              setUseRecovery(!useRecovery);
              setCode("");
            }}
          >
            {useRecovery ? "Use your authenticator app" : "Use a recovery code"}
          </button>
          <Text variant="secondary" size="sm" as="p">
            Signing in as {email}
          </Text>
        </form>
      )}
    </AuthLayout>
  );
}
