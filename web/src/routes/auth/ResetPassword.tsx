import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { Banner, Button, Input, LinkButton } from "@cloudflare/kumo";
import { CheckCircleIcon } from "@phosphor-icons/react";
import { AuthLayout } from "../../layouts/AuthLayout";
import { api, ApiError, errorMessage, fieldError, primeCsrf } from "../../lib/api";
import { useConfig } from "../../lib/queries";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";
  const config = useConfig();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  useEffect(() => {
    void primeCsrf();
  }, []);
  const reset = useMutation({ mutationFn: () => api("/auth/password/reset", { method: "POST", body: { token, password } }) });
  const mismatch = confirm.length > 0 && confirm !== password;
  const generic = reset.error instanceof ApiError && !reset.error.fields.password ? errorMessage(reset.error) : null;

  return (
    <AuthLayout title="Choose a new password" footer={<Link to="/login" className="text-kumo-link underline">Back to sign in</Link>}>
      {reset.isSuccess ? (
        <div className="grid gap-4">
          <Banner variant="default" icon={<CheckCircleIcon weight="fill" />} title="Password updated" description="All other sessions were signed out." />
          <LinkButton href="/login" variant="primary" className="w-full justify-center">
            Sign in
          </LinkButton>
        </div>
      ) : (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (!mismatch) reset.mutate();
          }}
        >
          {!token && <Banner variant="error" size="sm" description="This reset link is incomplete. Request a new one." />}
          {generic && <Banner variant="error" size="sm" description={generic} />}
          <Input
            label="New password"
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoFocus
            description={`At least ${config.data?.password_min_length ?? 12} characters.`}
            error={fieldError(reset.error, "password")}
          />
          <Input
            label="Confirm password"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            error={mismatch ? "Passwords do not match" : undefined}
          />
          <Button type="submit" variant="primary" loading={reset.isPending} disabled={!token || mismatch} className="w-full justify-center">
            Update password
          </Button>
        </form>
      )}
    </AuthLayout>
  );
}
