import { useEffect, useState } from "react";
import { Link } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { Banner, Button, Input } from "@cloudflare/kumo";
import { CheckCircleIcon } from "@phosphor-icons/react";
import { AuthLayout } from "../../layouts/AuthLayout";
import { api, errorMessage, primeCsrf } from "../../lib/api";
import { useConfig } from "../../lib/queries";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const config = useConfig();
  useEffect(() => {
    void primeCsrf();
  }, []);
  const send = useMutation({ mutationFn: () => api("/auth/password/forgot", { method: "POST", body: { email } }) });

  return (
    <AuthLayout
      title="Reset your password"
      description="We will email you a link to choose a new password."
      footer={
        <Link to="/login" className="text-kumo-link underline">
          Back to sign in
        </Link>
      }
    >
      {send.isSuccess ? (
        <div className="grid gap-3">
          <Banner
            variant="default"
            icon={<CheckCircleIcon weight="fill" />}
            title="Check your inbox"
            description={`If an account exists for ${email}, a reset link is on its way. The link expires in one hour.`}
          />
          {!config.data?.email_enabled && (
            <Banner variant="alert" size="sm" description="Email delivery is not configured on this instance. Ask an administrator to reset your access." />
          )}
        </div>
      ) : (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            send.mutate();
          }}
        >
          {send.error && <Banner variant="error" size="sm" description={errorMessage(send.error)} />}
          <Input label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus autoComplete="username" />
          <Button type="submit" variant="primary" loading={send.isPending} className="w-full justify-center">
            Send reset link
          </Button>
        </form>
      )}
    </AuthLayout>
  );
}
