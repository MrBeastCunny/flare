import { useNavigate } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Banner, Button } from "@cloudflare/kumo";
import { ShieldWarningIcon } from "@phosphor-icons/react";
import { AuthLayout } from "../../layouts/AuthLayout";
import { MfaSetup } from "../../components/MfaSetup";
import { useMe } from "../../lib/queries";
import { api } from "../../lib/api";

/** Blocking page shown when the instance or an organization requires 2FA. */
export default function EnforceMFA() {
  const me = useMe();
  const qc = useQueryClient();
  const navigate = useNavigate();
  return (
    <AuthLayout wide title="Secure your account" description="Two-factor authentication is required before you can continue.">
      <div className="mb-5">
        <Banner
          variant="alert"
          icon={<ShieldWarningIcon weight="fill" />}
          description="Your administrator requires an authenticator app for every member. This keeps your DNS safe from account takeover."
        />
      </div>
      <MfaSetup
        account={me.data?.user.email ?? ""}
        onDone={async () => {
          await qc.invalidateQueries({ queryKey: ["me"] });
          navigate("/", { replace: true });
        }}
      />
      <div className="mt-6 border-t border-kumo-line pt-4">
        <Button
          variant="ghost"
          onClick={async () => {
            await api("/auth/logout", { method: "POST" }).catch(() => undefined);
            qc.clear();
            navigate("/login", { replace: true });
          }}
        >
          Log out
        </Button>
      </div>
    </AuthLayout>
  );
}
