import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input, Text, LinkButton } from "@cloudflare/kumo";
import { EnvelopeSimpleOpenIcon } from "@phosphor-icons/react";
import { AuthLayout } from "../../layouts/AuthLayout";
import { api, ApiError, errorMessage, fieldError, primeCsrf } from "../../lib/api";
import { useConfig, useMe } from "../../lib/queries";
import { FullPageLoader, RoleBadge } from "../../components/ui";

interface InviteInfo {
  org_name: string;
  email: string;
  role: string;
  inviter: string;
  expires_at: string;
  user_exists: boolean;
  sso_required: boolean;
}

export default function AcceptInvite() {
  const { token = "" } = useParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const config = useConfig();
  const me = useMe();
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  useEffect(() => {
    void primeCsrf();
  }, []);

  const invite = useQuery({ queryKey: ["invite", token], queryFn: () => api<InviteInfo>(`/invites/${token}`), retry: false });
  const accept = useMutation({
    mutationFn: () =>
      api<{ org_id: string }>(`/invites/${token}/accept`, { method: "POST", body: me.data ? undefined : { name, password } }),
    onSuccess: async (d) => {
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate(`/${d.org_id}`, { replace: true });
    },
  });

  if (invite.isLoading || me.isLoading) return <FullPageLoader />;
  if (invite.error || !invite.data) {
    return (
      <AuthLayout title="Invitation unavailable" footer={<Link to="/login" className="text-kumo-link underline">Go to sign in</Link>}>
        <Banner variant="error" size="sm" description={errorMessage(invite.error) || "This invitation is invalid or has expired."} />
      </AuthLayout>
    );
  }
  const inv = invite.data;
  const signedInAs = me.data?.user.email;
  const wrongAccount = signedInAs && signedInAs.toLowerCase() !== inv.email.toLowerCase();
  const generic = accept.error instanceof ApiError && !accept.error.fields.password ? errorMessage(accept.error) : null;

  return (
    <AuthLayout title={`Join ${inv.org_name}`} description={inv.inviter ? `${inv.inviter} invited you to collaborate.` : undefined}>
      <div className="mb-5 flex items-center gap-3 rounded-lg bg-kumo-recessed px-4 py-3">
        <EnvelopeSimpleOpenIcon size={22} className="text-brand" />
        <div className="grid min-w-0 gap-0.5">
          <Text truncate>{inv.email}</Text>
          <div>
            <RoleBadge role={inv.role} />
          </div>
        </div>
      </div>
      {generic && (
        <div className="mb-4">
          <Banner variant="error" size="sm" description={generic} />
        </div>
      )}
      {wrongAccount ? (
        <Banner
          variant="alert"
          size="sm"
          description={`You are signed in as ${signedInAs}. Sign out and sign in as ${inv.email} to accept this invitation.`}
        />
      ) : me.data ? (
        <Button variant="primary" loading={accept.isPending} onClick={() => accept.mutate()} className="w-full justify-center">
          Accept invitation
        </Button>
      ) : inv.sso_required ? (
        <div className="grid gap-3">
          <Text variant="secondary">Your organization uses single sign-on. Sign in with SSO, then open this link again.</Text>
          <LinkButton href={`/login?next=${encodeURIComponent(`/invite/${token}`)}`} variant="primary" className="w-full justify-center">
            Sign in with SSO
          </LinkButton>
        </div>
      ) : inv.user_exists ? (
        <div className="grid gap-3">
          <Text variant="secondary">You already have an account. Sign in to accept.</Text>
          <LinkButton href={`/login?next=${encodeURIComponent(`/invite/${token}`)}`} variant="primary" className="w-full justify-center">
            Sign in to accept
          </LinkButton>
        </div>
      ) : (
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            accept.mutate();
          }}
        >
          <Input label="Full name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" required autoFocus />
          <Input
            label="Create a password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            required
            description={`At least ${config.data?.password_min_length ?? 12} characters.`}
            error={fieldError(accept.error, "password")}
          />
          <Button type="submit" variant="primary" loading={accept.isPending} className="w-full justify-center">
            Create account and join
          </Button>
        </form>
      )}
    </AuthLayout>
  );
}
