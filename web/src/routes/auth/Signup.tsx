import { useEffect, useState } from "react";
import { Link, Navigate, useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input } from "@cloudflare/kumo";
import { AuthLayout } from "../../layouts/AuthLayout";
import { api, ApiError, errorMessage, fieldError, primeCsrf } from "../../lib/api";
import { useConfig } from "../../lib/queries";
import { FullPageLoader } from "../../components/ui";

export default function Signup() {
  const config = useConfig();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  useEffect(() => {
    void primeCsrf();
  }, []);

  const signup = useMutation({
    mutationFn: () => api("/auth/signup", { method: "POST", body: { name, email, password } }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate("/onboarding", { replace: true });
    },
  });

  if (config.isLoading) return <FullPageLoader />;
  if (!config.data?.signup_enabled) return <Navigate to="/login" replace />;
  const min = config.data.password_min_length;
  const generic = signup.error instanceof ApiError && Object.keys(signup.error.fields).length === 0 ? errorMessage(signup.error) : null;

  return (
    <AuthLayout
      title="Create your account"
      description="Start managing DNS for your domains in minutes."
      footer={
        <>
          Already have an account?{" "}
          <Link to="/login" className="text-kumo-link underline">
            Sign in
          </Link>
        </>
      }
    >
      <form
        className="grid gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          signup.mutate();
        }}
      >
        {generic && <Banner variant="error" size="sm" description={generic} />}
        <Input label="Full name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" required autoFocus />
        <Input
          label="Work email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          autoComplete="email"
          required
          error={fieldError(signup.error, "email")}
        />
        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          required
          description={`At least ${min} characters.`}
          error={fieldError(signup.error, "password")}
        />
        <Button type="submit" variant="primary" loading={signup.isPending} className="w-full justify-center">
          Create account
        </Button>
      </form>
    </AuthLayout>
  );
}
