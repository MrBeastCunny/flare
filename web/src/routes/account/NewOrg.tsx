import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Input } from "@cloudflare/kumo";
import { PageHeader, Section } from "../../components/ui";
import { api, errorMessage, fieldError } from "../../lib/api";
import type { Org } from "../../lib/types";

export default function NewOrg() {
  const [name, setName] = useState("");
  const navigate = useNavigate();
  const qc = useQueryClient();
  const create = useMutation({
    mutationFn: () => api<Org>("/orgs", { method: "POST", body: { name } }),
    onSuccess: async (o) => {
      await qc.invalidateQueries({ queryKey: ["me"] });
      navigate(`/${o.id}`);
    },
  });
  return (
    <div className="max-w-2xl">
      <PageHeader title="Create organization" description="Organizations keep domains, members and access policies separate." />
      <Section>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate();
          }}
        >
          <Input label="Organization name" placeholder="Acme Inc" value={name} onChange={(e) => setName(e.target.value)} autoFocus error={fieldError(create.error, "name")} />
          {create.error && !fieldError(create.error, "name") && <Banner variant="error" size="sm" description={errorMessage(create.error)} />}
          <div>
            <Button type="submit" variant="primary" loading={create.isPending} disabled={!name.trim()}>
              Create organization
            </Button>
          </div>
        </form>
      </Section>
    </div>
  );
}
