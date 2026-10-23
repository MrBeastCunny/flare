import type { InstanceRole, TokenRole } from "./types";

export const tokenRoles: { value: TokenRole; label: string; description: string }[] = [
  { value: "viewer", label: "Read only", description: "List zones and read DNS records." },
  { value: "editor", label: "DNS edit", description: "Edit DNS records, DNSSEC and zone settings." },
  { value: "admin", label: "Zone admin", description: "Everything above, plus creating and deleting zones and reading the audit log." },
  {
    value: "org_admin",
    label: "Organization admin",
    description: "Everything above, plus organization settings, members, invitations and webhooks. Never API tokens, SSO or deleting the organization.",
  },
];

export const instanceRoles: { value: InstanceRole; label: string; description: string }[] = [
  { value: "none", label: "None", description: "Works only inside the organizations below." },
  { value: "orgs", label: "Manage organizations", description: "Also create organizations and change their limits and placement." },
  { value: "admin", label: "Full administrator", description: "Also use every instance administration endpoint except creating API tokens." },
];

export const tokenRoleLabel = (r: string) => tokenRoles.find((t) => t.value === r)?.label ?? r;
export const instanceRoleLabel = (r: string) => instanceRoles.find((t) => t.value === r)?.label ?? r;
