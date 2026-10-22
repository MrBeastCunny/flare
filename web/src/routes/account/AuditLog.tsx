import { PageHeader } from "../../components/ui";
import { AuditLogView } from "../../components/AuditLogView";
import { useOrgId } from "../../lib/queries";

export default function AuditLog() {
  const orgId = useOrgId();
  return (
    <div>
      <PageHeader
        title="Audit log"
        description="A complete record of sign-ins, DNS changes and administrative actions. Entries are retained according to your instance policy."
      />
      <AuditLogView path={`/orgs/${orgId}/audit-logs`} exportPath={`/orgs/${orgId}/audit-logs/export`} scope={`org:${orgId}`} />
    </div>
  );
}
