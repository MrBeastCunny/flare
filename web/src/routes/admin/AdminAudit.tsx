import { PageHeader } from "../../components/ui";
import { AuditLogView } from "../../components/AuditLogView";

export default function AdminAudit() {
  return (
    <div>
      <PageHeader title="Instance audit log" description="Events from every organization, plus sign-ins and instance administration." />
      <AuditLogView path="/admin/audit-logs" exportPath="/admin/audit-logs/export" scope="admin" showOrg />
    </div>
  );
}
