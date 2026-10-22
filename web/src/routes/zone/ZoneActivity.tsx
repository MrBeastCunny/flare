import { PageHeader } from "../../components/ui";
import { AuditLogView } from "../../components/AuditLogView";
import { useSearchParams } from "react-router";
import { useCurrentZone } from "../../lib/queries";
import { stripDot } from "../../lib/format";

export default function ZoneActivity() {
  const { zone, orgId } = useCurrentZone();
  const [params] = useSearchParams();
  if (!zone) return null;
  return (
    <div>
      <PageHeader title="Activity" description={`Every change made to ${stripDot(zone.name)}, by whom and from where.`} />
      <AuditLogView path={`/orgs/${orgId}/zones/${zone.id}/audit-logs`} scope={`zone:${zone.id}`} compact initialQuery={params.get("q") ?? ""} />
    </div>
  );
}
