import { Outlet } from "react-router";
import { Empty, LinkButton } from "@cloudflare/kumo";
import { GlobeHemisphereWestIcon } from "@phosphor-icons/react";
import { useCurrentZone } from "../lib/queries";
import { FullPageLoader } from "../components/ui";

/** Resolves the zone from the URL before rendering zone pages. */
export function ZoneLayout() {
  const { zone, isLoading, notFound, orgId } = useCurrentZone();
  if (isLoading) return <FullPageLoader />;
  if (notFound || !zone) {
    return (
      <div className="py-16">
        <Empty
          icon={<GlobeHemisphereWestIcon size={48} className="text-kumo-inactive" />}
          title="Domain not found"
          description="This domain does not exist in the organization, or you do not have access to it."
          contents={<LinkButton href={`/${orgId}`}>Back to domains</LinkButton>}
        />
      </div>
    );
  }
  return <Outlet />;
}
