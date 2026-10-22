import { isRouteErrorResponse, useRouteError } from "react-router";
import { Button, Empty, LinkButton } from "@cloudflare/kumo";
import { CompassIcon, WarningIcon } from "@phosphor-icons/react";
import { Logo } from "../components/ui";

export function NotFound() {
  return (
    <div className="flex min-h-full flex-col items-center justify-center gap-8 p-8">
      <Logo />
      <Empty
        icon={<CompassIcon size={48} className="text-kumo-inactive" />}
        title="Page not found"
        description="The page you are looking for does not exist or has moved."
        contents={
          <LinkButton variant="primary" href="/">
            Go to dashboard
          </LinkButton>
        }
      />
    </div>
  );
}

export function RouteError() {
  const error = useRouteError();
  const message = isRouteErrorResponse(error) ? `${error.status} ${error.statusText}` : error instanceof Error ? error.message : "Unexpected error";
  const chunk = error instanceof Error && /dynamically imported module|Failed to fetch/.test(error.message);
  return (
    <div className="flex min-h-full flex-col items-center justify-center gap-8 p-8">
      <Logo />
      <Empty
        icon={<WarningIcon size={48} className="text-kumo-inactive" />}
        title={chunk ? "A new version is available" : "Something went wrong"}
        description={chunk ? "Reload the page to get the latest version of the dashboard." : message}
        contents={
          <Button variant="primary" onClick={() => window.location.reload()}>
            Reload
          </Button>
        }
      />
    </div>
  );
}
