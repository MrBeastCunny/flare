import type { ReactNode } from "react";
import { LayerCard, Text } from "@cloudflare/kumo";
import { Logo } from "../components/ui";
import { useConfig } from "../lib/queries";

/** Centered card layout for sign-in, sign-up and setup flows. */
export function AuthLayout({
  title,
  description,
  children,
  footer,
  wide,
}: {
  title: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const config = useConfig();
  return (
    <div className="flex min-h-full flex-col bg-kumo-canvas">
      <div className="border-b border-kumo-line bg-kumo-base">
        <div className="mx-auto flex h-14 max-w-6xl items-center px-6">
          <Logo name={config.data?.instance_name ?? "Flare"} />
        </div>
      </div>
      <div className="flex flex-1 items-start justify-center px-4 py-12 md:py-20">
        <div className={wide ? "w-full max-w-2xl" : "w-full max-w-md"}>
          <div className="mb-6 grid gap-1.5 text-center">
            <Text variant="heading" size="lg" as="h1">
              {title}
            </Text>
            {description && <Text variant="secondary">{description}</Text>}
          </div>
          <LayerCard className="px-6 py-6 shadow-sm">{children}</LayerCard>
          {footer && <div className="mt-6 text-center text-sm text-kumo-subtle">{footer}</div>}
        </div>
      </div>
      <div className="py-6 text-center text-xs text-kumo-subtle">
        {config.data?.support_email ? (
          <>
            Need help? <a className="underline" href={`mailto:${config.data.support_email}`}>{config.data.support_email}</a>
          </>
        ) : (
          <>Secure DNS management</>
        )}
      </div>
    </div>
  );
}
