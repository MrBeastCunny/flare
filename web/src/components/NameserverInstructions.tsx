import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Banner, Button, ClipboardText, Text, cn } from "@cloudflare/kumo";
import { ArrowsClockwiseIcon, CheckCircleIcon, MinusCircleIcon, PlusCircleIcon, InfoIcon } from "@phosphor-icons/react";
import { api } from "../lib/api";
import { VirtualList } from "./VirtualList";
import { stripDot, timeAgo } from "../lib/format";
import { toast } from "../lib/toast";
import { keys } from "../lib/queries";
import type { Zone } from "../lib/types";

/** Registrar instructions shown while a zone is waiting for delegation. */
export function NameserverInstructions({ zone, currentNameservers, compact }: { zone: Zone; currentNameservers?: string[]; compact?: boolean }) {
  const qc = useQueryClient();
  const check = useMutation({
    mutationFn: () => api<Zone>(`/orgs/${zone.org_id}/zones/${zone.id}/check-nameservers`, { method: "POST" }),
    onSuccess: (z) => {
      void qc.invalidateQueries({ queryKey: keys.zones(zone.org_id) });
      if (z.status === "active") toast.success("Nameservers verified", `${stripDot(z.name)} is now active.`);
      else toast.info("Not updated yet", "Registrars can take up to 24 hours to publish nameserver changes.");
    },
    onError: (e) => toast.error(e, "Nameserver check failed"),
  });
  const observed = currentNameservers ?? zone.observed_nameservers;
  const assigned = zone.assigned_nameservers.map((n) => n.toLowerCase());
  const toRemove = observed.filter((n) => !assigned.includes(n.toLowerCase()));

  if (zone.status === "active") {
    return (
      <Banner
        variant="default"
        icon={<CheckCircleIcon weight="fill" />}
        title="Your domain is active"
        description={`DNS queries for ${stripDot(zone.name)} are answered by your nameservers.`}
      />
    );
  }

  return (
    <div className="grid gap-5">
      {!compact && (
        <div className="grid gap-1.5">
          <Text variant="heading" as="h3">
            Update your nameservers
          </Text>
          <Text variant="secondary">
            Sign in to your registrar (where you bought {stripDot(zone.name)}) and replace the current nameservers with the ones below.
          </Text>
        </div>
      )}
      <div className={cn("grid gap-4", !compact && "md:grid-cols-2")}>
        <div className="grid content-start gap-2">
          <div className="flex items-center gap-2">
            <MinusCircleIcon size={16} className="text-kumo-danger" />
            <Text bold>Remove these nameservers</Text>
          </div>
          {toRemove.length === 0 ? (
            <Text variant="secondary" size="sm">
              {observed.length === 0 ? "No nameservers detected yet. The domain may be newly registered." : "None to remove."}
            </Text>
          ) : (
            <VirtualList
              ariaLabel="Nameservers to remove"
              items={toRemove}
              itemKey={(n) => n}
              divided={false}
              gap={8}
              estimateSize={44}
              maxHeight={240}
              renderItem={(n) => <div className="rounded-md bg-kumo-recessed px-3 py-2 font-mono text-sm text-kumo-subtle line-through">{stripDot(n)}</div>}
            />
          )}
        </div>
        <div className="grid content-start gap-2">
          <div className="flex items-center gap-2">
            <PlusCircleIcon size={16} className="text-kumo-success" />
            <Text bold>Add these nameservers</Text>
          </div>
          <NameserverList nameservers={zone.assigned_nameservers} label="Nameservers to add" />
        </div>
      </div>
      <Banner
        variant="secondary"
        size="sm"
        className="items-start"
        icon={
          <span className="flex h-lh items-center">
            <InfoIcon weight="fill" />
          </span>
        }
        description="If DNSSEC is enabled at your registrar, turn it off before changing nameservers, then re-enable it from the DNSSEC page once the domain is active."
      />
      <div className="flex flex-wrap items-center gap-3">
        <Button icon={<ArrowsClockwiseIcon />} loading={check.isPending} onClick={() => check.mutate()}>
          Check nameservers now
        </Button>
        <Badge variant="neutral">Last checked {timeAgo(zone.last_ns_check_at)}</Badge>
        <Text variant="secondary" size="sm">
          We also check automatically every few minutes.
        </Text>
      </div>
    </div>
  );
}

/** Copyable list of nameserver hostnames. */
export function NameserverList({ nameservers, label = "Nameservers" }: { nameservers: string[]; label?: string }) {
  return (
    <VirtualList
      ariaLabel={label}
      items={nameservers}
      itemKey={(n) => n}
      divided={false}
      gap={8}
      estimateSize={36}
      maxHeight={240}
      renderItem={(n) => <ClipboardText text={stripDot(n)} size="sm" />}
    />
  );
}

/** One-line reminder for pages where the full registrar instructions would crowd the content. */
export function PendingDelegationBanner({ zone }: { zone: Zone }) {
  const [open, setOpen] = useState(false);
  if (zone.status === "active" || zone.kind === "Slave" || zone.kind === "Consumer") return null;
  return (
    <div className="grid gap-3">
      <Banner
        variant="alert"
        icon={<InfoIcon weight="fill" />}
        title={zone.status === "moved" ? "Nameservers changed away" : "Waiting for nameserver update"}
        description={`Queries for ${stripDot(zone.name)} are answered elsewhere until the registrar points at your nameservers.`}
        action={
          <Button size="sm" onClick={() => setOpen(!open)}>
            {open ? "Hide instructions" : "Show nameservers"}
          </Button>
        }
      />
      {open && (
        <div className="rounded-xl bg-kumo-base px-5 py-4 ring ring-kumo-line">
          <NameserverInstructions zone={zone} />
        </div>
      )}
    </div>
  );
}
