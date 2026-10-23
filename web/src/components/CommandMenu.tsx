import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Dialog, cn, Loader } from "@cloudflare/kumo";
import {
  MagnifyingGlassIcon,
  GlobeHemisphereWestIcon,
  ListBulletsIcon,
  ArrowRightIcon,
  UsersThreeIcon,
  ClockCounterClockwiseIcon,
  KeyIcon,
  PlusIcon,
  GearSixIcon,
  UserCircleIcon,
} from "@phosphor-icons/react";
import { api } from "../lib/api";
import { useZones } from "../lib/queries";
import { stripDot } from "../lib/format";

interface Item {
  id: string;
  group: string;
  title: string;
  subtitle?: string;
  icon: ReactNode;
  to: string;
}

const ROW = 44;

export function CommandMenu({ open, onOpenChange, orgId }: { open: boolean; onOpenChange: (o: boolean) => void; orgId?: string }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const [debounced, setDebounced] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);
  const zones = useZones(orgId ?? "");

  useEffect(() => {
    const t = setTimeout(() => setDebounced(q.trim()), 200);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => {
    if (!open) setQ("");
  }, [open]);

  const search = useQuery({
    queryKey: ["search", orgId, debounced],
    queryFn: () =>
      api<{ records: { zone_id: string; zone_name: string; name: string; type: string; content: string }[] }>(`/orgs/${orgId}/search`, {
        query: { q: debounced },
      }),
    enabled: open && !!orgId && debounced.length >= 2,
  });

  const items = useMemo<Item[]>(() => {
    const query = q.trim().toLowerCase();
    const out: Item[] = [];
    if (orgId) {
      const pages: Item[] = [
        { id: "p-domains", group: "Pages", title: "Domains", icon: <GlobeHemisphereWestIcon />, to: `/${orgId}` },
        { id: "p-add", group: "Pages", title: "Add a domain", icon: <PlusIcon />, to: `/${orgId}/add-site` },
        { id: "p-members", group: "Pages", title: "Members", icon: <UsersThreeIcon />, to: `/${orgId}/members` },
        { id: "p-audit", group: "Pages", title: "Audit log", icon: <ClockCounterClockwiseIcon />, to: `/${orgId}/audit-log` },
        { id: "p-tokens", group: "Pages", title: "API tokens", icon: <KeyIcon />, to: `/${orgId}/api-tokens` },
        { id: "p-settings", group: "Pages", title: "Organization settings", icon: <GearSixIcon />, to: `/${orgId}/settings` },
        { id: "p-profile", group: "Pages", title: "My profile", icon: <UserCircleIcon />, to: `/profile` },
      ];
      out.push(...pages.filter((p) => !query || p.title.toLowerCase().includes(query)));
      for (const z of zones.data ?? []) {
        const name = stripDot(z.name);
        if (!query || name.includes(query)) {
          out.push({ id: "z-" + z.id, group: "Domains", title: name, subtitle: "DNS records", icon: <GlobeHemisphereWestIcon />, to: `/${orgId}/${name}/dns` });
        }
      }
      for (const r of search.data?.records ?? []) {
        out.push({
          id: `r-${r.zone_id}-${r.name}-${r.type}-${r.content}`,
          group: "DNS records",
          title: `${stripDot(r.name)}  ${r.type}`,
          subtitle: r.content,
          icon: <ListBulletsIcon />,
          to: `/${orgId}/${stripDot(r.zone_name)}/dns?search=${encodeURIComponent(stripDot(r.name))}`,
        });
      }
    }
    return out;
  }, [q, orgId, zones.data, search.data]);

  useEffect(() => setActive(0), [q, search.data]);

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => ROW,
    overscan: 10,
  });

  const go = (it: Item) => {
    onOpenChange(false);
    navigate(it.to);
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const n = Math.min(items.length - 1, active + 1);
      setActive(n);
      virtualizer.scrollToIndex(n);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const n = Math.max(0, active - 1);
      setActive(n);
      virtualizer.scrollToIndex(n);
    } else if (e.key === "Enter" && items[active]) {
      e.preventDefault();
      go(items[active]);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog size="xl" className="overflow-hidden p-0">
        <Dialog.Title className="sr-only">Search</Dialog.Title>
        <div className="flex items-center gap-3 border-b border-kumo-line px-4">
          <MagnifyingGlassIcon size={18} className="text-kumo-subtle" />
          <input
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Search domains, DNS records and pages"
            aria-label="Search"
            role="combobox"
            aria-expanded
            aria-controls="command-list"
            aria-activedescendant={items[active] ? `cmd-${active}` : undefined}
            className="h-13 w-full bg-transparent text-base text-kumo-default outline-none placeholder:text-kumo-placeholder"
          />
          {search.isFetching && <Loader size="sm" />}
        </div>
        <div ref={listRef} id="command-list" role="listbox" className="overflow-x-hidden overflow-y-auto p-2" style={{ height: 380 }}>
          {items.length === 0 ? (
            <div className="px-3 py-10 text-center text-kumo-subtle">{q.length < 2 ? "Type to search" : "No results"}</div>
          ) : (
            <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
              {virtualizer.getVirtualItems().map((vi) => {
                const it = items[vi.index];
                const showGroup = vi.index === 0 || items[vi.index - 1].group !== it.group;
                return (
                  <div
                    key={it.id}
                    id={`cmd-${vi.index}`}
                    role="option"
                    aria-selected={vi.index === active}
                    onMouseMove={() => setActive(vi.index)}
                    onClick={() => go(it)}
                    className={cn(
                      "absolute left-0 flex w-full cursor-pointer items-center gap-3 rounded-md px-3",
                      vi.index === active && "bg-kumo-tint",
                    )}
                    style={{ transform: `translateY(${vi.start}px)`, height: ROW }}
                  >
                    <span className="flex size-4 items-center text-kumo-subtle">{it.icon}</span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-kumo-default">{it.title}</span>
                      {it.subtitle && <span className="block truncate font-mono text-xs text-kumo-subtle">{it.subtitle}</span>}
                    </span>
                    {showGroup && <span className="shrink-0 text-xs text-kumo-subtle">{it.group}</span>}
                    {vi.index === active && <ArrowRightIcon size={14} className="shrink-0 text-kumo-subtle" />}
                  </div>
                );
              })}
            </div>
          )}
        </div>
        <div className="flex items-center gap-4 border-t border-kumo-line bg-kumo-elevated px-4 py-2 text-xs text-kumo-subtle">
          <span>Up and down to navigate</span>
          <span>Enter to open</span>
          <span>Esc to close</span>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}
