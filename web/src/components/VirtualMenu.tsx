import { useRef, useState, type ReactElement, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Button, DropdownMenu } from "@cloudflare/kumo";
import { CheckIcon, DotsThreeIcon } from "@phosphor-icons/react";

export interface MenuItem {
  key: string;
  label: string;
  icon?: ReactNode;
  onSelect?: () => void;
  danger?: boolean;
  disabled?: boolean;
  separatorBefore?: boolean;
  hidden?: boolean;
  /** Renders a check mark (for single-choice options such as the theme). */
  selected?: boolean;
  /** Non-interactive section heading. */
  kind?: "item" | "label";
}

const ITEM_HEIGHT = 34;
const LABEL_HEIGHT = 30;

/** Content of a dropdown menu rendered through a virtualizer. */
function VirtualMenuItems({ items }: { items: MenuItem[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const size = (i: number) => (items[i].kind === "label" ? LABEL_HEIGHT : ITEM_HEIGHT) + (items[i].separatorBefore ? 9 : 0);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => ref.current,
    estimateSize: size,
    overscan: 6,
    initialRect: { width: 220, height: 360 },
  });
  const height = Math.min(virtualizer.getTotalSize(), 360);
  return (
    <div ref={ref} className="-mx-1 overflow-x-hidden overflow-y-auto px-1" style={{ height }} role="presentation">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((vi) => {
          const it = items[vi.index];
          return (
            <div key={it.key} className="absolute left-0 w-full" style={{ transform: `translateY(${vi.start}px)` }}>
              {it.separatorBefore && <DropdownMenu.Separator />}
              {it.kind === "label" ? (
                <div className="px-2 pt-2 pb-1 text-xs font-medium text-kumo-subtle" style={{ height: LABEL_HEIGHT }}>
                  {it.label}
                </div>
              ) : (
                <DropdownMenu.Item
                  icon={it.icon}
                  variant={it.danger ? "danger" : "default"}
                  disabled={it.disabled}
                  onClick={() => it.onSelect?.()}
                >
                  <span className="flex flex-1 items-center justify-between gap-3">
                    {it.label}
                    {it.selected && <CheckIcon size={14} className="text-brand" />}
                  </span>
                </DropdownMenu.Item>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface ActionMenuProps {
  items: MenuItem[];
  label?: string;
  trigger?: ReactElement;
  /** Static content above the items, such as the signed-in user's name. */
  header?: ReactNode;
  minWidth?: number;
}

/** Dropdown menu whose items are virtualized (row actions, account and help menus). */
export function ActionMenu({ items, label = "Actions", trigger, header, minWidth = 192 }: ActionMenuProps) {
  const visible = items.filter((i) => !i.hidden);
  const [open, setOpen] = useState(false);
  if (visible.length === 0) return null;
  return (
    <span onClick={(e) => e.stopPropagation()} className="inline-flex">
      <DropdownMenu open={open} onOpenChange={setOpen}>
        <DropdownMenu.Trigger
          render={trigger ?? <Button variant="ghost" size="sm" shape="square" icon={<DotsThreeIcon size={18} weight="bold" />} aria-label={label} />}
        />
        <DropdownMenu.Content style={{ minWidth }}>
          {header}
          {header && <DropdownMenu.Separator />}
          {open && <VirtualMenuItems items={visible} />}
        </DropdownMenu.Content>
      </DropdownMenu>
    </span>
  );
}
