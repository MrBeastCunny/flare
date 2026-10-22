import { useEffect, useRef, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@cloudflare/kumo";

interface VirtualListProps<T> {
  items: T[];
  itemKey: (item: T) => string;
  renderItem: (item: T, index: number) => ReactNode;
  estimateSize?: number;
  maxHeight?: string | number;
  className?: string;
  /** Divider lines between items. */
  divided?: boolean;
  empty?: ReactNode;
  onEndReached?: () => void;
  hasMore?: boolean;
  ariaLabel: string;
  /** Vertical space between items in pixels. */
  gap?: number;
}

/** Vertically virtualized list with measured (variable height) rows. */
export function VirtualList<T>({
  items,
  itemKey,
  renderItem,
  estimateSize = 56,
  maxHeight = 480,
  className,
  divided = true,
  empty,
  onEndReached,
  hasMore,
  ariaLabel,
  gap = 0,
}: VirtualListProps<T>) {
  const ref = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => ref.current,
    estimateSize: () => estimateSize,
    overscan: 8,
  });
  const vItems = virtualizer.getVirtualItems();
  const last = vItems.length ? vItems[vItems.length - 1].index : -1;
  useEffect(() => {
    if (onEndReached && hasMore && last >= items.length - 5 && items.length > 0) onEndReached();
  }, [last, items.length, hasMore, onEndReached]);

  if (items.length === 0) return <>{empty}</>;
  return (
    <div ref={ref} role="list" aria-label={ariaLabel} className={cn("overflow-y-auto p-px", className)} style={{ maxHeight }}>
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {vItems.map((vi) => (
          <div
            key={itemKey(items[vi.index])}
            role="listitem"
            data-index={vi.index}
            ref={virtualizer.measureElement}
            className={cn("absolute left-0 w-full", divided && vi.index > 0 && "border-t border-kumo-line")}
            style={{ transform: `translateY(${vi.start}px)`, paddingBottom: vi.index < items.length - 1 ? gap : 0 }}
          >
            {renderItem(items[vi.index], vi.index)}
          </div>
        ))}
      </div>
    </div>
  );
}
