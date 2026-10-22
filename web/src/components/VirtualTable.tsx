import { useEffect, useRef, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Loader, Table } from "@cloudflare/kumo";

export interface Column<T> {
  key: string;
  header: ReactNode;
  width?: string;
  align?: "left" | "right";
  className?: string;
  render: (row: T, index: number) => ReactNode;
}

interface Selection {
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  isSelectable?: (key: string) => boolean;
}

interface VirtualTableProps<T> {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  rowHeight?: number;
  /** Maximum height of the scroll viewport. Defaults to filling most of the screen. */
  maxHeight?: string;
  onRowClick?: (row: T) => void;
  selection?: Selection;
  empty?: ReactNode;
  loading?: boolean;
  /** Called when the user scrolls near the end (infinite loading). */
  onEndReached?: () => void;
  hasMore?: boolean;
  loadingMore?: boolean;
  rowClassName?: (row: T) => string | undefined;
  ariaLabel: string;
  /** Minimum table width before the viewport scrolls horizontally (narrow screens). */
  minWidth?: number;
}

/**
 * A Kumo table whose body rows are virtualized: only rows in (and near) the viewport
 * are mounted, with spacer rows preserving the scroll height.
 */
export function VirtualTable<T>({
  rows,
  columns,
  rowKey,
  rowHeight = 52,
  maxHeight = "calc(100vh - 300px)",
  onRowClick,
  selection,
  empty,
  loading,
  onEndReached,
  hasMore,
  loadingMore,
  rowClassName,
  ariaLabel,
  minWidth = 760,
}: VirtualTableProps<T>) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => rowHeight,
    overscan: 12,
  });
  const items = virtualizer.getVirtualItems();
  const total = virtualizer.getTotalSize();
  const paddingTop = items.length > 0 ? items[0].start : 0;
  const paddingBottom = items.length > 0 ? total - items[items.length - 1].end : 0;
  const lastIndex = items.length > 0 ? items[items.length - 1].index : -1;

  useEffect(() => {
    if (onEndReached && hasMore && !loadingMore && lastIndex >= rows.length - 10 && rows.length > 0) {
      onEndReached();
    }
  }, [lastIndex, rows.length, hasMore, loadingMore, onEndReached]);

  const selectableKeys = selection
    ? rows.map(rowKey).filter((k) => (selection.isSelectable ? selection.isSelectable(k) : true))
    : [];
  const selectedCount = selection ? selectableKeys.filter((k) => selection.selected.has(k)).length : 0;
  const colSpan = columns.length + (selection ? 1 : 0);

  return (
    <div
      ref={scrollRef}
      className="scroll-stable relative overflow-auto"
      style={{ maxHeight }}
      role="region"
      aria-label={ariaLabel}
      tabIndex={0}
    >
      <Table layout="fixed" className="w-full" style={{ minWidth }} aria-rowcount={rows.length}>
        <colgroup>
          {selection && <col style={{ width: 44 }} />}
          {columns.map((c) => (
            <col key={c.key} style={c.width ? { width: c.width } : undefined} />
          ))}
        </colgroup>
        <Table.Header sticky className="border-b border-kumo-line">
          <Table.Row>
            {selection && (
              <Table.CheckHead
                checked={selectableKeys.length > 0 && selectedCount === selectableKeys.length}
                indeterminate={selectedCount > 0 && selectedCount < selectableKeys.length}
                onCheckedChange={(checked) => selection.onChange(checked ? new Set(selectableKeys) : new Set())}
                aria-label="Select all rows"
              />
            )}
            {columns.map((c) => (
              <Table.Head key={c.key} className={c.align === "right" ? "text-right" : undefined}>
                {c.header}
              </Table.Head>
            ))}
          </Table.Row>
        </Table.Header>
        <Table.Body>
          {loading ? (
            <tr>
              <td colSpan={colSpan} className="py-16">
                <div className="flex justify-center">
                  <Loader />
                </div>
              </td>
            </tr>
          ) : rows.length === 0 ? (
            <tr>
              <td colSpan={colSpan} className="p-0">
                {empty}
              </td>
            </tr>
          ) : (
            <>
              {paddingTop > 0 && (
                <tr aria-hidden>
                  <td colSpan={colSpan} style={{ height: paddingTop, padding: 0, border: 0 }} />
                </tr>
              )}
              {items.map((vi) => {
                const row = rows[vi.index];
                const key = rowKey(row);
                const isSelected = selection?.selected.has(key) ?? false;
                return (
                  <Table.Row
                    key={key}
                    data-index={vi.index}
                    aria-rowindex={vi.index + 1}
                    variant={isSelected ? "selected" : "default"}
                    className={[onRowClick ? "cursor-pointer" : "", rowClassName?.(row) ?? ""].join(" ")}
                    style={{ height: rowHeight }}
                    onClick={onRowClick ? () => onRowClick(row) : undefined}
                  >
                    {selection && (
                      <Table.CheckCell
                        checked={isSelected}
                        disabled={selection.isSelectable ? !selection.isSelectable(key) : false}
                        onClick={(e) => e.stopPropagation()}
                        onCheckedChange={(checked) => {
                          const next = new Set(selection.selected);
                          if (checked) next.add(key);
                          else next.delete(key);
                          selection.onChange(next);
                        }}
                        aria-label="Select row"
                      />
                    )}
                    {columns.map((c) => (
                      <Table.Cell
                        key={c.key}
                        className={[c.align === "right" ? "text-right" : "", "overflow-hidden", c.className ?? ""].join(" ")}
                      >
                        <div className={c.align === "right" ? "flex min-w-0 justify-end" : "min-w-0 truncate"}>{c.render(row, vi.index)}</div>
                      </Table.Cell>
                    ))}
                  </Table.Row>
                );
              })}
              {paddingBottom > 0 && (
                <tr aria-hidden>
                  <td colSpan={colSpan} style={{ height: paddingBottom, padding: 0, border: 0 }} />
                </tr>
              )}
              {loadingMore && (
                <tr>
                  <td colSpan={colSpan} className="py-4">
                    <div className="flex justify-center">
                      <Loader size="sm" />
                    </div>
                  </td>
                </tr>
              )}
            </>
          )}
        </Table.Body>
      </Table>
    </div>
  );
}
