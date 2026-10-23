import React, { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Popover, Label, cn, inputVariants } from "@cloudflare/kumo";
import { CaretUpDownIcon, CheckIcon, MagnifyingGlassIcon } from "@phosphor-icons/react";

export interface Option<V extends string | number = string> {
  value: V;
  label: string;
  description?: string;
  disabled?: boolean;
  /** Extra text matched by search. */
  keywords?: string;
}

interface BaseProps<V extends string | number> {
  options: Option<V>[];
  label?: ReactNode;
  description?: ReactNode;
  error?: string;
  placeholder?: string;
  searchable?: boolean;
  searchPlaceholder?: string;
  disabled?: boolean;
  size?: "sm" | "base";
  className?: string;
  /** Width of the popup. Defaults to the trigger width. */
  popupWidth?: number;
  renderOption?: (o: Option<V>) => ReactNode;
  emptyText?: string;
  required?: boolean;
  "aria-label"?: string;
  id?: string;
  /** Replaces the default input-styled trigger. Must render a button element. */
  renderTrigger?: (text: string, open: boolean) => React.ReactElement;
  /** Content pinned below the list (for example a "create new" action). */
  footer?: (close: () => void) => ReactNode;
  side?: "bottom" | "top";
  align?: "start" | "end";
}

interface SingleProps<V extends string | number> extends BaseProps<V> {
  multiple?: false;
  value: V | null | undefined;
  onChange: (value: V) => void;
}

interface MultiProps<V extends string | number> extends BaseProps<V> {
  multiple: true;
  value: V[];
  onChange: (value: V[]) => void;
  /** Text shown in the trigger when values are selected. */
  summarize?: (selected: Option<V>[]) => string;
}

const ROW = 34;

/**
 * Select / multi-select dropdown whose option list is virtualized, so it stays fast
 * with thousands of options (zones, users, organizations).
 */
export function VirtualSelect<V extends string | number = string>(props: SingleProps<V> | MultiProps<V>) {
  const {
    options,
    label,
    description,
    error,
    placeholder = "Select",
    searchable = options.length > 8,
    searchPlaceholder = "Search",
    disabled,
    size = "base",
    className,
    popupWidth,
    renderOption,
    emptyText = "No results",
  } = props;
  const autoId = useId();
  const id = props.id ?? autoId;
  const listId = id + "-list";
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const selectedValues = useMemo(
    () => new Set<V>(props.multiple ? props.value : props.value != null ? [props.value] : []),
    [props.multiple, props.value],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return options;
    return options.filter((o) =>
      (o.label + " " + (o.description ?? "") + " " + (o.keywords ?? "") + " " + String(o.value)).toLowerCase().includes(q),
    );
  }, [options, query]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => listRef.current,
    estimateSize: (i) => (filtered[i]?.description ? ROW + 16 : ROW),
    overscan: 8,
  });

  useEffect(() => {
    if (!open) return;
    setQuery("");
    const idx = options.findIndex((o) => selectedValues.has(o.value));
    setActive(Math.max(0, idx));
    requestAnimationFrame(() => {
      virtualizer.measure();
      if (idx >= 0) virtualizer.scrollToIndex(idx, { align: "center" });
      if (searchable) searchRef.current?.focus();
      else listRef.current?.focus();
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  const choose = (o: Option<V>) => {
    if (o.disabled) return;
    if (props.multiple) {
      const next = new Set(props.value);
      if (next.has(o.value)) next.delete(o.value);
      else next.add(o.value);
      props.onChange(options.filter((x) => next.has(x.value)).map((x) => x.value));
    } else {
      props.onChange(o.value);
      setOpen(false);
      triggerRef.current?.focus();
    }
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.min(filtered.length - 1, active + 1);
      setActive(next);
      virtualizer.scrollToIndex(next);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.max(0, active - 1);
      setActive(next);
      virtualizer.scrollToIndex(next);
    } else if (e.key === "Home") {
      e.preventDefault();
      setActive(0);
      virtualizer.scrollToIndex(0);
    } else if (e.key === "End") {
      e.preventDefault();
      setActive(filtered.length - 1);
      virtualizer.scrollToIndex(filtered.length - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const o = filtered[active];
      if (o) choose(o);
    }
  };

  let triggerText: string;
  if (props.multiple) {
    const sel = options.filter((o) => selectedValues.has(o.value));
    triggerText = sel.length === 0 ? placeholder : props.summarize ? props.summarize(sel) : sel.map((s) => s.label).join(", ");
  } else {
    triggerText = options.find((o) => o.value === props.value)?.label ?? placeholder;
  }
  const hasValue = selectedValues.size > 0;
  const listHeight = Math.min(320, Math.max(ROW, virtualizer.getTotalSize()));

  return (
    <div className={cn("flex min-w-0 flex-col gap-1.5", className)}>
      {label && (
        <Label htmlFor={id} showOptional={props.required === false}>
          {label}
        </Label>
      )}
      <Popover.Root open={open} onOpenChange={(o) => !disabled && setOpen(o)}>
        {props.renderTrigger ? (
          <Popover.Trigger render={props.renderTrigger(triggerText, open)} />
        ) : (
        <Popover.Trigger
          render={
            <button
              ref={triggerRef}
              id={id}
              type="button"
              disabled={disabled}
              aria-haspopup="listbox"
              aria-expanded={open}
              aria-controls={listId}
              aria-label={props["aria-label"]}
              aria-invalid={error ? true : undefined}
              className={cn(
                inputVariants({ size, variant: error ? "error" : "default" }),
                "flex w-full items-center justify-between gap-2 text-left disabled:cursor-not-allowed disabled:opacity-60",
              )}
            />
          }
        >
          <span className={cn("min-w-0 truncate", !hasValue && "text-kumo-placeholder")}>{triggerText}</span>
          <CaretUpDownIcon className="shrink-0 text-kumo-subtle" size={14} />
        </Popover.Trigger>
        )}
        <Popover.Portal>
          <Popover.Positioner side={props.side ?? "bottom"} align={props.align ?? "start"} sideOffset={4} className="z-50">
            <Popover.Popup
              className="overflow-hidden rounded-lg bg-kumo-base p-0 shadow-lg ring ring-kumo-line"
              style={{ width: popupWidth ?? "var(--anchor-width)", minWidth: 200 }}
            >
              {searchable && (
                <div className="flex items-center gap-2 border-b border-kumo-line px-3">
                  <MagnifyingGlassIcon size={14} className="shrink-0 text-kumo-subtle" />
                  <input
                    ref={searchRef}
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={onKeyDown}
                    placeholder={searchPlaceholder}
                    aria-label={searchPlaceholder}
                    aria-controls={listId}
                    aria-activedescendant={filtered[active] ? `${id}-opt-${active}` : undefined}
                    className="h-9 w-full bg-transparent text-sm text-kumo-default outline-none placeholder:text-kumo-placeholder"
                  />
                </div>
              )}
              <div
                ref={listRef}
                id={listId}
                role="listbox"
                aria-multiselectable={props.multiple || undefined}
                tabIndex={searchable ? -1 : 0}
                onKeyDown={searchable ? undefined : onKeyDown}
                aria-activedescendant={!searchable && filtered[active] ? `${id}-opt-${active}` : undefined}
                className="overflow-x-hidden overflow-y-auto p-1 outline-none"
                style={{ height: filtered.length === 0 ? undefined : listHeight + 8, maxHeight: 328 }}
              >
                {filtered.length === 0 ? (
                  <div className="px-2 py-3 text-sm text-kumo-subtle">{emptyText}</div>
                ) : (
                  <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                    {virtualizer.getVirtualItems().map((vi) => {
                      const o = filtered[vi.index];
                      const selected = selectedValues.has(o.value);
                      return (
                        <div
                          key={String(o.value)}
                          id={`${id}-opt-${vi.index}`}
                          role="option"
                          aria-selected={selected}
                          aria-disabled={o.disabled || undefined}
                          data-index={vi.index}
                          ref={virtualizer.measureElement}
                          onMouseMove={() => setActive(vi.index)}
                          onClick={() => choose(o)}
                          className={cn(
                            "absolute left-0 flex w-full cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm",
                            vi.index === active && "bg-kumo-tint",
                            o.disabled && "cursor-not-allowed opacity-50",
                          )}
                          style={{ transform: `translateY(${vi.start}px)` }}
                        >
                          {props.multiple ? (
                            <span
                              className={cn(
                                "flex size-4 shrink-0 items-center justify-center rounded ring ring-kumo-line",
                                selected && "bg-brand text-white ring-0",
                              )}
                            >
                              {selected && <CheckIcon size={11} weight="bold" />}
                            </span>
                          ) : null}
                          <span className="min-w-0 flex-1">
                            {renderOption ? (
                              renderOption(o)
                            ) : (
                              <>
                                <span className="block truncate text-kumo-default">{o.label}</span>
                                {o.description && <span className="block truncate text-xs text-kumo-subtle">{o.description}</span>}
                              </>
                            )}
                          </span>
                          {!props.multiple && selected && <CheckIcon size={14} className="shrink-0 text-brand" />}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
              {props.footer && <div className="border-t border-kumo-line p-1">{props.footer(() => setOpen(false))}</div>}
            </Popover.Popup>
          </Popover.Positioner>
        </Popover.Portal>
      </Popover.Root>
      {error ? (
        <p className="text-sm text-kumo-danger">{error}</p>
      ) : description ? (
        <p className="text-sm text-kumo-subtle">{description}</p>
      ) : null}
    </div>
  );
}
