import { cn } from "@cloudflare/kumo";
import { CheckIcon } from "@phosphor-icons/react";

/** Horizontal progress indicator for multi-step flows. */
export function Steps({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="flex w-full items-center gap-2" aria-label="Progress">
      {steps.map((label, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <li key={label} className="flex min-w-0 flex-1 items-center gap-2" aria-current={active ? "step" : undefined}>
            <span
              className={cn(
                "flex size-6 shrink-0 items-center justify-center rounded-full text-xs font-medium ring",
                done && "bg-brand text-white ring-transparent",
                active && "bg-kumo-base text-brand ring-2 ring-brand",
                !done && !active && "bg-kumo-base text-kumo-subtle ring-kumo-line",
              )}
            >
              {done ? <CheckIcon size={12} weight="bold" /> : i + 1}
            </span>
            <span className={cn("hidden truncate text-sm md:inline", active ? "font-medium text-kumo-strong" : "text-kumo-subtle")}>{label}</span>
            {i < steps.length - 1 && <span className={cn("h-px min-w-4 flex-1", done ? "bg-brand" : "bg-kumo-line")} />}
          </li>
        );
      })}
    </ol>
  );
}
