import { useSyncExternalStore } from "react";

/** Tracks a CSS media query, for layouts that change structure rather than just styling. */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const mql = window.matchMedia(query);
      mql.addEventListener("change", onChange);
      return () => mql.removeEventListener("change", onChange);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

/** True below Tailwind's `sm` breakpoint (phones). */
export const useIsNarrow = () => useMediaQuery("(max-width: 639px)");
