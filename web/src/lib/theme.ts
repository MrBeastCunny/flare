import { useEffect, useState } from "react";

export type ThemePref = "light" | "dark" | "system";

function apply(pref: ThemePref) {
  const dark = pref === "dark" || (pref === "system" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-mode", dark ? "dark" : "light");
}

function read(): ThemePref {
  try {
    const v = localStorage.getItem("flare-theme");
    if (v === "light" || v === "dark" || v === "system") return v;
  } catch {
    /* ignore */
  }
  return "system";
}

export function useTheme() {
  const [pref, setPref] = useState<ThemePref>(read);
  useEffect(() => {
    apply(pref);
    try {
      localStorage.setItem("flare-theme", pref);
    } catch {
      /* ignore */
    }
    if (pref !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const fn = () => apply("system");
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, [pref]);
  return { pref, setPref };
}
