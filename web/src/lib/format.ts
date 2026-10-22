const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const df = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

export function formatDateTime(v: string | Date | null | undefined): string {
  if (!v) return "Never";
  return dtf.format(new Date(v));
}

export function formatDate(v: string | Date | null | undefined): string {
  if (!v) return "";
  return df.format(new Date(v));
}

export function timeAgo(v: string | Date | null | undefined): string {
  if (!v) return "Never";
  const diff = (new Date(v).getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["minute", 60],
    ["hour", 3600],
    ["day", 86400],
    ["week", 604800],
    ["month", 2629800],
    ["year", 31557600],
  ];
  let unit: Intl.RelativeTimeFormatUnit = "minute";
  let div = 60;
  for (const [u, d] of units) {
    if (abs >= d) {
      unit = u;
      div = d;
    }
  }
  return rtf.format(Math.round(diff / div), unit);
}

export function stripDot(name: string): string {
  return name.endsWith(".") ? name.slice(0, -1) : name;
}

/** Shows a record name relative to its zone, like the zone editor in most DNS dashboards. */
export function relativeName(name: string, zone: string): string {
  const n = stripDot(name);
  const z = stripDot(zone);
  if (n === z) return "@";
  if (n.endsWith("." + z)) return n.slice(0, -(z.length + 1));
  return n;
}

export function formatTTL(ttl: number): string {
  if (ttl === 1) return "Auto";
  if (ttl % 86400 === 0) return `${ttl / 86400} ${ttl === 86400 ? "day" : "days"}`;
  if (ttl % 3600 === 0) return `${ttl / 3600} ${ttl === 3600 ? "hr" : "hrs"}`;
  if (ttl % 60 === 0) return `${ttl / 60} min`;
  return `${ttl} sec`;
}

export function formatNumber(n: number | undefined | null): string {
  if (n === undefined || n === null) return "0";
  return new Intl.NumberFormat().format(n);
}

export function compactNumber(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function formatDuration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export const roleLabels: Record<string, string> = {
  owner: "Owner",
  admin: "Administrator",
  editor: "DNS Editor",
  viewer: "Viewer",
  auditor: "Auditor",
};

export const roleDescriptions: Record<string, string> = {
  owner: "Full access, including billing-level actions and deleting the organization.",
  admin: "Manage members, SSO, API tokens, webhooks and every zone.",
  editor: "Add zones and edit DNS records, DNSSEC and zone settings.",
  viewer: "Read-only access to zones and DNS records.",
  auditor: "Read-only access plus the audit log.",
};

export function initials(nameOrEmail: string): string {
  const parts = nameOrEmail.replace(/@.*/, "").split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return "?";
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

export function plural(n: number, one: string, many?: string): string {
  return `${formatNumber(n)} ${n === 1 ? one : many ?? one + "s"}`;
}

export function parseUA(ua: string): string {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /Firefox\//.test(ua)
      ? "Firefox"
      : /Chrome\//.test(ua)
        ? "Chrome"
        : /Safari\//.test(ua)
          ? "Safari"
          : /curl\//.test(ua)
            ? "curl"
            : "Browser";
  const os = /Windows/.test(ua)
    ? "Windows"
    : /Mac OS X|Macintosh/.test(ua)
      ? "macOS"
      : /Android/.test(ua)
        ? "Android"
        : /iPhone|iPad/.test(ua)
          ? "iOS"
          : /Linux/.test(ua)
            ? "Linux"
            : "";
  return os ? `${browser} on ${os}` : browser;
}
