export class ApiError extends Error {
  status: number;
  code: string;
  fields: Record<string, string>;
  extra: Record<string, unknown>;

  constructor(status: number, code: string, message: string, fields?: Record<string, string>, extra?: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.fields = fields ?? {};
    this.extra = extra ?? {};
  }
}

function readCookie(name: string): string {
  const match = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : "";
}

type Query = Record<string, string | number | boolean | undefined | null>;

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Query;
  signal?: AbortSignal;
}

let unauthorizedHandler: (() => void) | null = null;

/** Registers a callback invoked when the API reports an expired session. */
export function onUnauthorized(fn: () => void) {
  unauthorizedHandler = fn;
}

export function buildUrl(path: string, query?: Query): string {
  const url = new URL("/api/v1" + path, window.location.origin);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
    }
  }
  return url.pathname + url.search;
}

export async function api<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET") headers["X-CSRF-Token"] = readCookie("flare_csrf");

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      credentials: "same-origin",
      signal: opts.signal,
    });
  } catch (err) {
    if ((err as Error).name === "AbortError") throw err;
    throw new ApiError(0, "network_error", "Unable to reach the server. Check your connection and try again.");
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!res.ok) {
    const e = (data as { error?: { code?: string; message?: string; fields?: Record<string, string> } })?.error;
    const err = new ApiError(res.status, e?.code ?? "error", e?.message ?? res.statusText, e?.fields, e as Record<string, unknown>);
    if (res.status === 401 && (err.code === "unauthorized" || err.code === "session_expired") && !path.startsWith("/auth")) {
      unauthorizedHandler?.();
    }
    throw err;
  }
  return data as T;
}

/** Ensures the CSRF cookie exists before the first mutation on a fresh page load. */
export async function primeCsrf() {
  if (!readCookie("flare_csrf")) {
    await api("/config").catch(() => undefined);
  }
}

/** Downloads an API response as a file (export endpoints). */
export async function download(path: string, query?: Query) {
  const res = await fetch(buildUrl(path, query), { credentials: "same-origin" });
  if (!res.ok) {
    let message = res.statusText;
    try {
      message = (await res.json()).error?.message ?? message;
    } catch {
      /* ignore */
    }
    throw new ApiError(res.status, "download_failed", message);
  }
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") ?? "";
  const name = /filename="([^"]+)"/.exec(cd)?.[1] ?? "download";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) return err.message;
  return "Something went wrong";
}

export function fieldError(err: unknown, field: string): string | undefined {
  if (err instanceof ApiError) return err.fields[field];
  return undefined;
}
