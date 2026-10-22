import { QueryClient, useQuery, useInfiniteQuery } from "@tanstack/react-query";
import { useParams } from "react-router";
import { api, ApiError } from "./api";
import type {
  AuditPage,
  DayCount,
  DnsRecord,
  Invitation,
  Me,
  Member,
  OrgDetail,
  Perm,
  PublicConfig,
  Zone,
  AuditEntry,
} from "./types";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: true,
      retry: (count, err) => {
        if (err instanceof ApiError && err.status >= 400 && err.status < 500) return false;
        return count < 2;
      },
    },
    mutations: { retry: false },
  },
});

export const keys = {
  config: ["config"] as const,
  me: ["me"] as const,
  org: (orgId: string) => ["org", orgId] as const,
  orgOverview: (orgId: string) => ["org", orgId, "overview"] as const,
  zones: (orgId: string) => ["org", orgId, "zones"] as const,
  zone: (orgId: string, zoneId: string) => ["org", orgId, "zone", zoneId] as const,
  records: (orgId: string, zoneId: string) => ["org", orgId, "zone", zoneId, "records"] as const,
  zoneOverview: (orgId: string, zoneId: string) => ["org", orgId, "zone", zoneId, "overview"] as const,
  zoneSettings: (orgId: string, zoneId: string) => ["org", orgId, "zone", zoneId, "settings"] as const,
  dnssec: (orgId: string, zoneId: string) => ["org", orgId, "zone", zoneId, "dnssec"] as const,
  members: (orgId: string) => ["org", orgId, "members"] as const,
  invites: (orgId: string) => ["org", orgId, "invites"] as const,
  tokens: (orgId: string) => ["org", orgId, "tokens"] as const,
  sso: (orgId: string) => ["org", orgId, "sso"] as const,
  scim: (orgId: string) => ["org", orgId, "scim"] as const,
  webhooks: (orgId: string) => ["org", orgId, "webhooks"] as const,
  audit: (scope: string, filters: Record<string, string>) => ["audit", scope, filters] as const,
  nsSets: (orgId: string) => ["org", orgId, "nameserver-sets"] as const,
  admin: (part: string) => ["admin", part] as const,
};

export function useConfig() {
  return useQuery({ queryKey: keys.config, queryFn: () => api<PublicConfig>("/config"), staleTime: 60_000 });
}

export function useMe(enabled = true) {
  return useQuery({ queryKey: keys.me, queryFn: () => api<Me>("/me"), enabled, staleTime: 30_000 });
}

export function useOrgId(): string {
  return useParams().orgId ?? "";
}

export function useOrg(orgId: string) {
  return useQuery({ queryKey: keys.org(orgId), queryFn: () => api<OrgDetail>(`/orgs/${orgId}`), enabled: !!orgId });
}

export function usePerms(orgId: string) {
  const { data } = useOrg(orgId);
  const perms = new Set<Perm>(data?.permissions ?? []);
  return {
    can: (p: Perm) => perms.has(p),
    role: data?.role,
    loaded: !!data,
  };
}

export function useZones(orgId: string) {
  return useQuery({ queryKey: keys.zones(orgId), queryFn: () => api<Zone[]>(`/orgs/${orgId}/zones`), enabled: !!orgId });
}

/** Resolves the zone from the `:zoneName` route parameter. */
export function useCurrentZone() {
  const params = useParams();
  const orgId = params.orgId ?? "";
  const name = (params.zoneName ?? "").toLowerCase();
  const zones = useZones(orgId);
  const zone = zones.data?.find((z) => z.name === name + "." || z.name === name);
  return { orgId, zone, isLoading: zones.isLoading, notFound: zones.isSuccess && !zone, error: zones.error };
}

export function useRecords(orgId: string, zoneId: string | undefined) {
  return useQuery({
    queryKey: keys.records(orgId, zoneId ?? ""),
    queryFn: () => api<{ records: DnsRecord[]; serial: number; dnssec: boolean }>(`/orgs/${orgId}/zones/${zoneId}/records`),
    enabled: !!zoneId,
  });
}

export function useMembers(orgId: string) {
  return useQuery({ queryKey: keys.members(orgId), queryFn: () => api<Member[]>(`/orgs/${orgId}/members`), enabled: !!orgId });
}

export function useInvites(orgId: string, enabled = true) {
  return useQuery({ queryKey: keys.invites(orgId), queryFn: () => api<Invitation[]>(`/orgs/${orgId}/invites`), enabled: !!orgId && enabled });
}

export interface OrgOverview {
  zone_count: number;
  status_counts: Record<string, number>;
  member_count: number;
  recent_zones: Zone[];
  activity?: DayCount[];
  recent_activity?: AuditEntry[];
  sso_enabled: boolean;
  mfa_member_count: number;
}

export function useOrgOverview(orgId: string) {
  return useQuery({ queryKey: keys.orgOverview(orgId), queryFn: () => api<OrgOverview>(`/orgs/${orgId}/overview`), enabled: !!orgId });
}

/** Cursor-paginated audit log (infinite scroll). */
export function useAuditLog(path: string, scope: string, filters: Record<string, string>, enabled = true) {
  return useInfiniteQuery({
    queryKey: keys.audit(scope, filters),
    queryFn: ({ pageParam }) => api<AuditPage>(path, { query: { ...filters, limit: 100, before: pageParam ?? undefined } }),
    initialPageParam: null as number | null,
    getNextPageParam: (last) => last.next_cursor,
    enabled,
  });
}
