import { useEffect, useState, type ComponentType } from "react";
import { Outlet, useLocation, useNavigate, useParams, Link } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Banner, Button, Sidebar, Text, cn, useSidebar } from "@cloudflare/kumo";
import {
  GlobeHemisphereWestIcon,
  UsersThreeIcon,
  ClockCounterClockwiseIcon,
  KeyIcon,
  ShieldCheckIcon,
  WebhooksLogoIcon,
  GearSixIcon,
  MagnifyingGlassIcon,
  SignOutIcon,
  UserCircleIcon,
  SunIcon,
  MoonIcon,
  MonitorIcon,
  CaretUpDownIcon,
  PlusIcon,
  ArrowLeftIcon,
  ChartBarIcon,
  ListBulletsIcon,
  LockKeyIcon,
  SlidersHorizontalIcon,
  HardDrivesIcon,
  BuildingsIcon,
  UserListIcon,
  ShieldStarIcon,
  QuestionIcon,
  InfoIcon,
  TreeStructureIcon,
  CopySimpleIcon,
} from "@phosphor-icons/react";
import { Logo, LogoMark, Avatar, FullPageLoader } from "../components/ui";
import { VirtualSelect } from "../components/VirtualSelect";
import { CommandMenu } from "../components/CommandMenu";
import { ActionMenu } from "../components/VirtualMenu";
import { useMe, useOrg, useConfig, useZones } from "../lib/queries";
import { displayDomain } from "../lib/idn";
import { api } from "../lib/api";
import { useTheme } from "../lib/theme";
import { roleLabels } from "../lib/format";
import type { Perm } from "../lib/types";

type IconType = ComponentType<{ className?: string }>;

interface NavItem {
  label: string;
  icon: IconType;
  to: string;
  exact?: boolean;
  perm?: Perm;
}

function NavGroup({ label, items, can }: { label?: string; items: NavItem[]; can?: (p: Perm) => boolean }) {
  const loc = useLocation();
  const visible = items.filter((i) => !i.perm || !can || can(i.perm));
  if (visible.length === 0) return null;
  return (
    <Sidebar.Group>
      {label && <Sidebar.GroupLabel>{label}</Sidebar.GroupLabel>}
      <Sidebar.Menu>
        {visible.map((i) => {
          const active = i.exact ? loc.pathname === i.to : loc.pathname === i.to || loc.pathname.startsWith(i.to + "/");
          return (
            <Sidebar.MenuButton key={i.to} href={i.to} icon={i.icon} active={active} tooltip={i.label}>
              {i.label}
            </Sidebar.MenuButton>
          );
        })}
      </Sidebar.Menu>
    </Sidebar.Group>
  );
}

/** Jump between domains of the current organization without leaving the current page type. */
function ZoneSwitcher({ orgId, zoneName }: { orgId: string; zoneName: string }) {
  const zones = useZones(orgId);
  const navigate = useNavigate();
  const loc = useLocation();
  const section = loc.pathname.split("/").slice(3).join("/");
  return (
    <VirtualSelect
      aria-label="Switch domain"
      options={(zones.data ?? []).map((z) => ({ value: z.name.replace(/\.$/, ""), label: displayDomain(z.name), keywords: z.name }))}
      value={zoneName}
      onChange={(name) => navigate(`/${orgId}/${name}${section ? "/" + section : ""}`)}
      searchable
      searchPlaceholder="Find a domain"
      popupWidth={320}
      renderTrigger={() => (
        <button type="button" className="flex h-8 min-w-0 max-w-72 items-center gap-2 rounded-md px-2 text-left hover:bg-kumo-tint">
          <GlobeHemisphereWestIcon size={16} className="shrink-0 text-kumo-subtle" />
          <span className="truncate font-medium text-kumo-strong">{displayDomain(zoneName)}</span>
          <CaretUpDownIcon size={14} className="shrink-0 text-kumo-subtle" />
        </button>
      )}
    />
  );
}

/** Logo that shrinks to the mark when the sidebar collapses to its icon rail. */
function SidebarBrand({ to, name }: { to: string; name: string }) {
  const { state, isMobile } = useSidebar();
  const collapsed = state === "collapsed" && !isMobile;
  return (
    <Link to={to} className={cn("flex h-8 min-w-0 items-center", collapsed ? "w-full justify-center" : "px-1.5")} aria-label={`${name} home`}>
      {collapsed ? <LogoMark size={28} /> : <Logo name={name} />}
    </Link>
  );
}

function SidebarFooterContent({ version }: { version: string }) {
  const { state, isMobile } = useSidebar();
  if (state === "collapsed" && !isMobile) return null;
  return <span className="truncate text-xs text-kumo-subtle">Version {version}</span>;
}

function lastOrgId(): string {
  try {
    return localStorage.getItem("flare-last-org") ?? "";
  } catch {
    return "";
  }
}

export function AppShell() {
  const me = useMe();
  const config = useConfig();
  const params = useParams();
  const loc = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { pref, setPref } = useTheme();
  const [searchOpen, setSearchOpen] = useState(false);

  const inAdmin = loc.pathname.startsWith("/admin");
  const routeOrg = params.orgId;
  const orgs = me.data?.orgs ?? [];
  const orgId = routeOrg ?? (orgs.find((o) => o.id === lastOrgId()) ?? orgs[0])?.id ?? "";
  const orgDetail = useOrg(routeOrg ?? "");
  const perms = new Set(orgDetail.data?.permissions ?? orgs.find((o) => o.id === orgId)?.permissions ?? []);
  const can = (p: Perm) => perms.has(p);
  const zoneName = params.zoneName;

  useEffect(() => {
    if (routeOrg) {
      try {
        localStorage.setItem("flare-last-org", routeOrg);
      } catch {
        /* ignore */
      }
    }
  }, [routeOrg]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setSearchOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (!me.data) return <FullPageLoader />;
  const user = me.data.user;
  const currentOrg = orgs.find((o) => o.id === orgId);
  const notMember = routeOrg && !orgs.some((o) => o.id === routeOrg);

  const logout = async () => {
    await api("/auth/logout", { method: "POST" }).catch(() => undefined);
    qc.clear();
    navigate("/login", { replace: true });
  };

  const orgNav: NavItem[] = orgId
    ? [
        { label: "Domains", icon: GlobeHemisphereWestIcon, to: `/${orgId}`, exact: true, perm: "zones.read" },
        { label: "Zone templates", icon: CopySimpleIcon, to: `/${orgId}/templates`, perm: "zones.read" },
      ]
    : [];
  const accessNav: NavItem[] = orgId
    ? [
        { label: "Members", icon: UsersThreeIcon, to: `/${orgId}/members`, perm: "members.read" },
        { label: "Single sign-on", icon: ShieldCheckIcon, to: `/${orgId}/sso`, perm: "sso.manage" },
        { label: "API tokens", icon: KeyIcon, to: `/${orgId}/api-tokens`, perm: "tokens.manage" },
      ]
    : [];
  const manageNav: NavItem[] = orgId
    ? [
        { label: "Audit log", icon: ClockCounterClockwiseIcon, to: `/${orgId}/audit-log`, perm: "audit.read" },
        { label: "Webhooks", icon: WebhooksLogoIcon, to: `/${orgId}/webhooks`, perm: "webhooks.manage" },
        { label: "Settings", icon: GearSixIcon, to: `/${orgId}/settings`, perm: "org.read" },
      ]
    : [];
  const zoneBase = `/${orgId}/${zoneName}`;
  const zoneNav: NavItem[] = [
    { label: "Overview", icon: ChartBarIcon, to: zoneBase, exact: true },
    { label: "DNS records", icon: ListBulletsIcon, to: `${zoneBase}/dns` },
    { label: "DNSSEC", icon: LockKeyIcon, to: `${zoneBase}/dnssec` },
    { label: "Zone settings", icon: SlidersHorizontalIcon, to: `${zoneBase}/settings` },
    { label: "Activity", icon: ClockCounterClockwiseIcon, to: `${zoneBase}/activity`, perm: "audit.read" },
  ];
  const adminNav: NavItem[] = [
    { label: "Overview", icon: ChartBarIcon, to: "/admin", exact: true },
    { label: "DNS servers", icon: HardDrivesIcon, to: "/admin/servers" },
    { label: "Nameservers", icon: TreeStructureIcon, to: "/admin/nameservers" },
    { label: "Organizations", icon: BuildingsIcon, to: "/admin/organizations" },
    { label: "Users", icon: UserListIcon, to: "/admin/users" },
    { label: "All zones", icon: GlobeHemisphereWestIcon, to: "/admin/zones" },
    { label: "Zone templates", icon: CopySimpleIcon, to: "/admin/templates" },
    { label: "Audit log", icon: ClockCounterClockwiseIcon, to: "/admin/audit-log" },
    { label: "Settings", icon: GearSixIcon, to: "/admin/settings" },
  ];

  const announcement = me.data.announcement || config.data?.announcement;

  return (
    <Sidebar.Provider defaultOpen className="h-screen min-h-0">
      <Sidebar>
        <Sidebar.Header>
          <SidebarBrand to={orgId ? `/${orgId}` : "/"} name={me.data.instance_name || "Flare"} />
        </Sidebar.Header>
        <Sidebar.Content>
          {inAdmin ? (
            <>
              <Sidebar.Group>
                <Sidebar.Menu>
                  <Sidebar.MenuButton href={orgId ? `/${orgId}` : "/"} icon={ArrowLeftIcon} tooltip="Back to dashboard">
                    Back to dashboard
                  </Sidebar.MenuButton>
                </Sidebar.Menu>
              </Sidebar.Group>
              <NavGroup label="Instance administration" items={adminNav} />
            </>
          ) : zoneName && routeOrg ? (
            <>
              <Sidebar.Group>
                <Sidebar.Menu>
                  <Sidebar.MenuButton href={`/${orgId}`} icon={ArrowLeftIcon} tooltip="All domains">
                    All domains
                  </Sidebar.MenuButton>
                </Sidebar.Menu>
              </Sidebar.Group>
              <NavGroup label={zoneName} items={zoneNav} can={can} />
            </>
          ) : (
            <>
              <NavGroup items={orgNav} can={can} />
              <NavGroup label="Access" items={accessNav} can={can} />
              <NavGroup label="Manage" items={manageNav} can={can} />
            </>
          )}
          {user.is_superadmin && !inAdmin && (
            <NavGroup label="Instance" items={[{ label: "Administration", icon: ShieldStarIcon, to: "/admin" }]} />
          )}
        </Sidebar.Content>
        <Sidebar.Footer>
          <SidebarFooterContent version={config.data?.version ?? ""} />
        </Sidebar.Footer>
      </Sidebar>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-3 border-b border-kumo-line bg-kumo-base px-4">
          <Sidebar.Trigger aria-label="Toggle navigation" className="flex size-8 items-center justify-center rounded-md text-kumo-default hover:bg-kumo-tint" />
          {orgs.length > 0 && (
            <VirtualSelect
              aria-label="Switch organization"
              options={orgs.map((o) => ({ value: o.id, label: o.name, description: `${roleLabels[o.role]} · ${o.zone_count} zones` }))}
              value={orgId}
              onChange={(id) => navigate(`/${id}`)}
              searchable
              searchPlaceholder="Find an organization"
              popupWidth={300}
              renderTrigger={(text) => (
                <button
                  type="button"
                  className={cn("h-8 min-w-0 max-w-64 items-center gap-2 rounded-md px-2 text-left hover:bg-kumo-tint", zoneName && !inAdmin ? "hidden sm:flex" : "flex")}
                >
                  <BuildingsIcon size={16} className="shrink-0 text-kumo-subtle" />
                  <span className="truncate font-medium text-kumo-strong">{currentOrg ? currentOrg.name : text}</span>
                  <CaretUpDownIcon size={14} className="shrink-0 text-kumo-subtle" />
                </button>
              )}
              footer={(close) =>
                me.data!.can_create_org ? (
                  <button
                    type="button"
                    onClick={() => {
                      close();
                      navigate("/new-organization");
                    }}
                    className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm text-kumo-default hover:bg-kumo-tint"
                  >
                    <PlusIcon size={14} /> Create organization
                  </button>
                ) : null
              }
            />
          )}
          {zoneName && !inAdmin && routeOrg && (
            <>
              <span className="hidden text-kumo-inactive sm:inline">/</span>
              <ZoneSwitcher orgId={routeOrg} zoneName={zoneName} />
            </>
          )}
          <div className="ml-auto flex items-center gap-1">
            <button
              type="button"
              onClick={() => setSearchOpen(true)}
              className="hidden h-8 w-64 items-center gap-2 rounded-lg bg-kumo-control px-3 text-left text-sm text-kumo-subtle ring ring-kumo-line hover:bg-kumo-tint md:flex"
            >
              <MagnifyingGlassIcon size={14} />
              <span className="flex-1">Search</span>
              <kbd className="rounded border border-kumo-line px-1.5 font-mono text-[11px]">Ctrl K</kbd>
            </button>
            <Button className="md:hidden" variant="ghost" shape="square" size="sm" icon={<MagnifyingGlassIcon />} aria-label="Search" onClick={() => setSearchOpen(true)} />
            <ActionMenu
              label="Help"
              trigger={<Button variant="ghost" shape="square" size="sm" icon={<QuestionIcon />} aria-label="Help" />}
              minWidth={220}
              items={[
                { key: "h", kind: "label", label: "Help" },
                { key: "guide", label: "Getting started guide", icon: <InfoIcon />, onSelect: () => navigate("/onboarding?tour=1") },
                {
                  key: "support",
                  label: "Contact support",
                  icon: <QuestionIcon />,
                  hidden: !config.data?.support_email,
                  onSelect: () => {
                    window.location.href = `mailto:${config.data?.support_email}`;
                  },
                },
                { key: "api", label: "API status", icon: <KeyIcon />, onSelect: () => window.open("/api/v1/config", "_blank", "noopener") },
              ]}
            />
            <ActionMenu
              label="Account menu"
              minWidth={240}
              trigger={
                <button type="button" className="ml-1 flex items-center gap-2 rounded-full p-0.5 hover:bg-kumo-tint" aria-label="Account menu">
                  <Avatar name={user.name || user.email} size={30} />
                </button>
              }
              header={
                <div className="px-2 py-1.5">
                  <Text bold>{user.name || user.email}</Text>
                  <Text variant="secondary" size="sm">
                    {user.email}
                  </Text>
                </div>
              }
              items={[
                { key: "profile", label: "My profile", icon: <UserCircleIcon />, onSelect: () => navigate("/profile") },
                { key: "admin", label: "Instance administration", icon: <ShieldStarIcon />, hidden: !user.is_superadmin, onSelect: () => navigate("/admin") },
                { key: "appearance", kind: "label", label: "Appearance", separatorBefore: true },
                { key: "light", label: "Light", icon: <SunIcon />, selected: pref === "light", onSelect: () => setPref("light") },
                { key: "dark", label: "Dark", icon: <MoonIcon />, selected: pref === "dark", onSelect: () => setPref("dark") },
                { key: "system", label: "System", icon: <MonitorIcon />, selected: pref === "system", onSelect: () => setPref("system") },
                { key: "logout", label: "Log out", icon: <SignOutIcon />, danger: true, separatorBefore: true, onSelect: logout },
              ]}
            />
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          {announcement && (
            <div className="border-b border-kumo-line px-6 py-2">
              <Banner variant="secondary" size="sm" icon={<InfoIcon weight="fill" />} description={announcement} />
            </div>
          )}
          <div className={cn("mx-auto w-full max-w-7xl px-4 py-6 md:px-8 md:py-8")}>
            {notMember && !user.is_superadmin ? (
              <div className="py-24 text-center">
                <Text variant="heading" size="lg" as="h1">
                  Organization not found
                </Text>
                <Text variant="secondary">You may not have access to this organization.</Text>
              </div>
            ) : (
              <Outlet />
            )}
          </div>
        </main>
      </div>
      <CommandMenu open={searchOpen} onOpenChange={setSearchOpen} orgId={orgId} />
    </Sidebar.Provider>
  );
}
