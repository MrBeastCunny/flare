import { lazy, Suspense, type ReactNode } from "react";
import { createBrowserRouter, Navigate, Outlet, useLocation } from "react-router";
import { FullPageLoader } from "./components/ui";
import { useConfig, useMe } from "./lib/queries";
import { AppShell } from "./layouts/AppShell";
import { ZoneLayout } from "./layouts/ZoneLayout";
import { NotFound, RouteError } from "./routes/NotFound";

const Login = lazy(() => import("./routes/auth/Login"));
const Signup = lazy(() => import("./routes/auth/Signup"));
const ForgotPassword = lazy(() => import("./routes/auth/ForgotPassword"));
const ResetPassword = lazy(() => import("./routes/auth/ResetPassword"));
const AcceptInvite = lazy(() => import("./routes/auth/AcceptInvite"));
const Setup = lazy(() => import("./routes/auth/Setup"));
const EnforceMFA = lazy(() => import("./routes/auth/EnforceMFA"));
const Onboarding = lazy(() => import("./routes/Onboarding"));

const Domains = lazy(() => import("./routes/account/Domains"));
const AddZone = lazy(() => import("./routes/account/AddZone"));
const Members = lazy(() => import("./routes/account/Members"));
const AuditLog = lazy(() => import("./routes/account/AuditLog"));
const ApiTokens = lazy(() => import("./routes/account/ApiTokens"));
const SSO = lazy(() => import("./routes/account/SSO"));
const Webhooks = lazy(() => import("./routes/account/Webhooks"));
const OrgSettings = lazy(() => import("./routes/account/OrgSettings"));
const NewOrg = lazy(() => import("./routes/account/NewOrg"));
const Templates = lazy(() => import("./routes/account/Templates"));
const AdminTemplates = lazy(() => import("./routes/admin/AdminTemplates"));
const AdminApiTokens = lazy(() => import("./routes/admin/AdminApiTokens"));

const ZoneOverview = lazy(() => import("./routes/zone/Overview"));
const DnsRecords = lazy(() => import("./routes/zone/DnsRecords"));
const Dnssec = lazy(() => import("./routes/zone/Dnssec"));
const ZoneSettings = lazy(() => import("./routes/zone/ZoneSettings"));
const ZoneActivity = lazy(() => import("./routes/zone/ZoneActivity"));

const Profile = lazy(() => import("./routes/profile/Profile"));

const AdminOverview = lazy(() => import("./routes/admin/AdminOverview"));
const AdminServers = lazy(() => import("./routes/admin/Servers"));
const AdminNameservers = lazy(() => import("./routes/admin/Nameservers"));
const AdminUsers = lazy(() => import("./routes/admin/Users"));
const AdminOrgs = lazy(() => import("./routes/admin/Orgs"));
const AdminZones = lazy(() => import("./routes/admin/Zones"));
const AdminSettings = lazy(() => import("./routes/admin/Settings"));
const AdminAudit = lazy(() => import("./routes/admin/AdminAudit"));


function S({ children }: { children: ReactNode }) {
  return <Suspense fallback={<FullPageLoader />}>{children}</Suspense>;
}

/** Redirects to first-run setup when the instance has no users yet. */
function SetupGate() {
  const config = useConfig();
  const loc = useLocation();
  if (config.isLoading) return <FullPageLoader />;
  if (config.data?.setup_required && loc.pathname !== "/setup") return <Navigate to="/setup" replace />;
  return <Outlet />;
}

function RequireAuth() {
  const me = useMe();
  const loc = useLocation();
  if (me.isLoading) return <FullPageLoader />;
  if (!me.data) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />;
  if (me.data.mfa_setup_required && loc.pathname !== "/security/mfa") return <Navigate to="/security/mfa" replace />;
  return <Outlet />;
}

function RootRedirect() {
  const me = useMe();
  if (!me.data) return <FullPageLoader />;
  if (me.data.needs_onboarding || me.data.orgs.length === 0) return <Navigate to="/onboarding" replace />;
  let last = "";
  try {
    last = localStorage.getItem("flare-last-org") ?? "";
  } catch {
    /* storage unavailable */
  }
  const org = me.data.orgs.find((o) => o.id === last) ?? me.data.orgs[0];
  return <Navigate to={`/${org.id}`} replace />;
}

export const router = createBrowserRouter([
  {
    element: <SetupGate />,
    errorElement: <RouteError />,
    children: [
      { path: "/setup", element: <S><Setup /></S> },
      { path: "/login", element: <S><Login /></S> },
      { path: "/signup", element: <S><Signup /></S> },
      { path: "/forgot-password", element: <S><ForgotPassword /></S> },
      { path: "/reset-password", element: <S><ResetPassword /></S> },
      { path: "/invite/:token", element: <S><AcceptInvite /></S> },
      {
        element: <RequireAuth />,
        children: [
          { path: "/", element: <RootRedirect /> },
          { path: "/security/mfa", element: <S><EnforceMFA /></S> },
          { path: "/onboarding", element: <S><Onboarding /></S> },
          {
            element: <AppShell />,
            children: [
              { path: "/profile", element: <S><Profile /></S> },
              { path: "/new-organization", element: <S><NewOrg /></S> },
              {
                path: "/admin",
                children: [
                  { index: true, element: <S><AdminOverview /></S> },
                  { path: "servers", element: <S><AdminServers /></S> },
                  { path: "nameservers", element: <S><AdminNameservers /></S> },
                  { path: "users", element: <S><AdminUsers /></S> },
                  { path: "organizations", element: <S><AdminOrgs /></S> },
                  { path: "zones", element: <S><AdminZones /></S> },
                  { path: "settings", element: <S><AdminSettings /></S> },
                  { path: "audit-log", element: <S><AdminAudit /></S> },
                  { path: "templates", element: <S><AdminTemplates /></S> },
                  { path: "api-tokens", element: <S><AdminApiTokens /></S> },
                ],
              },
              {
                path: "/:orgId",
                children: [
                  { index: true, element: <S><Domains /></S> },
                  { path: "add-site", element: <S><AddZone /></S> },
                  { path: "templates", element: <S><Templates /></S> },
                  { path: "members", element: <S><Members /></S> },
                  { path: "audit-log", element: <S><AuditLog /></S> },
                  { path: "api-tokens", element: <S><ApiTokens /></S> },
                  { path: "sso", element: <S><SSO /></S> },
                  { path: "webhooks", element: <S><Webhooks /></S> },
                  { path: "settings", element: <S><OrgSettings /></S> },
                  {
                    path: ":zoneName",
                    element: <ZoneLayout />,
                    children: [
                      { index: true, element: <S><ZoneOverview /></S> },
                      { path: "dns", element: <S><DnsRecords /></S> },
                      { path: "dnssec", element: <S><Dnssec /></S> },
                      { path: "settings", element: <S><ZoneSettings /></S> },
                      { path: "activity", element: <S><ZoneActivity /></S> },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      },
      { path: "*", element: <NotFound /> },
    ],
  },
]);
