import { lazy, Suspense } from "react";
import { Center, Loader } from "@mantine/core";
import { useQuery } from "@tanstack/react-query";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { api } from "./api/client";
import { useSession } from "./api/session";
import { Layout } from "./components/Layout";
import { SettingsPage } from "./pages/SettingsPage";
import { SettingsShell } from "./settings/SettingsShell";
import { LoginPage } from "./pages/LoginPage";
import { SetupPage } from "./pages/SetupPage";
import { MasterKeyPage } from "./pages/MasterKeyPage";

// Pages other than the first screens load on demand, which keeps the first download small.
const page = <K extends string>(load: () => Promise<Record<K, React.ComponentType>>, name: K) => lazy(() => load().then((m) => ({ default: m[name] })));
const DashboardPage = page(() => import("./pages/DashboardPage"), "DashboardPage");
const DevicesPage = page(() => import("./pages/DevicesPage"), "DevicesPage");
const HeldUpdatesPage = page(() => import("./pages/HeldUpdatesPage"), "HeldUpdatesPage");
const AboutPage = page(() => import("./pages/AboutPage"), "AboutPage");
const SettingsSectionPage = page(() => import("./pages/SettingsSectionPage"), "SettingsSectionPage");
const AuditPage = page(() => import("./pages/AuditPage"), "AuditPage");
const CatalogPage = page(() => import("./pages/CatalogPage"), "CatalogPage");
const DeploymentPage = page(() => import("./pages/DeploymentPage"), "DeploymentPage");
const DeploymentsPage = page(() => import("./pages/DeploymentsPage"), "DeploymentsPage");
const NewDeploymentPage = page(() => import("./pages/NewDeploymentPage"), "NewDeploymentPage");
const PackagePage = page(() => import("./pages/PackagePage"), "PackagePage");
const BrandingPage = page(() => import("./pages/BrandingPage"), "BrandingPage");
const StyleGuidePage = page(() => import("./pages/StyleGuidePage"), "StyleGuidePage");
const DevicePage = page(() => import("./pages/DevicePage"), "DevicePage");
const GroupsPage = page(() => import("./pages/GroupsPage"), "GroupsPage");
const SoftwarePage = page(() => import("./pages/SoftwarePage"), "SoftwarePage");
const SoftwareUpdatesPage = page(() => import("./pages/SoftwareUpdatesPage"), "SoftwareUpdatesPage");
const TokensPage = page(() => import("./pages/TokensPage"), "TokensPage");
const AutomationsPage = page(() => import("./pages/AutomationsPage"), "AutomationsPage");
const ScriptsPage = page(() => import("./pages/ScriptsPage"), "ScriptsPage");
const ReportsPage = page(() => import("./pages/ReportsPage"), "ReportsPage");
const VulnerabilitiesPage = page(() => import("./pages/VulnerabilitiesPage"), "VulnerabilitiesPage");
const AgentUpdatesPage = page(() => import("./pages/AgentUpdatesPage"), "AgentUpdatesPage");
const AccountPage = page(() => import("./pages/AccountPage"), "AccountPage");
const SitesPage = page(() => import("./pages/SitesPage"), "SitesPage");
const UsersPage = page(() => import("./pages/UsersPage"), "UsersPage");
const UpdatesPage = page(() => import("./pages/UpdatesPage"), "UpdatesPage");

export function App() {
  const loc = useLocation();
  const setup = useQuery({ queryKey: ["setup"], queryFn: () => api<{ setup_required: boolean }>("GET", "/setup/status") });
  const { session, loading } = useSession();

  if (setup.isLoading || loading) {
    return (
      <Center mih="100vh">
        <Loader />
      </Center>
    );
  }
  // Setup must finish (including showing recovery codes) before anything else.
  if (setup.data?.setup_required || loc.pathname === "/setup") {
    return (
      <Routes>
        <Route path="/setup" element={<SetupPage />} />
        <Route path="*" element={setup.data?.setup_required ? <Navigate to="/setup" replace /> : <Navigate to="/login" replace />} />
      </Routes>
    );
  }
  // A stack that generated its own master key makes the first administrator save it before anything else works (D109).
  if (session?.master_key_pending) return <MasterKeyPage />;
  return (
    <Suspense
      fallback={
        <Center mih="40vh">
          <Loader />
        </Center>
      }
    >
    <Routes>
      <Route path="/login" element={session ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route element={session ? <Layout /> : <Navigate to="/login" replace />}>
        <Route index element={<DashboardPage />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:id" element={<DevicePage />} />
        <Route path="/software" element={<SoftwarePage />} />
        <Route path="/software-updates" element={<SoftwareUpdatesPage />} />
        <Route path="/groups" element={<GroupsPage />} />
        <Route path="/catalog" element={<CatalogPage />} />
        <Route path="/catalog/:id" element={<PackagePage />} />
        <Route path="/automations" element={<AutomationsPage />} />
        {/* The software policies and the update rings and rules used to be two pages. */}
        <Route path="/policies" element={<Navigate to="/automations" replace />} />
        <Route path="/scripts" element={<ScriptsPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="/agent-updates" element={<AgentUpdatesPage />} />
        <Route path="/account" element={<AccountPage />} />
        <Route path="/users" element={<UsersPage />} />
        <Route path="/sites" element={<SitesPage />} />
        <Route path="/updates" element={<UpdatesPage />} />
        <Route path="/updates/held" element={<HeldUpdatesPage />} />
        <Route path="/update-policy" element={<Navigate to="/automations?tab=windows" replace />} />
        <Route path="/deployments" element={<DeploymentsPage />} />
        <Route path="/deployments/new" element={<NewDeploymentPage />} />
        <Route path="/deployments/:id" element={<DeploymentPage />} />
        <Route path="/settings" element={<SettingsShell />}>
          <Route index element={<SettingsPage />} />
          <Route path="branding" element={<BrandingPage />} />
          <Route path="about" element={<AboutPage />} />
          <Route path=":section" element={<SettingsSectionPage />} />
        </Route>
        <Route path="/styleguide" element={<StyleGuidePage />} />
        <Route path="/enrollment" element={<TokensPage />} />
        <Route path="/audit" element={<AuditPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
    </Suspense>
  );
}
