import React, { Suspense, lazy, useEffect, useState } from "react";
import Layout from "./components/Layout.jsx";
import { syncSession } from "./lib/api.js";

// Route-level code splitting: each page is loaded on demand, so Vite emits a
// separate chunk per page instead of one large bundle (~554 kB). This cuts the
// initial load for users who only visit a few sections.
const CommandCenter = lazy(() => import("./pages/CommandCenter.jsx"));
const LiveEnvironment = lazy(() => import("./pages/LiveEnvironment.jsx"));
const Network = lazy(() => import("./pages/Network.jsx"));
const Cloud = lazy(() => import("./pages/Cloud.jsx"));
const Vendor = lazy(() => import("./pages/Vendor.jsx"));
const Hardware = lazy(() => import("./pages/Hardware.jsx"));
const Crypto = lazy(() => import("./pages/Crypto.jsx"));
const Assets = lazy(() => import("./pages/Assets.jsx"));
const Cmdb = lazy(() => import("./pages/Cmdb.jsx"));
const Scope = lazy(() => import("./pages/Scope.jsx"));
const CryptoAssets = lazy(() => import("./pages/CryptoAssets.jsx"));
const Certificates = lazy(() => import("./pages/Certificates.jsx"));
const Libraries = lazy(() => import("./pages/Libraries.jsx"));
const Protocols = lazy(() => import("./pages/Protocols.jsx"));
const Catalog = lazy(() => import("./pages/Catalog.jsx"));
const Cbom = lazy(() => import("./pages/Cbom.jsx"));
const Hbom = lazy(() => import("./pages/Hbom.jsx"));
const Graph = lazy(() => import("./pages/DependencyGraph"));
const Pqc = lazy(() => import("./pages/Pqc.jsx"));
const Agility = lazy(() => import("./pages/Agility.jsx"));
const Risk = lazy(() => import("./pages/Risk.jsx"));
const Drift = lazy(() => import("./pages/Drift.jsx"));
const Alerts = lazy(() => import("./pages/Alerts.jsx"));
const WhatIf = lazy(() => import("./pages/WhatIf.jsx"));
const Migration = lazy(() => import("./pages/Migration.jsx"));
const Compliance = lazy(() => import("./pages/Compliance.jsx"));
const Governance = lazy(() => import("./pages/Governance.jsx"));
const Sectors = lazy(() => import("./pages/Sectors.jsx"));
const Onboarding = lazy(() => import("./pages/Onboarding.jsx"));
const PlatformP2 = lazy(() => import("./pages/PlatformP2"));
const Evidence = lazy(() => import("./pages/Evidence.jsx"));
const Scanners = lazy(() => import("./pages/Scanners.jsx"));
const Runtime = lazy(() => import("./pages/Runtime.jsx"));
const LiveScanners = lazy(() => import("./pages/LiveScanners.jsx"));
const LiveAssetIntelligence = lazy(() => import("./pages/LiveAssetIntelligence"));
const Supervision = lazy(() => import("./pages/Supervision"));
const Telecom = lazy(() => import("./pages/Telecom"));
const Timeline = lazy(() => import("./pages/Timeline.jsx"));
const Reports = lazy(() => import("./pages/Reports.jsx"));
const Integrations = lazy(() => import("./pages/Integrations.jsx"));
const Admin = lazy(() => import("./pages/Admin.jsx"));
const Identity = lazy(() => import("./pages/Identity.jsx"));
const CryptoAssurance = lazy(() => import("./pages/CryptoAssurance.jsx"));
const DevSecOps = lazy(() => import("./pages/DevSecOps.jsx"));
const Automation = lazy(() => import("./pages/Automation.jsx"));
const Resilience = lazy(() => import("./pages/Resilience.jsx"));
const Trust = lazy(() => import("./pages/Trust.jsx"));
const RoleDashboard = lazy(() => import("./pages/RoleDashboard.jsx"));
const Executive = lazy(() => import("./pages/Executive.jsx"));
const Accuracy = lazy(() => import("./pages/Accuracy.jsx"));
const Organization = lazy(() => import("./pages/Organization.jsx"));
const Notifications = lazy(() => import("./pages/Notifications.jsx"));
const PqcMap = lazy(() => import("./pages/PqcMap.jsx"));
const CryptoChanges = lazy(() => import("./pages/CryptoChanges.jsx"));
const SearchResults = lazy(() => import("./pages/SearchResults.jsx"));
const Login = lazy(() => import("./pages/Login.jsx"));
const Register = lazy(() => import("./pages/Register.jsx"));
const Findings = lazy(() => import("./pages/Findings.jsx"));
const Settings = lazy(() => import("./pages/Settings.jsx"));
const Security = lazy(() => import("./pages/Security.jsx"));
const SecurityCenter = lazy(() => import("./pages/SecurityCenter.jsx"));
const SecurityPolicy = lazy(() => import("./pages/SecurityPolicy"));
const SecurityIntelligence = lazy(() => import("./pages/SecurityIntelligence"));

const PAGES: Record<string, React.ComponentType> = {
  "/": CommandCenter,
  "/env": LiveEnvironment,
  "/network": Network,
  "/cloud": Cloud,
  "/vendor": Vendor,
  "/hardware": Hardware,
  "/crypto": Crypto,
  "/assets": Assets,
  "/cmdb": Cmdb,
  "/scope": Scope,
  "/crypto-assets": CryptoAssets,
  "/certificates": Certificates,
  "/libraries": Libraries,
  "/protocols": Protocols,
  "/catalog": Catalog,
  "/cbom": Cbom,
  "/hbom": Hbom,
  "/graph": Graph,
  "/pqc": Pqc,
  "/agility": Agility,
  "/risk": Risk,
  "/drift": Drift,
  "/alerts": Alerts,
  "/whatif": WhatIf,
  "/migration": Migration,
  "/compliance": Compliance,
  "/governance": Governance,
  "/sectors": Sectors,
  "/onboarding": Onboarding,
  "/platform": PlatformP2,
  "/evidence": Evidence,
  "/scanners": Scanners,
  "/runtime": Runtime,
  "/live-scanners": LiveScanners,
  "/timeline": Timeline,
  "/live-asset-intelligence": LiveAssetIntelligence,
  "/supervision": Supervision,
  "/telecom": Telecom,
  "/reports": Reports,
  "/integrations": Integrations,
  "/admin": Admin,
  "/identity": Identity,
  "/crypto-assurance": CryptoAssurance,
  "/devsecops": DevSecOps,
  "/automation": Automation,
  "/resilience": Resilience,
  "/trust": Trust,
  "/role-home": RoleDashboard,
  "/executive": Executive,
  "/accuracy": Accuracy,
  "/organization": Organization,
  "/notifications": Notifications,
  "/pqc-map": PqcMap,
  "/crypto-changes": CryptoChanges,
  "/search": SearchResults,
  "/login": Login,
  "/register": Register,
  "/findings": Findings,
  "/settings": Settings,
  "/security": Security,
  "/security-center": SecurityCenter,
  "/security-policy": SecurityPolicy,
  "/security-intelligence": SecurityIntelligence,
};

function useHashRoute(): string {
  const [hash, setHash] = useState(window.location.hash || "#/");
  useEffect(() => {
    const onChange = () => setHash(window.location.hash || "#/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash.replace(/^#/, "") || "/";
}

export default function App() {
  const route = useHashRoute();
  const Page = PAGES[route] || CommandCenter;
  const active = Object.keys(PAGES).includes(route) ? route : "/";
  // Refresh server-truth identity (username + roles) from GET /auth/me via the
  // httpOnly session cookie on boot, so the UI never trusts localStorage roles.
  useEffect(() => {
    void syncSession();
  }, []);
  if (route === "/login" || route === "/register") {
    return (
      <Suspense fallback={<div className="page-loading">Loading…</div>}>
        <Page />
      </Suspense>
    );
  }
  return (
    <Layout route={active}>
      <Suspense fallback={<div className="page-loading">Loading…</div>}>
        <Page />
      </Suspense>
    </Layout>
  );
}
