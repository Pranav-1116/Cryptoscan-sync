import React, { useEffect, useState } from "react";
import Layout from "./components/Layout.jsx";
import CommandCenter from "./pages/CommandCenter.jsx";
import LiveEnvironment from "./pages/LiveEnvironment.jsx";
import Network from "./pages/Network.jsx";
import Cloud from "./pages/Cloud.jsx";
import Vendor from "./pages/Vendor.jsx";
import Hardware from "./pages/Hardware.jsx";
import Crypto from "./pages/Crypto.jsx";
import Assets from "./pages/Assets.jsx";
import CryptoAssets from "./pages/CryptoAssets.jsx";
import Certificates from "./pages/Certificates.jsx";
import Libraries from "./pages/Libraries.jsx";
import Protocols from "./pages/Protocols.jsx";
import Catalog from "./pages/Catalog.jsx";
import Cbom from "./pages/Cbom.jsx";
import Hbom from "./pages/Hbom.jsx";
import Graph from "./pages/Graph.jsx";
import Pqc from "./pages/Pqc.jsx";
import Agility from "./pages/Agility.jsx";
import Risk from "./pages/Risk.jsx";
import Drift from "./pages/Drift.jsx";
import Alerts from "./pages/Alerts.jsx";
import WhatIf from "./pages/WhatIf.jsx";
import Migration from "./pages/Migration.jsx";
import Compliance from "./pages/Compliance.jsx";
import Governance from "./pages/Governance.jsx";
import Sectors from "./pages/Sectors.jsx";
import Onboarding from "./pages/Onboarding.jsx";
import PlatformP2 from "./pages/PlatformP2";
import Evidence from "./pages/Evidence.jsx";
import Scanners from "./pages/Scanners.jsx";
import Runtime from "./pages/Runtime.jsx";
import LiveScanners from "./pages/LiveScanners.jsx";
import Timeline from "./pages/Timeline.jsx";
import Reports from "./pages/Reports.jsx";
import Integrations from "./pages/Integrations.jsx";
import Admin from "./pages/Admin.jsx";
import Identity from "./pages/Identity.jsx";
import CryptoAssurance from "./pages/CryptoAssurance.jsx";
import DevSecOps from "./pages/DevSecOps.jsx";
import Accuracy from "./pages/Accuracy.jsx";
import Organization from "./pages/Organization.jsx";
import Notifications from "./pages/Notifications.jsx";
import PqcMap from "./pages/PqcMap.jsx";
import CryptoChanges from "./pages/CryptoChanges.jsx";
import SearchResults from "./pages/SearchResults.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";

const PAGES: Record<string, React.ComponentType> = {
  "/": CommandCenter,
  "/env": LiveEnvironment,
  "/network": Network,
  "/cloud": Cloud,
  "/vendor": Vendor,
  "/hardware": Hardware,
  "/crypto": Crypto,
  "/assets": Assets,
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
  "/reports": Reports,
  "/integrations": Integrations,
  "/admin": Admin,
  "/identity": Identity,
  "/crypto-assurance": CryptoAssurance,
  "/devsecops": DevSecOps,
  "/accuracy": Accuracy,
  "/organization": Organization,
  "/notifications": Notifications,
  "/pqc-map": PqcMap,
  "/crypto-changes": CryptoChanges,
  "/search": SearchResults,
  "/login": Login,
  "/register": Register,
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
  if (route === "/login" || route === "/register") return <Page />;
  return (
    <Layout route={active}>
      <Page />
    </Layout>
  );
}
