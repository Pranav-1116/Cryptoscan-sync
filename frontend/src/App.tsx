/* App — route table for the ZELNX / CryptoScan console.
 *
 * One lazy-loaded route per real page (route-level code splitting: Vite emits
 * a chunk per page). Only pages that exist in src/pages/ are referenced.
 * Unknown routes redirect to the Command Center.
 */
import React, { Suspense, lazy } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { RealtimeProvider } from "./lib/realtime.js";
import Layout from "./components/Layout.jsx";
import ErrorBoundary from "./components/ErrorBoundary.js";
import { AuthProvider, RequireAuth } from "./lib/auth.js";

// Generated from src/pages/ — one entry per page file.
const Accuracy = lazy(() => import("./pages/Accuracy"));
const Intelligence = lazy(() => import("./pages/Intelligence"));
const Admin = lazy(() => import("./pages/Admin"));
const Agility = lazy(() => import("./pages/Agility"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Assets = lazy(() => import("./pages/Assets"));
const Automation = lazy(() => import("./pages/Automation"));
const BankingRegulatory = lazy(() => import("./pages/BankingRegulatory"));
const Catalog = lazy(() => import("./pages/Catalog"));
const Cbom = lazy(() => import("./pages/Cbom"));
const Certificates = lazy(() => import("./pages/Certificates"));
const Cloud = lazy(() => import("./pages/Cloud"));
const Cmdb = lazy(() => import("./pages/Cmdb"));
const CryptoLog = lazy(() => import("./pages/CryptoLog"));
const AssuranceCoverage = lazy(() => import("./pages/AssuranceCoverage"));
const Audit = lazy(() => import("./pages/Audit"));
const AssuranceQualification = lazy(() => import("./pages/AssuranceQualification"));
const AssuranceRecords = lazy(() => import("./pages/AssuranceRecords"));
const AssuranceSampling = lazy(() => import("./pages/AssuranceSampling"));
const AssuranceTrace = lazy(() => import("./pages/AssuranceTrace"));
const LaunchReadiness = lazy(() => import("./pages/LaunchReadiness"));
const OperatorDecisions = lazy(() => import("./pages/OperatorDecisions"));
const CommandCenter = lazy(() => import("./pages/CommandCenter"));
const Compliance = lazy(() => import("./pages/Compliance"));
const Crypto = lazy(() => import("./pages/Crypto"));
const CryptoAssets = lazy(() => import("./pages/CryptoAssets"));
const CryptoAssurance = lazy(() => import("./pages/CryptoAssurance"));
const CryptoChanges = lazy(() => import("./pages/CryptoChanges"));
const DependencyGraph = lazy(() => import("./pages/DependencyGraph"));
const DevSecOps = lazy(() => import("./pages/DevSecOps"));
const Drift = lazy(() => import("./pages/Drift"));
const Evidence = lazy(() => import("./pages/Evidence"));
const Executive = lazy(() => import("./pages/Executive"));
const Findings = lazy(() => import("./pages/Findings"));
const Governance = lazy(() => import("./pages/Governance"));
const Graph = lazy(() => import("./pages/Graph"));
const Hardware = lazy(() => import("./pages/Hardware"));
const Hbom = lazy(() => import("./pages/Hbom"));
const Identity = lazy(() => import("./pages/Identity"));
const Integrations = lazy(() => import("./pages/Integrations"));
const InviteAccept = lazy(() => import("./pages/InviteAccept"));
const Libraries = lazy(() => import("./pages/Libraries"));
const LiveAssetIntelligence = lazy(() => import("./pages/LiveAssetIntelligence"));
const LiveEnvironment = lazy(() => import("./pages/LiveEnvironment"));
const LiveMonitor = lazy(() => import("./pages/LiveMonitor"));
const LiveEstate = lazy(() => import("./pages/LiveEstate"));
const LiveScanners = lazy(() => import("./pages/LiveScanners"));
const LiveStream = lazy(() => import("./pages/LiveStream"));
const Login = lazy(() => import("./pages/Login"));
const Nbom = lazy(() => import("./pages/Nbom"));
const Sbom = lazy(() => import("./pages/Sbom"));
const Vbom = lazy(() => import("./pages/Vbom"));
const Migration = lazy(() => import("./pages/Migration"));
const Network = lazy(() => import("./pages/Network"));
const Notifications = lazy(() => import("./pages/Notifications"));
const Onboarding = lazy(() => import("./pages/Onboarding"));
const Organization = lazy(() => import("./pages/Organization"));
const PlatformP2 = lazy(() => import("./pages/PlatformP2"));
const Pqc = lazy(() => import("./pages/Pqc"));
const PqcMap = lazy(() => import("./pages/PqcMap"));
const Priorities = lazy(() => import("./pages/Priorities"));
const Remediation = lazy(() => import("./pages/Remediation"));
const Protocols = lazy(() => import("./pages/Protocols"));
const Register = lazy(() => import("./pages/Register"));
const Reports = lazy(() => import("./pages/Reports"));
const ResetPassword = lazy(() => import("./pages/ResetPassword"));
const Resilience = lazy(() => import("./pages/Resilience"));
const SecurityControls = lazy(() => import("./pages/SecurityControls"));
const Risk = lazy(() => import("./pages/Risk"));
const RoleDashboard = lazy(() => import("./pages/RoleDashboard"));
const Runtime = lazy(() => import("./pages/Runtime"));
const Scanners = lazy(() => import("./pages/Scanners"));
const Scope = lazy(() => import("./pages/Scope"));
const SearchResults = lazy(() => import("./pages/SearchResults"));
const Sectors = lazy(() => import("./pages/Sectors"));
const Security = lazy(() => import("./pages/Security"));
const SecurityCenter = lazy(() => import("./pages/SecurityCenter"));
const SecurityIntelligence = lazy(() => import("./pages/SecurityIntelligence"));
const SecurityPolicy = lazy(() => import("./pages/SecurityPolicy"));
const Settings = lazy(() => import("./pages/Settings"));
const Supervision = lazy(() => import("./pages/Supervision"));
const SystemHealth = lazy(() => import("./pages/SystemHealth"));
const Telecom = lazy(() => import("./pages/Telecom"));
const Tenancy = lazy(() => import("./pages/Tenancy"));
const Timeline = lazy(() => import("./pages/Timeline"));
const Trust = lazy(() => import("./pages/Trust"));
const Vendor = lazy(() => import("./pages/Vendor"));
const VendorDueDiligence = lazy(() => import("./pages/VendorDueDiligence"));
const WhatIf = lazy(() => import("./pages/WhatIf"));
const Simulation = lazy(() => import("./pages/Simulation"));
const DigitalTwin = lazy(() => import("./pages/DigitalTwin"));
const CollectorDepth = lazy(() => import("./pages/CollectorDepth"));
const EstateTwin = lazy(() => import("./pages/EstateTwin"));
const TwinWalkthrough = lazy(() => import("./pages/TwinWalkthrough"));

function PublicEntry({ children, resetKey }: { children: React.ReactNode; resetKey: string }) {
  return (
    <ErrorBoundary resetKey={resetKey}>
      <Suspense fallback={<div className="route-loading" role="status">Loading secure entry…</div>}>
        <div className="auth-entry">{children}</div>
      </Suspense>
    </ErrorBoundary>
  );
}

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          {/* Authentication is a separate entry flow. It never mounts the
              authenticated shell, realtime stream, or primary navigation. */}
          <Route path="/login" element={<PublicEntry resetKey="login"><Login /></PublicEntry>} />
          <Route path="/register" element={<PublicEntry resetKey="register"><Register /></PublicEntry>} />
          <Route path="/reset-password" element={<PublicEntry resetKey="reset-password"><ResetPassword /></PublicEntry>} />
          <Route path="/invite-accept" element={<PublicEntry resetKey="invite-accept"><InviteAccept /></PublicEntry>} />
          <Route path="*" element={
            <RequireAuth>
              <RealtimeProvider>
                <Layout>
                  <RoutedPages />
                </Layout>
              </RealtimeProvider>
            </RequireAuth>
          } />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

/* Inside BrowserRouter so it can read the current path: the boundary is keyed
 * on the route, so navigating away from a page that threw clears the error
 * instead of stranding the operator on it. */
function RoutedPages() {
  const { pathname } = useLocation();
  const reducedMotion = useReducedMotion();
  return (
    <ErrorBoundary resetKey={pathname}>
      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          key={pathname}
          className="route-frame"
          initial={reducedMotion ? false : { opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={reducedMotion ? undefined : { opacity: 0, y: -4 }}
          transition={reducedMotion ? { duration: 0 } : { type: "spring", stiffness: 100, damping: 15 }}
        >
          <Suspense fallback={<div className="route-loading" role="status">Loading workspace…</div>}>
            <Routes>
      <Route path="/" element={<Navigate to="/command-center" replace />} />
      <Route path="/banking-regulatory" element={<BankingRegulatory />} />
      <Route path="/accuracy" element={<Accuracy />} />
      <Route path="/intelligence" element={<Intelligence />} />
      {/* Legacy bookmarks resolve inside the authenticated shell, without duplicating pages. */}
      <Route path="/audit" element={<Audit />} />
      <Route path="/remediation" element={<Remediation />} />
      <Route path="/techbom" element={<Navigate to="/live-asset-intelligence" replace />} />
      <Route path="/admin" element={<Admin />} />
      <Route path="/agility" element={<Agility />} />
      <Route path="/alerts" element={<Alerts />} />
      <Route path="/assets" element={<Assets />} />
      <Route path="/automation" element={<Automation />} />
      <Route path="/catalog" element={<Catalog />} />
      <Route path="/cbom" element={<Cbom />} />
      <Route path="/certificates" element={<Certificates />} />
      <Route path="/cryptolog" element={<CryptoLog />} />
      <Route path="/cloud" element={<Cloud />} />
      <Route path="/cmdb" element={<Cmdb />} />
      <Route path="/launch-readiness" element={<LaunchReadiness />} />
      <Route path="/operator-decisions" element={<OperatorDecisions />} />
      <Route path="/assurance-records" element={<AssuranceRecords />} />
      <Route path="/assurance-coverage" element={<AssuranceCoverage />} />
      <Route path="/assurance-trace" element={<AssuranceTrace />} />
      <Route path="/assurance-sampling" element={<AssuranceSampling />} />
      <Route path="/assurance-qualification" element={<AssuranceQualification />} />
      <Route path="/command-center" element={<CommandCenter />} />
      <Route path="/compliance" element={<Compliance />} />
      <Route path="/crypto" element={<Crypto />} />
      <Route path="/crypto-assets" element={<CryptoAssets />} />
      <Route path="/crypto-assurance" element={<CryptoAssurance />} />
      <Route path="/crypto-changes" element={<CryptoChanges />} />
      <Route path="/dependency-graph" element={<DependencyGraph />} />
      <Route path="/dev-sec-ops" element={<DevSecOps />} />
      <Route path="/drift" element={<Drift />} />
      <Route path="/evidence" element={<Evidence />} />
      <Route path="/executive" element={<Executive />} />
      <Route path="/findings" element={<Findings />} />
      <Route path="/governance" element={<Governance />} />
      <Route path="/graph" element={<Graph />} />
      <Route path="/hardware" element={<Hardware />} />
      <Route path="/hbom" element={<Hbom />} />
      <Route path="/identity" element={<Identity />} />
      <Route path="/integrations" element={<Integrations />} />
      <Route path="/libraries" element={<Libraries />} />
      <Route path="/live-asset-intelligence" element={<LiveAssetIntelligence />} />
      <Route path="/live-environment" element={<LiveEnvironment />} />
      <Route path="/live-monitor" element={<LiveMonitor />} />
      <Route path="/live" element={<LiveEstate />} />
      <Route path="/live-scanners" element={<LiveScanners />} />
      <Route path="/live-stream" element={<LiveStream />} />
      <Route path="/migration" element={<Migration />} />
      <Route path="/network" element={<Network />} />
      <Route path="/notifications" element={<Notifications />} />
      <Route path="/onboarding" element={<Onboarding />} />
      <Route path="/organization" element={<Organization />} />
      <Route path="/platform-p2" element={<PlatformP2 />} />
      <Route path="/pqc" element={<Pqc />} />
      <Route path="/pqc-map" element={<PqcMap />} />
      <Route path="/priorities" element={<Priorities />} />
      <Route path="/protocols" element={<Protocols />} />
      <Route path="/reports" element={<Reports />} />
      <Route path="/resilience" element={<Resilience />} />
      <Route path="/security-controls" element={<SecurityControls />} />
      <Route path="/risk" element={<Risk />} />
      <Route path="/role-dashboard" element={<RoleDashboard />} />
      <Route path="/runtime" element={<Runtime />} />
      <Route path="/scanners" element={<Scanners />} />
      <Route path="/collector-depth" element={<CollectorDepth />} />
      <Route path="/scope" element={<Scope />} />
      <Route path="/search-results" element={<SearchResults />} />
      <Route path="/sectors" element={<Sectors />} />
      <Route path="/security" element={<Security />} />
      <Route path="/security-center" element={<SecurityCenter />} />
      <Route path="/security-intelligence" element={<SecurityIntelligence />} />
      <Route path="/security-policy" element={<SecurityPolicy />} />
      <Route path="/system-health" element={<SystemHealth />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/supervision" element={<Supervision />} />
      <Route path="/telecom" element={<Telecom />} />
      <Route path="/tenancy" element={<Tenancy />} />
      <Route path="/timeline" element={<Timeline />} />
      <Route path="/trust" element={<Trust />} />
      <Route path="/vendor" element={<Vendor />} />
      <Route path="/vendor-due-diligence" element={<VendorDueDiligence />} />
      <Route path="/nbom" element={<Nbom />} />
      <Route path="/sbom" element={<Sbom />} />
      <Route path="/vbom" element={<Vbom />} />
      <Route path="/what-if" element={<WhatIf />} />
      <Route path="/simulation" element={<Simulation />} />
      <Route path="/digital-twin" element={<DigitalTwin />} />
      <Route path="/estate-twin" element={<EstateTwin />} />
      <Route path="/twin-walkthrough" element={<TwinWalkthrough />} />
      <Route path="*" element={<Navigate to="/command-center" replace />} />            </Routes>
          </Suspense>
        </motion.div>
      </AnimatePresence>
    </ErrorBoundary>
  );
}

export default App;
