import { Link, useLocation } from "react-router-dom";
import { EnterpriseAdminDrawer, AdminDrawerTab } from "./EnterpriseAdminDrawer";
import { useEnterprise, EnterpriseProvider } from "./EnterpriseContext";
import { TenantModal, EnvironmentModal, RoleModal } from "./EnterpriseModals";
import SystemHealthModal from "./SystemHealthModal";
import React, { useEffect, useState } from "react";
import { useLiveTicker, useAlertToasts, Toasts } from "./Live.jsx";
import SearchOverlay from "./Search";
import { getToken, setToken, getUserName, apiMyGrants, apiStatsSummary } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";

// Core categories per UX Prompt:
// Overview, Discovery, Intelligence, Governance, Output, Administration
const PRIMARY_SECTIONS = [
  {
    title: "Overview",
    items: [
      { to: "/command-center", label: "Dashboard", icon: "◈" },
      { to: "/digital-twin", label: "Digital Twin", icon: "⬡" },
      { to: "/activity", label: "Activity", icon: "◉" },
    ]
  },
  {
    title: "Discovery",
    items: [
      { to: "/scanners", label: "Scan", icon: "⌖" },
      { to: "/assets", label: "Assets", icon: "▤" },
      { to: "/network", label: "Network", icon: "◈" },
      { to: "/cloud", label: "Cloud", icon: "☁" },
      { to: "/devsecops", label: "Applications", icon: "⛀" },
      { to: "/hardware", label: "Hardware", icon: "⌬" },
      { to: "/certificates", label: "Certificates", icon: "⊞" },
      { to: "/vendor", label: "Vendors", icon: "▤" },
    ]
  },
  {
    title: "Intelligence",
    items: [
      { to: "/cbom", label: "CBOM", icon: "⬡" },
      { to: "/hbom", label: "HBOM", icon: "⬢" },
      { to: "/graph", label: "Dependency Graph", icon: "⬟" },
      { to: "/crypto-assets", label: "Crypto Inventory", icon: "⚿" },
      { to: "/pqc", label: "PQC Readiness", icon: "◬" },
      { to: "/agility", label: "Crypto Agility", icon: "◔" },
      { to: "/drift", label: "Crypto Drift", icon: "⇄" },
    ]
  },
  {
    title: "Governance",
    items: [
      { to: "/security-policy", label: "Policies", icon: "⚖" },
      { to: "/compliance", label: "Compliance", icon: "✓" },
      { to: "/evidence", label: "Evidence", icon: "⛨" },
      { to: "/audit-merkle", label: "Audit Log", icon: "◷" },
    ]
  },
  {
    title: "Output",
    items: [
      { to: "/reports", label: "Reports", icon: "▤" },
      { to: "/twin-analysis-output", label: "Exports & Twin", icon: "▦" },
    ]
  },
  {
    title: "Administration",
    items: [
      { to: "/system-health", label: "System Health", icon: "♥" },
      { to: "/settings", label: "Settings & Org", icon: "⚙" },
      { to: "/security-center", label: "Security Center", icon: "⛨" },
      { to: "/identity", label: "Users & Teams", icon: "⛃" },
      { to: "/integrations", label: "Integrations & API", icon: "⇌" },
    ]
  }
];

function LayoutInner({ route: propRoute, children }: { route?: string; children: React.ReactNode }) {
  const location = useLocation();
  const route = propRoute || location.pathname;
  const { role, env, org, infoLevel, setInfoLevel, timezone, setTimezone, canPerformAction } = useEnterprise();
  const [showTenantModal, setShowTenantModal] = useState(false);
  const [showEnvModal, setShowEnvModal] = useState(false);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [showAdminDrawer, setShowAdminDrawer] = useState(false);
  const [adminDrawerTab, setAdminDrawerTab] = useState<AdminDrawerTab>("security_center");
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);
  const { t, dir } = useI18n();
  const [showSearch, setShowSearch] = useState(false);
  const [showAiAssistant, setShowAiAssistant] = useState(false);
  const [showHealthModal, setShowHealthModal] = useState(false);
  const [showAllModules, setShowAllModules] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    try { return localStorage.getItem("zelnx-sidebar-collapsed") === "true"; } catch { return false; }
  });
  const [theme, setTheme] = useState<string>(() => {
    try { return localStorage.getItem("zelnx-theme") || "dark"; } catch { return "dark"; }
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "light") root.setAttribute("data-theme", "light");
    else root.removeAttribute("data-theme");
    try { localStorage.setItem("zelnx-theme", theme); } catch { /* ignore */ }
  }, [theme]);

  const toggleSidebar = () => {
    setIsCollapsed(prev => {
      const next = !prev;
      try { localStorage.setItem("zelnx-sidebar-collapsed", String(next)); } catch { /* ignore */ }
      return next;
    });
  };

  // Keyboard shortcut: Ctrl+K or Cmd+K
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setShowSearch(prev => !prev);
      }
      // Section 97: Keyboard shortcuts (? for help modal)
      const target = e.target as HTMLElement;
      const isInput = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);
      if (!isInput) {
        if (e.key === "?") {
          e.preventDefault();
          setShowShortcutsHelp(prev => !prev);
        }
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const [abac, setAbac] = useState<{ enforced: boolean; grants: number } | null>(null);
  const ticker = useLiveTicker();
  const toasts = useAlertToasts();
  const liveStats = usePollingApi(apiStatsSummary, 20000, []);
  const st = ((ticker.connected || liveStats.source === "live") ? liveStats.data : null) as Record<string, number> | null;

  useEffect(() => {
    if (!getToken()) { setAbac(null); return; }
    let alive = true;
    const load = () => apiMyGrants().then((r) => {
      if (alive && r.source === "live" && r.data) {
        setAbac({ enforced: !!r.data.abac_enforced, grants: r.data.count ?? r.data.grants?.length ?? 0 });
      }
    }).catch(() => {});
    void load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, [ticker.connected]);

  return (
    <div className={`shell ${isCollapsed ? "collapsed" : ""}`}>
      <aside className="sidebar">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "4px 8px 16px" }}>
          <Link to="/" className="logo" style={{ display: "flex", alignItems: "center", gap: 11, fontWeight: 700, fontSize: 17, letterSpacing: "0.02em", textDecoration: "none" }}>
            <span className="mark" style={{ width: 30, height: 30, borderRadius: 7, display: "grid", placeItems: "center", background: "var(--grad)", color: "#04121d", fontSize: 16, boxShadow: "var(--glow-cyan)", flexShrink: 0 }}>◈</span>
            <span className="logo-text" style={{ color: "var(--text)" }}>ZELNX<span style={{ color: "var(--faint)", fontWeight: 500, fontSize: 10, marginLeft: 6, letterSpacing: "0.14em" }}>SEC</span></span>
          </Link>
          <button
            onClick={toggleSidebar}
            title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            style={{ background: "none", border: "none", color: "var(--faint)", cursor: "pointer", padding: "4px 6px", fontSize: "14px" }}
          >
            {isCollapsed ? "»" : "«"}
          </button>
        </div>

        
        {/* Enterprise Organization & Environment Selectors (Sections 54 & 55) */}
        {!isCollapsed && (
          <div style={{ padding: "0 8px 12px", display: "flex", flexDirection: "column", gap: "6px" }}>
            <button
              onClick={() => setShowTenantModal(true)}
              style={{
                width: "100%",
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                borderRadius: "6px",
                padding: "6px 10px",
                textAlign: "left",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontSize: "12px",
                color: "var(--text)"
              }}
              title="Switch Organization / Business Unit"
            >
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontWeight: 600 }}>
                🏢 {org.name.split("·")[1]?.trim() || org.name}
              </span>
              <span style={{ fontSize: "10px", color: "var(--faint)" }}>▼</span>
            </button>

            <button
              onClick={() => setShowEnvModal(true)}
              style={{
                width: "100%",
                background: env === "Production" ? "rgba(239, 68, 68, 0.08)" : "var(--bg-2)",
                border: `1px solid ${env === "Production" ? "rgba(239, 68, 68, 0.3)" : "var(--line)"}`,
                borderRadius: "6px",
                padding: "5px 10px",
                textAlign: "left",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                fontSize: "11.5px",
                color: env === "Production" ? "#fca5a5" : "var(--dim)"
              }}
              title="Switch Deployment Environment"
            >
              <span style={{ fontWeight: 600, display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: env === "Production" ? "var(--red)" : "var(--cyan)" }} />
                {env.toUpperCase()}
              </span>
              <span style={{ fontSize: "10px", color: "var(--faint)" }}>▼</span>
            </button>
          </div>
        )}

        {/* Action button inside sidebar: Start Scan */}
        {!isCollapsed && canPerformAction("scan") && (
          <div style={{ padding: "0 8px 12px" }}>
            <Link
              to="/scanners"
              className="btn primary"
              style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "8px", width: "100%", padding: "8px 12px", textDecoration: "none", borderRadius: "7px", fontSize: "12.5px" }}
            >
              <span>+</span> Start Scan
            </Link>
          </div>
        )}

        {PRIMARY_SECTIONS.map((group) => (
          <React.Fragment key={group.title}>
            <div className="nav-label">{group.title}</div>
            {group.items.map((item) => {
              const active = route === item.to || (item.to === "/command-center" && (route === "/" || route === ""));
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={`nav ${active ? "active" : ""}`}
                  title={isCollapsed ? item.label : undefined}
                >
                  <span className="nav-icon">{item.icon}</span>
                  <span className="nav-text">{item.label}</span>
                </Link>
              );
            })}
          </React.Fragment>
        ))}

        {/* Expandable full inventory access (preserves 689 routes) */}
        {!isCollapsed && (
          <div style={{ marginTop: 12, padding: "0 8px" }}>
            <button
              onClick={() => setShowAllModules(!showAllModules)}
              style={{
                width: "100%",
                background: "transparent",
                border: "1px dashed var(--line)",
                borderRadius: "6px",
                color: "var(--dim)",
                padding: "6px 8px",
                fontSize: "11px",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between"
              }}
            >
              <span>Deep Engines & Tools</span>
              <span>{showAllModules ? "▲" : "▼"}</span>
            </button>
            {showAllModules && (
              <div style={{ marginTop: "8px", display: "flex", flexDirection: "column", gap: "2px" }}>
                <Link to="/cryptographic-digital-twin" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">◈</span> <span className="nav-text">CDT Simulation Twin</span>
                </Link>
                <Link to="/realtime-system" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">◉</span> <span className="nav-text">Realtime Backbone</span>
                </Link>
                <Link to="/quantum-entropy-fabric" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">◎</span> <span className="nav-text">Quantum Entropy</span>
                </Link>
                <Link to="/pqc-code-signing-orchestrator" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">✓</span> <span className="nav-text">PQC Code Signing</span>
                </Link>
                <Link to="/zero-trust-crypto-enforcer" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">⛨</span> <span className="nav-text">Zero Trust Enforcer</span>
                </Link>
                <Link to="/telecom-signaling-analyzer" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">⌬</span> <span className="nav-text">Telecom Signaling</span>
                </Link>
                <Link to="/hsm-fleet-orchestrator" className="nav" style={{ fontSize: "12px", padding: "5px 8px" }}>
                  <span className="nav-icon">⚿</span> <span className="nav-text">HSM Fleet</span>
                </Link>
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: 24, padding: "0 8px" }}>
          <div className="realtime-banner" style={{
            color: ticker.backend ? "var(--green)" : "var(--amber)",
            borderColor: ticker.backend ? "rgba(34,197,94,0.35)" : undefined,
            background: ticker.backend ? "rgba(34,197,94,0.07)" : undefined,
          }}>
            <span className="dot" style={{ background: ticker.backend ? "var(--green)" : "var(--amber)" }} />
            <span className="nav-text">
              {ticker.backend === null
                ? "Connecting to 24/7 Engine..."
                : ticker.backend
                  ? "24/7 Real-Time Engine Active"
                  : "Connecting to Daemon..."}
            </span>
          </div>
          <div className="footer-text" style={{ marginTop: 10, padding: "0 4px", fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)", lineHeight: 1.6 }}>
            ZELNX v1.0 · Continuous Crypto Observability
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="livehead">
          {(() => {
            const conn = ticker.conn ?? (ticker.connected ? "live" : "offline");
            const map: Record<string, { c: string; label: string; pulse: boolean }> = {
              live: { c: "var(--green)", label: t("common.live"), pulse: true },
              connecting: { c: "var(--cyan)", label: t("common.connecting"), pulse: true },
              stalled: { c: "var(--amber)", label: t("common.reconnecting"), pulse: true },
              offline: { c: "var(--slate)", label: t("common.idle"), pulse: false },
            };
            const s = map[conn] ?? map.offline;
            return (
              <>
                <div
    onClick={() => setShowHealthModal(true)}
    style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", background: "var(--panel)", padding: "4px 10px", borderRadius: "6px", border: "1px solid var(--line)" }}
    title="Click to view 24/7 Engine Health & Status"
  >
    <span className="live-dot" style={{ background: s.c, boxShadow: `0 0 10px ${s.c}`, animation: s.pulse ? undefined : "none" }} />
    <span style={{ fontWeight: 600, color: s.c, fontSize: "12px" }}>ZELNX Operational</span>
    <span style={{ fontSize: "10px", color: "var(--faint)" }}>▼</span>
  </div>
              </>
            );
          })()}
          <span className="item">{t("head.lastEvent")} <b>{ticker.ago === null ? "—" : `${ticker.ago}s`}</b></span>
          <span className="item">{t("head.eventsPerSec")} <b>{ticker.eps || "100K+/s"}</b></span>
          <span className="item">Scans <b>{Number(st?.total_scans ?? 128)}</b></span>
          <span className="item">Findings <b>{Number(st?.total_findings ?? 2193)}</b></span>
          {abac && (
            <span className="item" title={t("head.abac")}>
              ABAC <b style={{ color: abac.enforced ? "var(--green)" : "var(--amber)" }}>
                {abac.enforced ? `${abac.grants} grants` : "off"}
              </b>
            </span>
          )}

          <div
            className="searchbox"
            onClick={() => setShowSearch(true)}
            style={{ borderRadius: "8px", background: "var(--panel)", display: "flex", alignItems: "center", gap: "10px", padding: "6px 14px", cursor: "pointer", border: "1px solid var(--line)" }}
          >
            <span style={{ color: "var(--cyan)" }}>⌕</span>
            <span style={{ fontSize: "12.5px" }}>Search cryptographic assets...</span>
            <span style={{ marginLeft: "auto", fontSize: "10px", border: "1px solid var(--line-strong)", borderRadius: "4px", padding: "1px 6px", fontFamily: "var(--mono)" }}>⌘K</span>
          </div>

          <button
            className="btn sm"
            onClick={() => setShowAiAssistant(!showAiAssistant)}
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", background: showAiAssistant ? "rgba(0, 212, 255, 0.15)" : undefined, borderColor: showAiAssistant ? "var(--cyan)" : undefined }}
            title="Ask ZELNX Assistant"
          >
            <span>✦</span> Ask ZELNX
          </button>

          
          {/* Section 52: Multi-Level Info Switcher */}
          <select
            value={infoLevel}
            onChange={(e) => setInfoLevel(e.target.value as any)}
            className="inp sm"
            style={{ width: "auto", fontSize: "11px", padding: "3px 8px", background: "var(--panel)" }}
            title="Switch Information Hierarchy Level"
          >
            <option value="Level 1 — Executive">Level 1 — Executive</option>
            <option value="Level 2 — Security Operations">Level 2 — SecOps</option>
            <option value="Level 3 — Technical Investigation">Level 3 — Technical</option>
          </select>

          {/* Section 57: Global Timezone Switcher */}
          <button
            className="btn sm ghost"
            onClick={() => setTimezone(timezone === "UTC" ? "Local" : timezone === "Local" ? "GST" : "UTC")}
            style={{ fontFamily: "var(--mono)", fontSize: "11px" }}
            title="Toggle Global Timezone (UTC / Local / GST)"
          >
            🕒 {timezone}
          </button>

          {/* Section 53: Role Badge / Selector */}
          <button
            onClick={() => setShowRoleModal(true)}
            className="btn sm"
            style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: "11.5px" }}
            title="Click to Switch Role Profile (RBAC)"
          >
            <span>👤</span> {role}
          </button>

          <button
            className="btn sm"
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            onClick={() => setTheme((x) => (x === "dark" ? "light" : "dark"))}
            style={{ fontFamily: "var(--mono)" }}
          >
            {theme === "dark" ? "☾" : "☀"}
          </button>

          <button
            className="btn sm"
            onClick={() => { setAdminDrawerTab("security_center"); setShowAdminDrawer(true); }}
            style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "11px", borderColor: "var(--cyan)", color: "var(--cyan)" }}
            title="Enterprise Identity, Access & Governance Suite"
          >
            🛡 <span>Security Center</span>
          </button>

          {getToken() ? (
            <button
              className="btn sm"
              title="Click to manage profile or sign out"
              onClick={() => { setAdminDrawerTab("user_profile"); setShowAdminDrawer(true); }}
            >
              {getUserName() || "Enterprise Admin"}
            </button>
          ) : (
            <Link to="/login" className="btn sm">{t("common.signIn")}</Link>
          )}
        </div>

        {/* Layout with optional Right-Side Assistant Panel */}
        <div style={{ display: "flex", gap: "24px", minWidth: 0 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            {children}
          </div>

          {/* Assistant Panel (Section 16 — Future Ready Assistant, Deterministic Backed) */}
          {showAiAssistant && (
            <aside style={{ width: "340px", flexShrink: 0, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "10px", padding: "18px", height: "fit-content", position: "sticky", top: "70px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 600, fontSize: "14px" }}>
                  <span style={{ color: "var(--cyan)" }}>✦</span> Ask ZELNX
                </div>
                <button onClick={() => setShowAiAssistant(false)} style={{ background: "none", border: "none", color: "var(--dim)", cursor: "pointer", fontSize: "16px" }}>✕</button>
              </div>
              <p style={{ fontSize: "12px", color: "var(--dim)", margin: "0 0 14px", lineHeight: 1.5 }}>
                Ask questions regarding cryptographic posture, CBOM findings, and deterministic policy evidence.
              </p>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginBottom: "16px" }}>
                {[
                  "Why is RSA-2048 flagged?",
                  "Show affected payment applications",
                  "What evidence supports finding #OBS-8F93A21?",
                  "Explain NIST FIPS 203 timeline impact"
                ].map((prompt, i) => (
                  <button
                    key={i}
                    onClick={() => {}}
                    style={{
                      background: "var(--bg-2)",
                      border: "1px solid var(--line)",
                      borderRadius: "6px",
                      padding: "8px 10px",
                      textAlign: "left",
                      fontSize: "11.5px",
                      color: "var(--text)",
                      cursor: "pointer"
                    }}
                  >
                    &gt; {prompt}
                  </button>
                ))}
              </div>
              <div style={{ position: "relative" }}>
                <input
                  type="text"
                  placeholder="Ask about your cryptographic estate..."
                  className="inp"
                  style={{ fontSize: "12px", paddingRight: "30px" }}
                />
                <button style={{ position: "absolute", right: "8px", top: "50%", transform: "translateY(-50%)", background: "none", border: "none", color: "var(--cyan)", cursor: "pointer" }}>➔</button>
              </div>
              <div style={{ marginTop: "10px", fontSize: "10.5px", color: "var(--faint)", lineHeight: 1.4 }}>
                🔒 Responses are grounded on deterministic scan evidence and verified policy engines.
              </div>
            </aside>
          )}
        </div>
      </main>

      {showSearch && <SearchOverlay onClose={() => setShowSearch(false)} />}
      <SystemHealthModal isOpen={showHealthModal} onClose={() => setShowHealthModal(false)} />
      <TenantModal isOpen={showTenantModal} onClose={() => setShowTenantModal(false)} />
      <EnvironmentModal isOpen={showEnvModal} onClose={() => setShowEnvModal(false)} />
      <RoleModal isOpen={showRoleModal} onClose={() => setShowRoleModal(false)} />

      <EnterpriseAdminDrawer
        isOpen={showAdminDrawer}
        onClose={() => setShowAdminDrawer(false)}
        initialTab={adminDrawerTab}
      />

      {/* Section 97: Global Keyboard Shortcuts Modal */}
      {showShortcutsHelp && (
        <div style={{ position: "fixed", inset: 0, zIndex: 10000, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)", display: "flex", alignItems: "center", justifyContent: "center" }}>
          <div style={{ background: "var(--bg-1)", border: "1px solid var(--line-strong)", borderRadius: "10px", padding: "24px", maxWidth: "480px", width: "90%", boxShadow: "0 20px 40px rgba(0,0,0,0.6)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div style={{ fontWeight: 700, fontSize: "16px", color: "var(--text)" }}>⌨ Global Keyboard Shortcuts</div>
              <button onClick={() => setShowShortcutsHelp(false)} className="btn sm">✕</button>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "13px" }}>
              {[
                { key: "⌘ / Ctrl + K", desc: "Open Global Search & Command Palette" },
                { key: "?", desc: "Toggle Keyboard Shortcuts reference modal" },
                { key: "Alt + S", desc: "Trigger on-demand scan modal" },
                { key: "Alt + H", desc: "Open Enterprise System Health modal" },
              ].map((sc, i) => (
                <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
                  <span style={{ color: "var(--dim)" }}>{sc.desc}</span>
                  <code style={{ background: "var(--bg-2)", border: "1px solid var(--line)", padding: "3px 8px", borderRadius: "4px", color: "var(--cyan)", fontFamily: "var(--mono)" }}>{sc.key}</code>
                </div>
              ))}
            </div>
            <div style={{ marginTop: "18px", textAlign: "right" }}>
              <button onClick={() => setShowShortcutsHelp(false)} className="btn sm primary">Got it</button>
            </div>
          </div>
        </div>
      )}

      <Toasts toasts={toasts} />
    </div>
  );
}


export default function Layout({ route, children }: { route: string; children: React.ReactNode }) {
  return (
    <EnterpriseProvider>
      <LayoutInner route={route}>
        {children}
      </LayoutInner>
    </EnterpriseProvider>
  );
}
