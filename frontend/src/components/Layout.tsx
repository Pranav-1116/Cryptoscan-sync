import { Link, useLocation } from "react-router-dom";
import { EnterpriseAdminDrawer, AdminDrawerTab } from "./EnterpriseAdminDrawer";
import { useEnterprise, EnterpriseProvider } from "./EnterpriseContext";
import { TenantModal, EnvironmentModal, RoleModal } from "./EnterpriseModals";
import SystemHealthModal from "./SystemHealthModal";
import React, { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import autoAnimate from "@formkit/auto-animate";
import {
  Atom, Bank, Buildings, Certificate, ChartLineUp, Cloud,
  Code, Cpu, Cube, FileText, GearSix, GlobeHemisphereWest, Graph, HardDrives,
  Key, ListChecks, MagnifyingGlass, Stack, PlugsConnected, Pulse, Scan,
  Scales, ShieldCheck, SlidersHorizontal, UsersThree, type Icon,
} from "@phosphor-icons/react";
import { BrandMark, ICON_LG, ICON_MD, ICON_SM, IconCaretDown, IconCaretLeft, IconCaretRight, IconClock, IconClose, IconDark, IconKeyboard, IconLight, IconSearch, IconSecurity, IconTenant, IconUser } from "./icons";
import { useLiveTicker, useAlertToasts, Toasts } from "./Live.jsx";
import SearchOverlay from "./Search";
import { getToken, setToken, getUserName, apiMyGrants, apiStatsSummary } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";
import { tierOf, TIER_LABEL, TIER_DETAIL, type Tier } from "../lib/maturity.js";
import { RequireRole } from "../lib/auth.js";

// Core categories per UX Prompt:
// Overview, Discovery, Intelligence, Governance, Output, Administration
type NavItem = { to: string; label: string; icon: Icon };
type NavSection = { title: string; items: NavItem[] };

// The navigation is deliberately data-driven: the same contract feeds the
// sidebar, maturity labels, search affordances and route-coverage tests. The
// duplicate Security Center placement is intentional: audit is a governance
// workflow, while the same server-verified surface is also an administration
// control. It remains one route and one source of truth.
const PRIMARY_SECTIONS: NavSection[] = [
  {
    title: "Overview",
    items: [
      { to: "/command-center", label: "Dashboard", icon: ChartLineUp },
      { to: "/launch-readiness", label: "Launch readiness", icon: Pulse },
      { to: "/operator-decisions", label: "Operator decisions", icon: Pulse },
      { to: "/live-stream", label: "Activity", icon: Pulse },
    ],
  },
  {
    title: "Discovery",
    items: [
      { to: "/scanners", label: "Scan", icon: Scan },
      { to: "/live-scanners", label: "Live Scanners", icon: Pulse },
      { to: "/assets", label: "Assets", icon: Cube },
      { to: "/network", label: "Network", icon: GlobeHemisphereWest },
      { to: "/cloud", label: "Cloud", icon: Cloud },
      { to: "/dev-sec-ops", label: "Applications", icon: Code },
      { to: "/hardware", label: "Hardware", icon: Cpu },
      { to: "/certificates", label: "Certificates", icon: Certificate },
      { to: "/vendor", label: "Vendors", icon: Buildings },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { to: "/crypto", label: "Cryptography", icon: Key },
      { to: "/cbom", label: "Crypto Inventory (CBOM)", icon: Atom },
      { to: "/crypto-assets", label: "Algorithm Catalog", icon: Key },
      { to: "/live-asset-intelligence", label: "Technology BOM", icon: Stack },
      { to: "/sbom", label: "SBOM", icon: Cube },
      { to: "/hbom", label: "HBOM", icon: HardDrives },
      { to: "/nbom", label: "NBOM", icon: GlobeHemisphereWest },
      { to: "/vbom", label: "VBOM", icon: Buildings },
      { to: "/dependency-graph", label: "Dependencies", icon: Graph },
      { to: "/graph", label: "Graph Explorer", icon: Graph },
      { to: "/findings", label: "Findings", icon: ListChecks },
      { to: "/pqc", label: "PQC Readiness", icon: ShieldCheck },
      { to: "/agility", label: "Crypto Agility", icon: SlidersHorizontal },
      { to: "/drift", label: "Crypto Drift", icon: Pulse },
    ],
  },
  {
    title: "Governance",
    items: [
      { to: "/banking-regulatory", label: "Banking & SWIFT", icon: Bank },
      { to: "/security-policy", label: "Policies", icon: Scales },
      { to: "/compliance", label: "Compliance", icon: ListChecks },
      { to: "/evidence", label: "Evidence", icon: FileText },
      { to: "/security-center", label: "Audit Log", icon: ListChecks },
      { to: "/remediation", label: "Remediation Tasks", icon: ListChecks },
      { to: "/priorities", label: "Remediation Priorities", icon: ListChecks },
      { to: "/migration", label: "Migration", icon: ShieldCheck },
    ],
  },
  {
    title: "Output",
    items: [
      { to: "/reports", label: "Reports", icon: FileText },
      { to: "/what-if", label: "What-If Analysis", icon: MagnifyingGlass },
      { to: "/digital-twin", label: "Digital Twin", icon: Stack },
    ],
  },
  {
    title: "Administration",
    items: [
      { to: "/system-health", label: "System Health", icon: Pulse },
      { to: "/settings", label: "Settings & Org", icon: GearSix },
      { to: "/security-center", label: "Security Center", icon: ShieldCheck },
      { to: "/identity", label: "Users & Teams", icon: UsersThree },
      { to: "/integrations", label: "Integrations & API", icon: PlugsConnected },
    ],
  },
];

const TIER_STYLE: Record<Tier, { bg: string; fg: string; border: string }> = {
  ga: { bg: "color-mix(in srgb, var(--green) 10%, transparent)", fg: "var(--green)", border: "color-mix(in srgb, var(--green) 35%, transparent)" },
  beta: { bg: "color-mix(in srgb, var(--amber) 10%, transparent)", fg: "var(--amber)", border: "color-mix(in srgb, var(--amber) 40%, transparent)" },
  preview: { bg: "color-mix(in srgb, var(--violet) 12%, transparent)", fg: "var(--slate)", border: "color-mix(in srgb, var(--violet) 45%, transparent)" },
};

/* TierPill — GA surfaces carry no pill (the default); beta/preview are marked
 * so the sidebar itself says which parts of the product are proven. */
export function TierPill({ tier, compact = false }: { tier: Tier; compact?: boolean }) {
  if (tier === "ga" && compact) return null;
  const st = TIER_STYLE[tier];
  return (
    <span
      className={`tier-pill tier-${tier}`}
      data-tier={tier}
      title={TIER_DETAIL[tier]}
      style={{
        marginLeft: compact ? "auto" : 8, fontSize: compact ? 9 : 10, fontWeight: 700, letterSpacing: 0.5,
        textTransform: "uppercase", padding: compact ? "1px 5px" : "2px 7px", borderRadius: "var(--r)",
        background: st.bg, color: st.fg, border: `1px solid ${st.border}`, lineHeight: 1.4, whiteSpace: "nowrap",
      }}
    >
      {TIER_LABEL[tier]}
    </span>
  );
}

/* MaturityBanner — one line under the header for beta/preview pages: what the
 * tier means, and where the full table lives. GA pages render nothing. */
export function MaturityBanner({ tier, route }: { tier: Tier; route: string }) {
  if (tier === "ga") return null;
  const st = TIER_STYLE[tier];
  return (
    <div
      className={`maturity-banner maturity-${tier}`}
      data-tier={tier}
      role="note"
      style={{
        display: "flex", alignItems: "center", gap: 10, margin: "0 0 12px", padding: "6px 12px",
        borderRadius: "var(--r)", background: st.bg, border: `1px solid ${st.border}`, fontSize: 12, color: "var(--dim)",
      }}
    >
      <TierPill tier={tier} />
      <span>
        <b style={{ color: st.fg }}>{TIER_LABEL[tier]} surface.</b> {TIER_DETAIL[tier]}{" "}
        <Link to="/scope" style={{ color: st.fg }}>See capability maturity →</Link>
      </span>
      <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)" }}>{route}</span>
    </div>
  );
}

function LayoutInner({ route: propRoute, children }: { route?: string; children: React.ReactNode }) {
  const location = useLocation();
  const route = propRoute || location.pathname;
  const { role, env, org, infoLevel, setInfoLevel, timezone, setTimezone } = useEnterprise();
  const [showTenantModal, setShowTenantModal] = useState(false);
  const [showEnvModal, setShowEnvModal] = useState(false);
  const [showRoleModal, setShowRoleModal] = useState(false);
  const [showAdminDrawer, setShowAdminDrawer] = useState(false);
  const [adminDrawerTab, setAdminDrawerTab] = useState<AdminDrawerTab>("security_center");
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);
  const { t, dir } = useI18n();
  const [showSearch, setShowSearch] = useState(false);
  const [showHealthModal, setShowHealthModal] = useState(false);
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    try { return localStorage.getItem("zelnx-sidebar-collapsed") === "true"; } catch { return false; }
  });
  const navRef = useRef<HTMLElement | null>(null);
  const [theme, setTheme] = useState<string>(() => {
    try {
      const stored = localStorage.getItem("zelnx-theme");
      if (stored) return stored;
    } catch { /* ignore */ }
    // §5 (round 66): first visit honors the OS preference instead of
    // assuming dark — an operator whose floor runs light shouldn't have
    // to find the toggle. An explicit choice (localStorage) always wins.
    if (typeof window !== "undefined" && typeof window.matchMedia === "function"
      && window.matchMedia("(prefers-color-scheme: light)").matches) return "light";
    return "dark";
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

  // FormKit handles the sidebar's dynamic height when groups, labels and
  // maturity pills appear/disappear; motion handles the shell's spatial
  // collapse. Both are opt-in and preserve the browser's reduced-motion choice.
  useEffect(() => {
    // jsdom does not implement matchMedia; the navigation remains fully
    // functional in tests and reduced-motion environments without animation.
    if (!navRef.current || typeof window.matchMedia !== "function") return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const controller = autoAnimate(navRef.current, { duration: 180, easing: "ease-out" });
    return () => controller.destroy?.();
  }, []);

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
    <motion.div
      className={`shell ${isCollapsed ? "collapsed" : ""}`}
      layout
      transition={{ type: "spring", stiffness: 100, damping: 15 }}
      dir={dir}
      data-sidebar-collapsed={isCollapsed ? "true" : "false"}
    >
      {/* §5 (round 66): the first focusable element on every page — keyboard
          users otherwise tab through 39 nav links before reaching content. */}
      <a href="#main-content" className="skip-link">Skip to main content</a>
      <motion.aside className="sidebar" layout="position" aria-label="Primary navigation">
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "4px 8px 16px" }}>
          <Link to="/" className="logo" style={{ display: "flex", alignItems: "center", gap: 11, fontWeight: 700, fontSize: 17, letterSpacing: "0.02em", textDecoration: "none" }}>
            <BrandMark size={30} />
            <span className="logo-text" style={{ color: "var(--text)" }}>ZELNX<span style={{ color: "var(--faint)", fontWeight: 500, fontSize: 10, marginLeft: 6, letterSpacing: "0.14em" }}>SEC</span></span>
          </Link>
          <button
            onClick={toggleSidebar}
            title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="icon-btn"
            aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {isCollapsed ? <IconCaretRight size={ICON_MD} /> : <IconCaretLeft size={ICON_MD} />}
          </button>
        </div>

        
        {/* Enterprise Organization & Environment Selectors (Sections 54 & 55) */}
        {!isCollapsed && (
          <div className="scope-group">
            <button
              onClick={() => setShowTenantModal(true)}
              className="scope-sel"
              title="Switch Organization / Business Unit"
            >
              <span className="ico-row">
                <IconTenant className="ico" size={ICON_MD} />
                <span>{org.name.split("·")[1]?.trim() || org.name}</span>
              </span>
              <IconCaretDown className="ico" size={ICON_SM} color="var(--faint)" />
            </button>

            <button
              onClick={() => setShowEnvModal(true)}
              className={`scope-sel env${env === "Production" ? " is-prod" : ""}`}
              title="Switch Deployment Environment"
            >
              <span className="ico-row">
                <span className="scope-dot" />
                <span>{env.toUpperCase()}</span>
              </span>
              <IconCaretDown className="ico" size={ICON_SM} color="var(--faint)" />
            </button>
          </div>
        )}

        {/* Action button inside sidebar: Start Scan */}
        {!isCollapsed && (
          <RequireRole anyOf={["superadmin", "ciso", "security_analyst", "developer", "scanner"]}>
            <div style={{ padding: "0 8px 12px" }}>
              <Link
                to="/scanners"
                className="btn primary"
                style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "8px", width: "100%", padding: "8px 12px", textDecoration: "none", borderRadius: "var(--r)", fontSize: "12.5px" }}
              >
                <span>+</span> Start Scan
              </Link>
            </div>
          </RequireRole>
        )}

        <nav ref={navRef} className="primary-nav" aria-label="Primary console sections">
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
                  aria-label={isCollapsed ? item.label : undefined}
                  aria-current={active ? "page" : undefined}
                >
                  <span className="nav-icon" aria-hidden="true">
                    <item.icon size={18} weight={active ? "fill" : "regular"} />
                  </span>
                  <span className="nav-text">{item.label}</span>
                  <TierPill tier={tierOf(item.to)} compact />
                </Link>
              );
            })}
          </React.Fragment>
          ))}
        </nav>

        <div style={{ marginTop: 24, padding: "0 8px" }}>
          <div className="realtime-banner" style={{
            color: ticker.backend ? "var(--green)" : "var(--amber)",
            borderColor: ticker.backend ? "color-mix(in srgb, var(--green) 35%, transparent)" : undefined,
            background: ticker.backend ? "color-mix(in srgb, var(--green) 7%, transparent)" : undefined,
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
      </motion.aside>

      <main className="main" id="main-content" tabIndex={-1}>
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
    style={{ display: "flex", alignItems: "center", gap: "8px", cursor: "pointer", background: "var(--panel)", padding: "4px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)" }}
    title="Click to view 24/7 Engine Health & Status"
  >
    <span className="live-dot" style={{ background: s.c, animation: s.pulse ? undefined : "none" }} />
    <span style={{ fontWeight: 600, color: s.c, fontSize: "12px" }}>ZELNX Operational</span>
    <IconCaretDown className="ico" size={ICON_SM} color="var(--faint)" />
  </div>
              </>
            );
          })()}
          <span className="item">{t("head.lastEvent")} <b>{ticker.ago === null ? "—" : `${ticker.ago}s`}</b></span>
          <span className="item">{t("head.eventsPerSec")} <b>{ticker.backend && ticker.eps !== null ? ticker.eps : "—"}</b></span>
          <span className="item">Scans <b>{st ? Number(st.total_scans ?? 0) : "—"}</b></span>
          <span className="item">Findings <b>{st ? Number(st.total_findings ?? 0) : "—"}</b></span>
          {abac && (
            <span className="item" title={t("head.abac")}>
              ABAC <b style={{ color: abac.enforced ? "var(--green)" : "var(--amber)" }}>
                {abac.enforced ? `${abac.grants} grants` : "off"}
              </b>
            </span>
          )}

          <button
            type="button"
            className="searchbox"
            aria-label="Open global search"
            onClick={() => setShowSearch(true)}
            style={{ borderRadius: "var(--r)", background: "var(--panel)", display: "flex", alignItems: "center", gap: "10px", padding: "6px 14px", cursor: "pointer", border: "1px solid var(--line)", font: "inherit", textAlign: "left" }}
          >
            <IconSearch className="ico" size={ICON_MD} color="var(--accent)" />
            <span style={{ fontSize: "12.5px" }}>Search the catalog...</span>
            <span style={{ marginLeft: "auto", fontSize: "10px", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", padding: "1px 6px", fontFamily: "var(--mono)" }}>⌘K</span>
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

          <LanguageSwitcher />

          {/* Section 57: Global Timezone Switcher */}
          <button
            className="btn sm ghost"
            onClick={() => setTimezone(timezone === "UTC" ? "Local" : timezone === "Local" ? "GST" : "UTC")}
            style={{ fontFamily: "var(--mono)", fontSize: "11px" }}
            title="Toggle Global Timezone (UTC / Local / GST)"
          >
            <span className="ico-row">
              <IconClock className="ico" size={ICON_SM} />
              <span>{timezone}</span>
            </span>
          </button>

          {/* Section 53: Role Badge / Selector */}
          <button
            onClick={() => setShowRoleModal(true)}
            className="btn sm ico-row"
            style={{ fontSize: "11.5px" }}
            title="Click to Switch Role Profile (RBAC)"
          >
            <IconUser className="ico" size={ICON_SM} />
            <span>{role}</span>
          </button>

          <button
            className="btn sm"
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            onClick={() => setTheme((x) => (x === "dark" ? "light" : "dark"))}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? <IconDark className="ico" size={ICON_MD} /> : <IconLight className="ico" size={ICON_MD} />}
          </button>

          <button
            className="btn sm ico-row"
            onClick={() => { setAdminDrawerTab("security_center"); setShowAdminDrawer(true); }}
            style={{ fontSize: "11px", borderColor: "var(--accent)", color: "var(--accent)" }}
            title="Enterprise Identity, Access & Governance Suite"
          >
            <IconSecurity className="ico" size={ICON_SM} />
            <span>Security Center</span>
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

        <div>
          <MaturityBanner tier={tierOf(route)} route={route} />
          {children}
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
          <div style={{ background: "var(--bg-2)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", padding: "24px", maxWidth: "480px", width: "90%", boxShadow: "0 20px 40px rgba(0,0,0,0.6)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
              <div className="ico-row" style={{ fontWeight: 700, fontSize: "16px", color: "var(--text)" }}><IconKeyboard className="ico" size={ICON_LG} /><span>Global Keyboard Shortcuts</span></div>
              <button onClick={() => setShowShortcutsHelp(false)} className="icon-btn" aria-label="Close"><IconClose size={ICON_MD} /></button>
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
                  <code style={{ background: "var(--bg-2)", border: "1px solid var(--line)", padding: "3px 8px", borderRadius: "var(--r)", color: "var(--cyan)", fontFamily: "var(--mono)" }}>{sc.key}</code>
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
    </motion.div>
  );
}


export default function Layout({ route, children }: { route?: string; children: React.ReactNode }) {
  return (
    <EnterpriseProvider>
      <LayoutInner route={route}>
        {children}
      </LayoutInner>
    </EnterpriseProvider>
  );
}
