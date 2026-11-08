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
import { hasSession, setToken, getUserName, apiMyGrants, apiStatsSummary } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";
import { RequireRole } from "../lib/auth.js";

// One nav row per job, and every page still one click away.
//
// The sidebar used to be a flat list of fifty links under six headings: every BOM kind,
// every assurance page and every remediation page sat at the same level as Dashboard, so
// finding anything meant reading fifty labels. Nothing is removed here — every route is
// still in the tree — but pages that answer the same question are folded into one group
// (the six BOMs under "BOMs", the five assurance pages under "Assurance"), and only the
// section you are actually in is open on arrival. A reader sees ~6 rows, not 56.
type NavItem = { to: string; label: string; icon: Icon; children?: NavItem[] };
type NavSection = { title: string; items: NavItem[] };
export type { NavItem, NavSection };

export const PRIMARY_SECTIONS: NavSection[] = [
  {
    title: "Overview",
    items: [
      { to: "/command-center", label: "Dashboard", icon: ChartLineUp },
      { to: "/live", label: "Live estate", icon: Pulse },
      { to: "/live-stream", label: "Activity", icon: Pulse },
      {
        to: "/live-monitor",
        label: "Monitors",
        icon: Pulse,
        children: [
          { to: "/live-monitor", label: "Live monitor", icon: Pulse },
          { to: "/live-scanners", label: "Live scanners", icon: Scan },
        ],
      },
      {
        to: "/launch-readiness",
        label: "Oversight",
        icon: ListChecks,
        children: [
          { to: "/launch-readiness", label: "Launch readiness", icon: ListChecks },
          { to: "/operator-decisions", label: "Operator decisions", icon: ListChecks },
        ],
      },
    ],
  },
  {
    title: "Discovery",
    items: [
      {
        // Discovery's own coverage answer sits next to the thing it describes:
        // what the scanners can reach, per surface, protocol, platform and BOM.
        to: "/scanners",
        label: "Scan",
        icon: Scan,
        children: [
          { to: "/scanners", label: "Scanners", icon: Scan },
          { to: "/collector-depth", label: "Collector depth", icon: Pulse },
        ],
      },
      { to: "/assets", label: "Assets", icon: Cube },
      { to: "/dev-sec-ops", label: "Applications", icon: Code },
      { to: "/certificates", label: "Certificates", icon: Certificate },
      { to: "/cryptolog", label: "CryptoLog", icon: Pulse },
      { to: "/performance", label: "Performance", icon: Pulse },
      { to: "/vendor", label: "Vendors", icon: Buildings },
      {
        to: "/network",
        label: "Infrastructure",
        icon: GlobeHemisphereWest,
        children: [
          { to: "/network", label: "Network", icon: GlobeHemisphereWest },
          { to: "/cloud", label: "Cloud", icon: Cloud },
          { to: "/hardware", label: "Hardware", icon: Cpu },
        ],
      },
    ],
  },
  {
    title: "Intelligence",
    items: [
      {
        to: "/cbom",
        label: "BOMs",
        icon: Stack,
        children: [
          { to: "/cbom", label: "CBOM", icon: Atom },
          { to: "/sbom", label: "SBOM", icon: Code },
          { to: "/hbom", label: "HBOM", icon: HardDrives },
          { to: "/nbom", label: "NBOM", icon: GlobeHemisphereWest },
          { to: "/vbom", label: "VBOM", icon: Buildings },
          { to: "/live-asset-intelligence", label: "Technology BOM", icon: Stack },
        ],
      },
      {
        to: "/dependency-graph",
        label: "Dependencies",
        icon: Graph,
        children: [
          { to: "/dependency-graph", label: "Cascade", icon: Graph },
          { to: "/graph", label: "Graph explorer", icon: Graph },
        ],
      },
      {
        to: "/findings",
        label: "Posture",
        icon: ShieldCheck,
        children: [
          { to: "/crypto", label: "Cryptography", icon: Key },
          { to: "/crypto-assets", label: "Algorithm catalog", icon: Key },
          { to: "/findings", label: "Findings", icon: ListChecks },
          { to: "/pqc", label: "PQC readiness", icon: ShieldCheck },
          { to: "/intelligence", label: "Intelligence workbench", icon: ShieldCheck },
          { to: "/agility", label: "Crypto agility", icon: SlidersHorizontal },
          { to: "/drift", label: "Crypto drift", icon: Pulse },
        ],
      },
      {
        // The chain is the twin's own working order, so it is a sibling of the
        // replica view rather than a tab inside it: one screen shows what the
        // twin holds, the other shows how far down the chain that holding reaches.
        to: "/digital-twin",
        label: "Digital twin",
        icon: Stack,
        children: [
          { to: "/digital-twin", label: "Replica & scenarios", icon: Stack },
          { to: "/estate-twin", label: "Twin chain", icon: Graph },
          { to: "/twin-walkthrough", label: "Thirteen-step walkthrough", icon: Graph },
        ],
      },
      {
        // Simulation is its own row: it asks a question of a copy of the twin, which is a
        // different job from reading a report of what the estate already is.
        to: "/simulation",
        label: "Simulation",
        icon: MagnifyingGlass,
        children: [
          { to: "/simulation", label: "What-if workspace", icon: MagnifyingGlass },
          { to: "/what-if", label: "Migration what-if", icon: Key },
        ],
      },
      { to: "/reports", label: "Reports", icon: FileText },
    ],
  },
  {
    title: "Governance",
    items: [
      { to: "/banking-regulatory", label: "Banking & SWIFT", icon: Bank },
      { to: "/security-policy", label: "Policies", icon: Scales },
      { to: "/compliance", label: "Compliance", icon: ListChecks },
      { to: "/evidence", label: "Evidence", icon: FileText },
      {
        to: "/remediation",
        label: "Remediation",
        icon: ListChecks,
        children: [
          { to: "/remediation", label: "Tasks", icon: ListChecks },
          { to: "/priorities", label: "Priorities", icon: ListChecks },
          { to: "/migration", label: "Migration", icon: ShieldCheck },
        ],
      },
      {
        to: "/assurance-records",
        label: "Assurance",
        icon: FileText,
        children: [
          { to: "/assurance-records", label: "Records", icon: FileText },
          { to: "/assurance-coverage", label: "Coverage", icon: ListChecks },
          { to: "/assurance-trace", label: "Application trace", icon: Graph },
          { to: "/assurance-sampling", label: "Accuracy sampling", icon: Scan },
          { to: "/assurance-qualification", label: "Qualification", icon: ShieldCheck },
        ],
      },
      {
        to: "/security-center",
        label: "Security center",
        icon: ShieldCheck,
        children: [
          { to: "/security-center", label: "Posture", icon: ShieldCheck },
          // the bank's own controls sit with the posture they contribute to: one screen
          // reads this estate, the other reads the controls that produced it
          { to: "/security-controls", label: "Control estate", icon: PlugsConnected },
          // the trail sits beside the controls it records; a section that grows a
          // row per page stops being a tree (Layout.navigation keeps that floor)
          { to: "/audit", label: "Audit trail", icon: ListChecks },
        ],
      },
    ],
  },
  {
    title: "Administration",
    items: [
      { to: "/system-health", label: "System health", icon: Pulse },
      { to: "/settings", label: "Settings & org", icon: GearSix },
      { to: "/identity", label: "Users & teams", icon: UsersThree },
      { to: "/integrations", label: "Integrations & API", icon: PlugsConnected },
    ],
  },
];

/** Every route the sidebar renders as a link, in tree order — the nav tests and search.
 *
 * A group row is a disclosure, not a destination: its own ``to`` only marks the group active
 * when you are on that page, which is why the parent's page also appears as a child. Counting
 * both would report the same route twice and hide a genuine duplicate behind the noise.
 */
export function navRoutes(sections: NavSection[] = PRIMARY_SECTIONS): string[] {
  return sections.flatMap((section) =>
    section.items.flatMap((item) =>
      item.children?.length ? item.children.map((child) => child.to) : [item.to],
    ),
  );
}

// The old preference name described a "classic" sidebar; the layout is now sectioned and
// groupable, so the collapse flag keeps its name (a returning operator's choice survives)
// while the open/closed state of sections and groups is stored beside it.
const NAV_STATE_KEY = "zelnx-nav-open";

function readNavState(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(NAV_STATE_KEY);
    const parsed = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed === "object" ? (parsed as Record<string, boolean>) : {};
  } catch { return {}; }
}

function writeNavState(state: Record<string, boolean>) {
  try { localStorage.setItem(NAV_STATE_KEY, JSON.stringify(state)); } catch { /* ignore */ }
}

function sameRoute(candidate: string, route: string): boolean {
  if (candidate === route) return true;
  // "/" and "" are the dashboard, not a page of their own
  return candidate === "/command-center" && (route === "/" || route === "");
}

function itemActive(item: NavItem, route: string): boolean {
  if (sameRoute(item.to, route)) return true;
  return (item.children || []).some((child) => sameRoute(child.to, route));
}

// Reset the prior estate-tree collapse preference once so the restored classic
// navigation is visible on first load; subsequent choices use this key.
const SIDEBAR_PREF_KEY = "zelnx-classic-sidebar-collapsed";

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
    try { return localStorage.getItem(SIDEBAR_PREF_KEY) === "true"; } catch { return false; }
  });
  // Which section and which group are open. The route decides by default — the section you
  // are in and the group holding the current page are open — and a click overrides that for
  // as long as the operator's choice is stored (a route change does not undo it).
  const [navOpen, setNavOpen] = useState<Record<string, boolean>>(() => readNavState());
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
      try { localStorage.setItem(SIDEBAR_PREF_KEY, String(next)); } catch { /* ignore */ }
      return next;
    });
  };

  const toggleNav = (key: string, fallback: boolean) => {
    setNavOpen((prev) => {
      const next = { ...prev, [key]: !(prev[key] ?? fallback) };
      writeNavState(next);
      return next;
    });
  };

  // FormKit handles the sidebar's dynamic height when groups and labels
  // appear/disappear; motion handles the shell's spatial collapse. Both are
  // opt-in and preserve the browser's reduced-motion choice.
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
    if (!hasSession()) { setAbac(null); return; }
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
          {PRIMARY_SECTIONS.map((group) => {
            const sectionKey = `section:${group.title}`;
            // a section is open when the route is inside it, unless the operator said otherwise
            const sectionHasRoute = group.items.some((item) => itemActive(item, route));
            const sectionOpen = navOpen[sectionKey] ?? sectionHasRoute;
            return (
              <React.Fragment key={group.title}>
                {isCollapsed ? (
                  <div className="nav-label" aria-hidden="true">{group.title}</div>
                ) : (
                  <button
                    type="button"
                    className={`nav-label nav-section${sectionOpen ? " open" : ""}`}
                    onClick={() => toggleNav(sectionKey, sectionHasRoute)}
                    aria-expanded={sectionOpen}
                    aria-controls={`nav-${group.title}`}
                  >
                    <span>{group.title}</span>
                    <IconCaretDown className="nav-caret" size={ICON_SM} />
                  </button>
                )}
                <div id={`nav-${group.title}`} className="nav-items" hidden={!sectionOpen && !isCollapsed}>
                  {group.items.map((item) => {
                    const active = itemActive(item, route);
                    const children = item.children || [];
                    if (!children.length) {
                      return (
                        <Link key={item.to}
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
                        </Link>
                      );
                    }
                    const groupKey = `group:${group.title}:${item.label}`;
                    const groupOpen = navOpen[groupKey] ?? active;
                    return (
                      <React.Fragment key={groupKey}>
                        <button
                          type="button"
                          className={`nav nav-group ${active ? "active" : ""}`}
                          title={item.label}
                          aria-expanded={isCollapsed ? undefined : groupOpen}
                          aria-controls={`nav-group-${groupKey}`}
                          onClick={() => {
                            // a group is a disclosure, not a page: in the collapsed rail it
                            // expands the sidebar so its contents can be read
                            if (isCollapsed) { setIsCollapsed(false); try { localStorage.setItem(SIDEBAR_PREF_KEY, "false"); } catch { /* ignore */ } }
                            toggleNav(groupKey, active);
                          }}
                        >
                          <span className="nav-icon" aria-hidden="true">
                            <item.icon size={18} weight={active ? "fill" : "regular"} />
                          </span>
                          <span className="nav-text">{item.label}</span>
                          <span className="nav-count" aria-hidden="true">{children.length}</span>
                          <IconCaretDown className="nav-caret" size={ICON_SM} />
                        </button>
                        <div id={`nav-group-${groupKey}`} className="nav-sub" hidden={!groupOpen}>
                          {children.map((child) => {
                            const childActive = sameRoute(child.to, route);
                            return (
                              <Link key={child.to}
                                to={child.to}
                                className={`nav ${childActive ? "active" : ""}`}
                                aria-current={childActive ? "page" : undefined}
                              >
                                <span className="nav-icon" aria-hidden="true">
                                  <child.icon size={16} weight={childActive ? "fill" : "regular"} />
                                </span>
                                <span className="nav-text">{child.label}</span>
                              </Link>
                            );
                          })}
                        </div>
                      </React.Fragment>
                    );
                  })}
                </div>
              </React.Fragment>
            );
          })}
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

          {hasSession() ? (
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

        <div>{children}</div>
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
