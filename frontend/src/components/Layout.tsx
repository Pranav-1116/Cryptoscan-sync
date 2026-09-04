import React, { useEffect, useState } from "react";
import { useLiveTicker, useAlertToasts, Toasts } from "./Live.jsx";
import SearchOverlay from "./Search.jsx";
import { getToken, setToken, getUserName, apiMyGrants, apiStatsSummary } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";

const NAV = [
  { section: "Command center", items: [
    { to: "/", label: "Command center", icon: "◎" },
    { to: "/onboarding", label: "Onboarding", icon: "➤" },
    { to: "/env", label: "Live environment", icon: "◉" },
    { to: "/organization", label: "Organization", icon: "◫" },
    { to: "/sectors", label: "Sector profiles", icon: "⛨" },
  ]},
  { section: "Discovery", items: [
    { to: "/network", label: "Network", icon: "◈" },
    { to: "/cloud", label: "Cloud", icon: "☁" },
    { to: "/vendor", label: "Vendor", icon: "▤" },
    { to: "/hardware", label: "Hardware", icon: "⌬" },
    { to: "/crypto", label: "Cryptography", icon: "⚿" },
  ]},
  { section: "Inventory", items: [
    { to: "/assets", label: "Assets", icon: "▣" },
    { to: "/crypto-assets", label: "Crypto assets", icon: "⚿" },
    { to: "/certificates", label: "Certificates", icon: "⊞" },
    { to: "/libraries", label: "Crypto libraries", icon: "▤" },
    { to: "/protocols", label: "Protocols", icon: "⇄" },
  ]},
  { section: "Boms", items: [
    { to: "/cbom", label: "CBOM", icon: "⬡" },
    { to: "/hbom", label: "HBOM", icon: "⬢" },
    { to: "/graph", label: "Dependency graph", icon: "⬟" },
  ]},
  { section: "Post-quantum", items: [
    { to: "/pqc", label: "PQC readiness", icon: "◬" },
    { to: "/pqc-map", label: "PQC migration map", icon: "⇉" },
    { to: "/agility", label: "Crypto agility", icon: "◔" },
    { to: "/risk", label: "Risk", icon: "⚠" },
    { to: "/drift", label: "Drift", icon: "⇄" },
    { to: "/alerts", label: "Alerts", icon: "▲" },
  ]},
  { section: "Live", items: [
    { to: "/crypto-changes", label: "Live crypto changes", icon: "≋" },
    { to: "/timeline", label: "Global timeline", icon: "◷" },
  ]},
  { section: "Plan", items: [
    { to: "/whatif", label: "What-if simulator", icon: "▶" },
    { to: "/migration", label: "Migration planning", icon: "⇉" },
  ]},
  { section: "Govern", items: [
    { to: "/compliance", label: "Compliance", icon: "✓" },
    { to: "/governance", label: "Governance", icon: "⚖" },
    { to: "/evidence", label: "Evidence", icon: "⛨" },
  ]},
  { section: "Operate", items: [
    { to: "/scanners", label: "Scanners", icon: "⌖" },
    { to: "/notifications", label: "Notifications", icon: "✉" },
    { to: "/reports", label: "Reports", icon: "▤" },
    { to: "/integrations", label: "Integrations", icon: "⇌" },
    { to: "/admin", label: "Administration", icon: "⚙" },
  ]},
  { section: "Platform (P2)", items: [
    { to: "/platform", label: "P2 console", icon: "⬢" },
  ]},
  { section: "Quality", items: [
    { to: "/accuracy", label: "Accuracy", icon: "◔" },
  ]},
];

export default function Layout({ route, children }: { route: string; children: React.ReactNode }) {
  const [showSearch, setShowSearch] = useState(false);
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
    <div className="shell">
      <aside className="sidebar">
        <a href="#/" className="logo" style={{ display: "flex", alignItems: "center", gap: 11, fontWeight: 700, fontSize: 18, letterSpacing: "0.02em", margin: "2px 8px 10px" }}>
          <span className="mark" style={{ width: 32, height: 32, borderRadius: 7, display: "grid", placeItems: "center", background: "var(--grad)", color: "#fff", fontFamily: "var(--sans)", fontWeight: 800 }}>Z</span>
          <span>ZELNX<span style={{ color: "var(--faint)", fontWeight: 500, fontSize: 11, marginLeft: 8, letterSpacing: "0.14em" }}>CRYPTO INTELLIGENCE</span></span>
        </a>
        {NAV.map((group) => (
          <React.Fragment key={group.section}>
            <div className="nav-label">{group.section}</div>
            {group.items.map((item) => (
              <a key={item.to} href={`#${item.to}`} className={`nav ${route === item.to ? "active" : ""}`}>
                <span style={{ width: 18, textAlign: "center" }}>{item.icon}</span>
                {item.label}
              </a>
            ))}
          </React.Fragment>
        ))}
        <div style={{ marginTop: 20 }}>
          <div className="demobanner" style={{
            color: ticker.backend ? "var(--green)" : "var(--amber)",
            borderColor: ticker.backend ? "rgba(47,184,119,0.35)" : undefined,
            background: ticker.backend ? "rgba(47,184,119,0.07)" : undefined,
          }}>
            <span className="dot" style={{ background: ticker.backend ? "var(--green)" : "var(--amber)" }} />
            <span>
              {ticker.backend === null
                ? "connecting to platform…"
                : ticker.backend
                  ? "live platform · deterministic engine · no AI inference"
                  : "offline · sign in to connect to the live platform"}
            </span>
          </div>
          <div style={{ marginTop: 10, padding: "0 8px", fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)", lineHeight: 1.7 }}>
            v1.0 · policy-as-code · hash-chained audit<br />fail-closed access control
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="livehead">
          <span className="live-dot" style={ticker.connected ? undefined : { background: "var(--amber)", boxShadow: "0 0 12px var(--amber)" }} />
          <span className="item"><b>{ticker.connected ? "LIVE" : "IDLE"}</b></span>
          <span className="item">last event <b>{ticker.ago === null ? "—" : `${ticker.ago}s`}</b> ago</span>
          <span className="item">events/sec <b>{ticker.eps || "—"}</b></span>
          {ticker.connected ? (
            <span className="item">stream subscribers <b>{ticker.subscribers}</b></span>
          ) : (
            <span className="item">agents <b>{Number(st?.agents_healthy ?? 0)}/{Number(st?.agents_total ?? 0)}</b> healthy</span>
          )}
          <span className="item">scanners <b>{Number(st?.active_scanners ?? 0)}/{Number(st?.total_scanners ?? 0)}</b></span>
          <span className="item">scans <b>{Number(st?.total_scans ?? 0)}</b></span>
          <span className="item">findings <b>{Number(st?.total_findings ?? 0)}</b></span>
          {abac && (
            <span className="item" title="ABAC scope policy — Region → Business Unit → Environment → Asset">
              ABAC <b style={{ color: abac.enforced ? "var(--green)" : "var(--amber)" }}>
                {abac.enforced ? `ENFORCED · ${abac.grants} grants` : "off"}
              </b>
            </span>
          )}
          <div className="searchbox" onClick={() => setShowSearch(true)}>
            <span>⌕</span> Search entire environment…
            <span style={{ marginLeft: "auto", fontSize: 10, border: "1px solid var(--line-strong)", borderRadius: 4, padding: "1px 6px" }}>esc</span>
          </div>
          {getToken() ? (
            <button
              className="btn sm"
              title="sign out"
              onClick={() => { setToken(null); window.location.hash = "#/"; }}
            >
              {getUserName() || "user"} · sign out
            </button>
          ) : (
            <a href="#/login" className="btn sm">sign in</a>
          )}
        </div>
        {children}
      </main>

      {showSearch && <SearchOverlay onClose={() => setShowSearch(false)} />}
      <Toasts toasts={toasts} />
    </div>
  );
}
