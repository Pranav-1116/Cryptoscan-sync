import React, { useState } from "react";
import { useLiveTicker, useAlertToasts, Toasts } from "./Live.jsx";
import SearchOverlay from "./Search.jsx";
import { globalState } from "../data/demo.js";
import { getToken, setToken } from "../lib/api.js";

const NAV = [
  { section: "Command center", items: [
    { to: "/", label: "Command center", icon: "◎" },
    { to: "/env", label: "Live environment", icon: "◉" },
    { to: "/organization", label: "Organization", icon: "◫" },
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
  { section: "Quality", items: [
    { to: "/accuracy", label: "Accuracy", icon: "◔" },
  ]},
];

export default function Layout({ route, children }: { route: string; children: React.ReactNode }) {
  const [showSearch, setShowSearch] = useState(false);
  const ticker = useLiveTicker();
  const toasts = useAlertToasts();

  return (
    <div className="shell">
      <aside className="sidebar">
        <a href="#/" className="logo" style={{ display: "flex", alignItems: "center", gap: 12, fontWeight: 700, fontSize: 19, margin: "0 8px 6px" }}>
          <span className="mark" style={{ width: 34, height: 34, borderRadius: 9, display: "grid", placeItems: "center", background: "var(--grad)", color: "#03121a", fontFamily: "var(--mono)", fontWeight: 700, boxShadow: "0 0 18px rgba(34,211,238,.5)" }}>Z</span>
          ZELNX
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
          <div className="demobanner">
            <span className="dot" />
            <span>demo mode · deterministic data · backend: {ticker.backend === null ? "checking…" : ticker.backend ? "LIVE" : "offline"}</span>
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="livehead">
          <span className="live-dot" style={ticker.connected ? undefined : { background: "var(--amber)", boxShadow: "0 0 12px var(--amber)" }} />
          <span className="item"><b>{ticker.connected ? "LIVE" : "DEMO"}</b></span>
          <span className="item">last event <b>{ticker.ago === null ? "—" : `${ticker.ago}s`}</b> ago</span>
          <span className="item">events/sec <b>{ticker.eps || "—"}</b></span>
          {ticker.connected ? (
            <span className="item">stream subscribers <b>{ticker.subscribers}</b></span>
          ) : (
            <span className="item">agents <b>{globalState.agentsHealthy}/{globalState.agentsTotal}</b> healthy</span>
          )}
          <span className="item">scanners <b>{globalState.activeScanners}/{globalState.totalScanners}</b></span>
          <span className="item">CBOM <b>v{globalState.cbomVersion}</b></span>
          <span className="item">HBOM <b>v{globalState.hbomVersion}</b></span>
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
              admin · sign out
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
