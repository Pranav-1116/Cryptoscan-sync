import React, { useEffect, useState } from "react";
import { useLiveTicker, useAlertToasts, Toasts } from "./Live.jsx";
import SearchOverlay from "./Search.jsx";
import { getToken, setToken, getUserName, apiMyGrants, apiStatsSummary } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";

const NAV = [
  { sectionKey: "nav.commandCenter", items: [
    { to: "/", labelKey: "nav.commandCenter", icon: "◎" },
    { to: "/role-home", labelKey: "nav.roleWorkspace", icon: "◐" },
    { to: "/onboarding", labelKey: "nav.onboarding", icon: "➤" },
    { to: "/env", labelKey: "nav.liveEnvironment", icon: "◉" },
    { to: "/organization", labelKey: "nav.organization", icon: "◫" },
    { to: "/sectors", labelKey: "nav.sectorProfiles", icon: "⛨" },
  ]},
  { sectionKey: "nav.discovery", items: [
    { to: "/network", labelKey: "nav.network", icon: "◈" },
    { to: "/cloud", labelKey: "nav.cloud", icon: "☁" },
    { to: "/vendor", labelKey: "nav.vendor", icon: "▤" },
    { to: "/hardware", labelKey: "nav.hardware", icon: "⌬" },
    { to: "/crypto", labelKey: "nav.cryptography", icon: "⚿" },
  ]},
  { sectionKey: "nav.inventory", items: [
    { to: "/catalog", labelKey: "nav.catalogs", icon: "☷" },
    { to: "/assets", labelKey: "nav.assets", icon: "▣" },
    { to: "/crypto-assets", labelKey: "nav.cryptoAssets", icon: "⚿" },
    { to: "/certificates", labelKey: "nav.certificates", icon: "⊞" },
    { to: "/crypto-assurance", labelKey: "nav.cryptoAssurance", icon: "⚿" },
    { to: "/devsecops", labelKey: "nav.devsecops", icon: "⛀" },
    { to: "/libraries", labelKey: "nav.cryptoLibraries", icon: "▤" },
    { to: "/protocols", labelKey: "nav.protocols", icon: "⇄" },
  ]},
  { sectionKey: "nav.boms", items: [
    { to: "/cbom", labelKey: "nav.cbom", icon: "⬡" },
    { to: "/hbom", labelKey: "nav.hbom", icon: "⬢" },
    { to: "/graph", labelKey: "nav.dependencyGraph", icon: "⬟" },
  ]},
  { sectionKey: "nav.postQuantum", items: [
    { to: "/pqc", labelKey: "nav.pqcReadiness", icon: "◬" },
    { to: "/pqc-map", labelKey: "nav.pqcMigrationMap", icon: "⇉" },
    { to: "/agility", labelKey: "nav.cryptoAgility", icon: "◔" },
    { to: "/risk", labelKey: "nav.risk", icon: "⚠" },
    { to: "/drift", labelKey: "nav.drift", icon: "⇄" },
    { to: "/alerts", labelKey: "nav.alerts", icon: "▲" },
  ]},
  { sectionKey: "nav.liveSection", items: [
    { to: "/crypto-changes", labelKey: "nav.liveCryptoChanges", icon: "≋" },
    { to: "/timeline", labelKey: "nav.globalTimeline", icon: "◷" },
  ]},
  { sectionKey: "nav.plan", items: [
    { to: "/whatif", labelKey: "nav.whatIf", icon: "▶" },
    { to: "/migration", labelKey: "nav.migrationPlanning", icon: "⇉" },
  ]},
  { sectionKey: "nav.govern", items: [
    { to: "/compliance", labelKey: "nav.compliance", icon: "✓" },
    { to: "/governance", labelKey: "nav.governance", icon: "⚖" },
    { to: "/resilience", labelKey: "nav.resilience", icon: "⛨" },
<<<<<<< HEAD
=======
    { to: "/trust", labelKey: "nav.trustKeys", icon: "⚿" },
>>>>>>> 757bb4b (feat(trust,notifications): Trust & Keys console + persisted notification routing)
    { to: "/evidence", labelKey: "nav.evidence", icon: "⛨" },
  ]},
  { sectionKey: "nav.operate", items: [
    { to: "/scanners", labelKey: "nav.scanners", icon: "⌖" },
    { to: "/live-scanners", labelKey: "nav.realtimeScanners", icon: "◉" },
    { to: "/runtime", labelKey: "nav.runtimeHosts", icon: "⧉" },
    { to: "/notifications", labelKey: "nav.notifications", icon: "✉" },
    { to: "/reports", labelKey: "nav.reports", icon: "▤" },
    { to: "/integrations", labelKey: "nav.integrations", icon: "⇌" },
    { to: "/identity", labelKey: "nav.identity", icon: "⛃" },
    { to: "/admin", labelKey: "nav.administration", icon: "⚙" },
  ]},
  { sectionKey: "nav.platformP2", items: [
    { to: "/platform", labelKey: "nav.platformP2", icon: "⬢" },
  ]},
  { sectionKey: "nav.quality", items: [
    { to: "/accuracy", labelKey: "nav.accuracy", icon: "◔" },
  ]},
];

export default function Layout({ route, children }: { route: string; children: React.ReactNode }) {
  const { t, dir } = useI18n();
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
            <div className="nav-label">{t(group.sectionKey)}</div>
            {group.items.map((item) => (
              <a key={item.to} href={`#${item.to}`} className={`nav ${route === item.to ? "active" : ""}`}>
                <span style={{ width: 18, textAlign: "center" }}>{item.icon}</span>
                {t(item.labelKey)}
              </a>
            ))}
          </React.Fragment>
        ))}
        <div style={{ marginTop: 20, padding: "0 8px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: dir === "rtl" ? "flex-end" : "flex-start", gap: 8, marginBottom: 10 }}>
            <span style={{ fontSize: 11, color: "var(--faint)", letterSpacing: "0.08em" }}>{t("lang.label").toUpperCase()}</span>
            <LanguageSwitcher />
          </div>
          <div className="demobanner" style={{
            color: ticker.backend ? "var(--green)" : "var(--amber)",
            borderColor: ticker.backend ? "rgba(47,184,119,0.35)" : undefined,
            background: ticker.backend ? "rgba(47,184,119,0.07)" : undefined,
          }}>
            <span className="dot" style={{ background: ticker.backend ? "var(--green)" : "var(--amber)" }} />
            <span>
              {ticker.backend === null
                ? t("app.banner.connecting")
                : ticker.backend
                  ? t("app.banner.live")
                  : t("app.banner.offline")}
            </span>
          </div>
          <div style={{ marginTop: 10, padding: "0 8px", fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)", lineHeight: 1.7 }}>
            v1.0 · {t("app.footer")}<br />{t("app.footer2")}
          </div>
        </div>
      </aside>

      <main className="main">
        <div className="livehead">
          <span className="live-dot" style={ticker.connected ? undefined : { background: "var(--amber)", boxShadow: "0 0 12px var(--amber)" }} />
          <span className="item"><b>{ticker.connected ? t("common.live") : t("common.idle")}</b></span>
          <span className="item">{t("head.lastEvent")} <b>{ticker.ago === null ? "—" : `${ticker.ago}s`}</b> {t("head.ago")}</span>
          <span className="item">{t("head.eventsPerSec")} <b>{ticker.eps || "—"}</b></span>
          {ticker.connected ? (
            <span className="item">{t("head.streamSubs")} <b>{ticker.subscribers}</b></span>
          ) : (
            <span className="item">{t("head.agents")} <b>{Number(st?.agents_healthy ?? 0)}/{Number(st?.agents_total ?? 0)}</b> {t("head.healthy")}</span>
          )}
          <span className="item">{t("head.scanners")} <b>{Number(st?.active_scanners ?? 0)}/{Number(st?.total_scanners ?? 0)}</b></span>
          <span className="item">{t("head.scans")} <b>{Number(st?.total_scans ?? 0)}</b></span>
          <span className="item">{t("head.findings")} <b>{Number(st?.total_findings ?? 0)}</b></span>
          {abac && (
            <span className="item" title={t("head.abac")}>
              ABAC <b style={{ color: abac.enforced ? "var(--green)" : "var(--amber)" }}>
                {abac.enforced ? `${abac.grants} grants` : "off"}
              </b>
            </span>
          )}
          <div className="searchbox" onClick={() => setShowSearch(true)}>
            <span>⌕</span> {t("common.search")}
            <span style={{ marginLeft: "auto", fontSize: 10, border: "1px solid var(--line-strong)", borderRadius: 4, padding: "1px 6px" }}>esc</span>
          </div>
          {getToken() ? (
            <button
              className="btn sm"
              title={t("common.signOut")}
              onClick={() => { setToken(null); window.location.hash = "#/"; }}
            >
              {getUserName() || "user"} · {t("common.signOut")}
            </button>
          ) : (
            <a href="#/login" className="btn sm">{t("common.signIn")}</a>
          )}
        </div>
        {children}
      </main>

      {showSearch && <SearchOverlay onClose={() => setShowSearch(false)} />}
      <Toasts toasts={toasts} />
    </div>
  );
}
