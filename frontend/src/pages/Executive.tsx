import React from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring, PageHead } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtimeRefresh, RealtimeChip } from "../lib/realtime.js";
import { ICON_SM, IconTrendDown, IconTrendFlat, IconTrendUp } from "../components/icons";
import {
  apiStatsSummary, apiLiveBom, apiLiveDrift, apiLiveAlerts,
  LiveBomResponse, LiveAlertsResponse,
} from "../lib/api.js";

/* Executive view — a board/CISO one-screen summary. Every figure is derived
   from live endpoints (stats summary, scan-derived CBOM, drift, alerts). There
   are no targets, no illustrative numbers, and no generated narrative: until scans
   run, the board sees honest zeros and a "no data" posture. The posture score
   is a deterministic, transparent function of coverage, quantum exposure and
   open drift — shown with its inputs, not asserted. */

function pct(n: number, d: number): number {
  return d > 0 ? Math.round((n / d) * 100) : 0;
}

export default function Executive() {
  const statsRes = usePollingApi(apiStatsSummary, 15000);
  const bomRes = usePollingApi(apiLiveBom, 12000);
  const driftRes = usePollingApi(apiLiveDrift, 10000);
  const alertsRes = usePollingApi(apiLiveAlerts, 8000);
  // Refresh immediately when the platform changes (SSE) instead of on the poll.
  useRealtimeRefresh(statsRes.run, bomRes.run, driftRes.run, alertsRes.run);
  const live = statsRes.source === "live";

  const s = (statsRes.data ?? {}) as Record<string, any>;
  const coverage = (s.coverage ?? {}) as Record<string, any>;
  const openDrift = (s.open_drift ?? {}) as Record<string, number>;
  const bomCounts = ((bomRes.data as LiveBomResponse | null)?.cbom?.counts ?? {}) as Record<string, number>;
  const driftChangeCount = Number((driftRes.data as any)?.change_count ?? 0);
  const alerts = ((alertsRes.data as LiveAlertsResponse | null)?.counts ?? {}) as Record<string, number>;

  const totalFindings = Number(s.total_findings ?? 0);
  const compliant = Number(s.compliant ?? 0);
  const coveragePct = Math.round(Number(coverage.coverage_pct ?? 0));
  const quantumVuln = Number(bomCounts.quantum_vulnerable ?? 0);
  const cryptoComps = Number(bomCounts.total ?? 0);
  const critHigh = Number(openDrift.CRITICAL ?? 0) + Number(openDrift.HIGH ?? 0);

  const hasData = Number(s.total_scans ?? 0) > 0 || cryptoComps > 0;

  // Deterministic posture score (0–100), transparent inputs:
  //  + coverage share (40), + crypto that is NOT quantum-vulnerable (30),
  //  + findings that are compliant (20), − open critical/high drift (10 cap).
  const safeCryptoShare = cryptoComps ? (cryptoComps - quantumVuln) / cryptoComps : 0;
  const compliantShare = totalFindings ? compliant / totalFindings : 0;
  const driftPenalty = Math.min(10, critHigh * 2);
  const posture = hasData
    ? Math.max(0, Math.min(100,
        Math.round(coveragePct * 0.4 + safeCryptoShare * 100 * 0.3 + compliantShare * 100 * 0.2) - driftPenalty))
    : 0;
  const postureTone = !hasData ? "slate" : posture >= 80 ? "green" : posture >= 55 ? "amber" : "red";
  const postureLabel = !hasData ? "NO DATA" : posture >= 80 ? "STRONG" : posture >= 55 ? "WATCH" : "AT RISK";

  type Priority = { tone: "red" | "amber" | "cyan"; label: string; n: number; to: string };
  const allPriorities: Priority[] = [
    { tone: "red", label: "Quantum-vulnerable crypto components", n: quantumVuln, to: "/pqc" },
    { tone: "red", label: "Open critical/high drift", n: critHigh, to: "/drift" },
    { tone: "amber", label: "Crypto changes since baseline", n: driftChangeCount, to: "/crypto-changes" },
    { tone: "amber", label: "Critical + high alerts", n: Number(alerts.CRITICAL ?? 0) + Number(alerts.HIGH ?? 0), to: "/alerts" },
    { tone: "cyan", label: "Assets with no CBOM / coverage gap", n: Number(coverage.unknown_crypto ?? 0), to: "/cbom" },
  ];
  const priorities: Priority[] = allPriorities.filter((p) => p.n > 0).sort((a, b) => b.n - a.n);

  return (
    <>
      <PageHead
        crumb="overview / executive"
        title="Executive view"
        sub="Board-level cryptographic risk posture — deterministic, derived from live scans; no targets or illustrative figures"
        right={<div style={{ display: "flex", gap: 8, alignItems: "center" }}><RealtimeChip /><Badge tone={live ? "green" : "slate"}><span className="dot" /> {live ? "live data" : "backend offline"}</Badge></div>}
      />

      {/* headline posture */}
      <Panel
        title="Overall crypto posture"
        sub="deterministic score from coverage (40) · quantum-safe crypto (30) · compliant findings (20) − critical drift (10)"
      >
        {!hasData ? (
          <div className="dim" style={{ fontSize: 13, padding: "18px 4px" }}>
            No scans yet — posture cannot be scored. Run discovery and a live scan; this board reflects
            real measured state and never shows an illustrative number.
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: 30, flexWrap: "wrap" }}>
            <Ring pct={posture / 100} label={`${posture}`} sub={postureLabel} tone={postureTone === "slate" ? "cyan" : postureTone} />
            <div style={{ flex: 1, minWidth: 260, display: "flex", flexDirection: "column", gap: 12 }}>
              {[
                { k: `Estate coverage (${coveragePct}%)`, v: coveragePct, tone: "cyan", to: "/assurance-coverage" },
                { k: `Quantum-safe crypto share (${pct(cryptoComps - quantumVuln, cryptoComps)}%)`, v: pct(cryptoComps - quantumVuln, cryptoComps), tone: quantumVuln ? "amber" : "green", to: "/pqc" },
                { k: `Compliant findings (${pct(compliant, totalFindings)}%)`, v: pct(compliant, totalFindings), tone: "green", to: "/findings" },
              ].map((r) => (
                <div key={r.k}>
                  <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                    <Link to={r.to} style={{ color: "inherit" }}>{r.k}</Link><span className="mono">{r.v}%</span>
                  </div>
                  <Bar value={r.v / 100} tone={r.tone} />
                </div>
              ))}
            </div>
          </div>
        )}
      </Panel>

      {/* board KPI strip */}
      <div className="grid cols-5" style={{ margin: "16px 0" }}>
        {[
          { k: "crypto components", v: cryptoComps, to: "/crypto-assets" },
          { k: "quantum vulnerable", v: quantumVuln, tone: quantumVuln ? "red" : "", to: "/pqc" },
          { k: "total findings", v: totalFindings, to: "/findings" },
          { k: "estate coverage", v: `${coveragePct}%`, to: "/assurance-coverage" },
          { k: "crypto drift changes", v: driftChangeCount, tone: driftChangeCount ? "amber" : "", to: "/crypto-changes" },
        ].map((kpi) => (
          <Link to={kpi.to} className="kpi" key={kpi.k} style={{ textDecoration: "none", color: "inherit" }}>
            <span className="k">{kpi.k}</span>
            <span className="v" style={kpi.tone ? { color: `var(--${kpi.tone})` } : undefined}>{kpi.v}</span>
          </Link>
        ))}
      </div>

      <div className="grid cols-2">
        <Panel title="Board priority queue" sub="real, measured items requiring attention — ranked, links to the source surface">
          {priorities.length === 0 ? (
            <div className="dim" style={{ fontSize: 13 }}>
              {hasData ? "No open priority items — zero quantum-vulnerable components, drift or high alerts." : "Populates after scans surface risk."}
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {priorities.map((p) => (
                <Link key={p.label} to={p.to} className="scan-row" style={{ textDecoration: "none" }}>
                  <div className="s-ico">
                    <Badge tone={p.tone}>{p.tone === "red" ? <IconTrendUp size={ICON_SM} /> : p.tone === "amber" ? <IconTrendFlat size={ICON_SM} /> : <IconTrendDown size={ICON_SM} />}</Badge>
                  </div>
                  <div className="s-meta"><div className="s-name">{p.label}</div></div>
                  <div className="s-right"><span className="s-elapsed" style={{ fontSize: 16, fontWeight: 700, color: `var(--${p.tone})` }}>{p.n}</span></div>
                </Link>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Coverage status" sub="systems by scan/current state (deterministic coverage engine)">
          {(() => {
            const counts = (coverage.counts ?? {}) as Record<string, number>;
            const order: Array<[string, string]> = [
              ["CURRENT", "green"], ["STALE", "amber"], ["FAILED", "red"],
              ["NEVER_SCANNED", "slate"], ["NO_TARGET", "slate"],
            ];
            const total = Object.values(counts).reduce((a, b) => a + Number(b || 0), 0);
            if (!total) return <div className="dim" style={{ fontSize: 13 }}>{coverage.message || "Register and scan systems to see coverage."}</div>;
            return (
              <>
                <div className="verdict-bar" style={{ marginBottom: 6 }}>
                  {order.map(([state, col]) => Number(counts[state] || 0) > 0 && (
                    <i key={state} style={{
                      width: `${(Number(counts[state]) / total) * 100}%`,
                      background: { green: "var(--green)", amber: "var(--amber)", red: "var(--red)", slate: "var(--slate)" }[col],
                    }} title={`${state}: ${counts[state]}`} />
                  ))}
                </div>
                <div className="verdict-legend">
                  {order.map(([state, col]) => (
                    <Link key={state} to="/live-asset-intelligence"
                          style={{ color: "inherit", textDecoration: "none" }}
                          title={`the ${state.toLowerCase()} systems are the records behind this count`}>
                      <span className="sw" style={{
                        background: { green: "var(--green)", amber: "var(--amber)", red: "var(--red)", slate: "var(--slate)" }[col],
                      }} />{state.toLowerCase()} {Number(counts[state] || 0)}
                    </Link>
                  ))}
                </div>
              </>
            );
          })()}
          <div className="mono" data-testid="coverage-foot" style={{ fontSize: 12, color: "var(--dim)", marginTop: 16 }}>
            systems: <Link to="/live-asset-intelligence"><b style={{ color: "var(--text)" }}>{Number(coverage.systems ?? 0)}</b></Link> · with CBOM:{" "}
            <Link to="/cbom"><b style={{ color: "var(--text)" }}>{Number(coverage.with_cbom ?? 0)}</b></Link> · unknown crypto:{" "}
            <Link to="/cbom"><b style={{ color: "var(--text)" }}>{Number(coverage.unknown_crypto ?? 0)}</b></Link>
          </div>
        </Panel>
      </div>
    </>
  );
}
