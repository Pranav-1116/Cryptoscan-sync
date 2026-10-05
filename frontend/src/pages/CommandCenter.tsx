import React, { useEffect, useState } from "react";
import { Panel, Badge, Bar, Kpi, Feed, PageHead, Code } from "../components/ui.jsx";
import { apiScope, apiStatsSummary, apiDeliveries, isBackendLive, apiLiveScanStatus, apiLiveAlerts, apiLiveScanRun, apiLiveBom, apiLiveDrift, ApiResult, LiveBadge, LiveScanStatus, LiveAlertsResponse } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent, useRealtimeRefresh, RealtimeChip } from "../lib/realtime.js";
import { useLive } from "../lib/useLive.js";
import { ICON_SM, IconRunning, StatusMark } from "../components/icons";

export default function CommandCenter() {
  // Live domain counts straight from the control plane (no static asset lists).
  const liveInventory = useLive<{ counts?: Record<string, number> }>("/api/v1/live-scan/inventory", {});
  const liveAgents = useLive<{ agents?: any[] }>("/api/v1/control/agents", { agents: [] });
  const recentEvents = useLive<{ events?: any[] }>("/api/v1/events/recent", { events: [] });
  const g = {
    // every value defaults to zero/empty — populated only by live data
    pqcReadyPct: 0, hybridReadyPct: 0, migrationRequiredPct: 0, risks: 0,
    activeScanners: 0, totalScanners: 0, eventsPerSec: 0, agentsHealthy: 0, agentsTotal: 0,
    scannerHealthPct: 0, evidenceHealthPct: 0, cbomVersion: 0, hbomVersion: 0,
    liveChanges24h: 0, criticalFindings: 0, highFindings: 0, pqcExposurePct: 0, migrationProgressPct: 0,
    totalAssets: 0, cryptoAssets: 0, quantumVulnerable: 0, activeDrift: 0,
  };
  const [firstScanBusy, setFirstScanBusy] = useState(false);
  const [firstScanMsg, setFirstScanMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const runFirstScan = async () => {
    setFirstScanBusy(true);
    setFirstScanMsg(null);
    const r = await apiLiveScanRun({ scanners: ["hardware", "runtime"] });
    setFirstScanBusy(false);
    if (r.ok) {
      setFirstScanMsg({ ok: true, text: "scan started — inventory populates in a few seconds" });
      setTimeout(() => { liveInventory.reload(); void liveScan.run(); }, 6000);
    } else {
      setFirstScanMsg({ ok: false, text: r.error ?? "scan failed to start" });
    }
  };
  const [backend, setBackend] = useState<boolean | null>(null);
  const [scope, setScope] = useState<ApiResult<Record<string, unknown>>>({ source: "offline", data: null });
  const rt = useRealtime();

  useEffect(() => {
    void isBackendLive().then(setBackend);
    void apiScope().then(setScope);
  }, []);

  // Live operational counts straight from the platform database (polled).
  const liveStats = usePollingApi(apiStatsSummary, 15000);
  const liveDeliveries = usePollingApi(apiDeliveries, 20000);
  // Realtime scanner execution (hardware/runtime/network run server-side).
  const liveScan = usePollingApi(apiLiveScanStatus, 5000);
  const lsx = (liveScan.data ?? null) as LiveScanStatus | null;
  // a completed cycle may arrive directly (live_scan.completed) or federated
  // from another API worker via the DB tailer (monitor.live_scan_completed).
  const lastScanEvent = rt.events.find((e) =>
    e.type === "live_scan.completed" || e.type === "monitor.live_scan_completed");
  const liveAlerts = usePollingApi(apiLiveAlerts, 6000);
  const liveBom = usePollingApi(apiLiveBom, 12000);
  const liveDrift = usePollingApi(apiLiveDrift, 9000);
  useRealtimeRefresh(liveStats.run, liveDeliveries.run, liveScan.run, liveAlerts.run, liveBom.run, liveDrift.run);
  const alx = (liveAlerts.data ?? null) as LiveAlertsResponse | null;
  const bomCounts = (liveBom.data as any)?.cbom?.counts ?? {};
  const activeDrift = Number((liveDrift.data as any)?.change_count ?? 0);
  const ls = (liveStats.data ?? {}) as Record<string, any>;
  const dStats = ((liveDeliveries.data as Record<string, unknown> | null)?.stats ?? {}) as Record<string, number>;
  const inventoryObserved = !liveInventory.loading && !liveInventory.error;
  const statsObserved = liveStats.source === "live";
  const agentsObserved = !liveAgents.loading && !liveAgents.error;
  const bomObserved = liveBom.source === "live";
  const driftObserved = liveDrift.source === "live";

  // Derive every dashboard KPI from live endpoints (zero until real data exists).
  const cov = (ls.coverage ?? {}) as Record<string, number>;
  const agents = liveAgents.data.agents ?? [];
  g.totalScanners = ls.total_scans ?? 0;
  g.activeScanners = ls.total_scans ?? 0;
  g.agentsTotal = agents.length;
  g.agentsHealthy = agents.filter((a: any) => a.status === "HEALTHY" || a.healthy).length;
  g.scannerHealthPct = g.agentsTotal ? Math.round((g.agentsHealthy / g.agentsTotal) * 100) : 0;
  g.risks = ls.total_findings ?? 0;
  g.criticalFindings = (ls.open_drift ?? {}).CRITICAL ?? 0;
  g.highFindings = (ls.open_drift ?? {}).HIGH ?? 0;
  g.liveChanges24h = (recentEvents.data.events ?? []).length;
  g.evidenceHealthPct = ls.total_findings ? Math.round(((ls.compliant ?? 0) / Math.max(1, ls.total_findings)) * 100) : 0;
  g.cbomVersion = cov.with_cbom ?? 0;
  g.pqcReadyPct = Math.round(cov.coverage_pct ?? 0);
  g.migrationProgressPct = Math.round(cov.coverage_pct ?? 0);
  const invCounts = liveInventory.data.counts ?? {};
  const networkAssets = Array(invCounts.network_assets ?? 0).fill(null);
  const cloudResources = []; // cloud counts come from /cloud accounts (read-only)
  const vendors = [];
  const hardware = Array(invCounts.hardware_devices ?? 0).fill(null);
  // Total / crypto asset counts derived from the live inventory counts.
  g.totalAssets = Object.entries(invCounts)
    .filter(([k]) => ["hardware_devices", "network_assets", "cloud_resources"].includes(k))
    .reduce((n, [, v]) => n + Number(v ?? 0), 0);
  g.cryptoAssets = (invCounts.libraries ?? 0) + (invCounts.certificates ?? 0) + (invCounts.processes ?? 0);
  // quantum-vulnerable components come straight from the deterministic CBOM classifier;
  // active drift is the count of live changes since the last baseline.
  g.quantumVulnerable = Number(bomCounts.quantum_vulnerable ?? 0);
  g.activeDrift = activeDrift;
  const hasInventory = g.totalAssets > 0 || g.cryptoAssets > 0;
  const scannerObserved = liveScan.source === "live" && Boolean(lsx?.last_run_at);
  const scannerPosture = !scannerObserved
    ? { tone: "amber", label: "SCANNER STATUS UNKNOWN — NO COMPLETED OBSERVATION" }
    : Number(lsx?.failed_count ?? 0) > 0
      ? { tone: "red", label: "SCANNERS DEGRADED — FAILURES OBSERVED" }
      : { tone: "green", label: "ALL SCANNERS NOMINAL" };
  const pqcObserved = liveStats.source === "live" && liveBom.source === "live" && typeof cov.coverage_pct === "number";
  const riskCounts: Record<string, number> = { CRITICAL: g.criticalFindings, HIGH: g.highFindings, MEDIUM: (ls.open_drift ?? {}).MEDIUM ?? 0, LOW: (ls.open_drift ?? {}).INFO ?? 0 };
  const events = recentEvents.data.events ?? [];

  /* realtime feed — shows only events streamed live from the control plane */
  const liveFeed = rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 6).map((e) => ({
    t: new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false }),
    tag: e.type.replace(/^(platform|monitor)\./, "").replace(/_/g, " ").slice(0, 22).toUpperCase(),
    text: String(e.payload?.detail || e.payload?.target || ""),
    severity: severityOf(e.type),
  }));
  const feed = liveFeed.length
    ? liveFeed
    : events.slice(0, 6).map((e: any) => ({
        t: new Date(e.ts ?? e.timestamp).toLocaleTimeString("en-GB", { hour12: false }),
        tag: String(e.type ?? "").replace(/^(platform|monitor)\./, "").slice(0, 22).toUpperCase(),
        text: String(e.payload?.detail || e.payload?.target || ""),
        severity: severityOf(e.type),
      }));

  return (
    <>
      <PageHead
        crumb="command center"
        title="Command center"
        sub="Global security state across network, cloud, vendor, hardware and cryptography"
        right={
          <>
            <RealtimeChip />
            {backend === null && <Badge>PROBING BACKEND…</Badge>}
            {backend === true && <Badge tone="green"><span className="dot" /> CONTROL PLANE: LIVE</Badge>}
            {backend === false && <Badge tone="amber"><span className="dot" /> CONTROL PLANE: OFFLINE — SIGN IN TO LOAD LIVE DATA</Badge>}
            <Badge tone={scannerPosture.tone}><span className="dot" /> {scannerPosture.label}</Badge>
            <Badge tone={pqcObserved ? "violet" : "amber"}>
              {pqcObserved ? `PQC ${g.pqcReadyPct}% OBSERVED` : "PQC STATUS UNKNOWN — NO LIVE EVIDENCE"}
            </Badge>
          </>
        }
      />

      {scope.data && (
        <Panel title="Platform scope (live manifest)" sub={scope.source === "live" ? "GET /api/v1/platform/scope — served by the control plane" : "no live data yet — connect the control plane"} className="mt">
          <Code>{JSON.stringify(scope.data, null, 2)}</Code>
        </Panel>
      )}

      {liveStats.source === "live" && (
        <Panel title="Live platform state" sub="GET /api/v1/stats/summary + control-plane delivery — counts from the running database" className="mt">
          <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
            <LiveStat label="scans" value={Number(ls.total_scans ?? 0)} />
            <LiveStat label="findings" value={Number(ls.total_findings ?? 0)} />
            <LiveStat label="compliant" value={Number(ls.compliant ?? 0)} tone="green" />
            <LiveStat label="non-compliant" value={Number(ls.non_compliant ?? 0)} tone="red" />
            <LiveStat label="webhooks delivered" value={Number(dStats.delivered ?? 0)} tone="green" />
            <LiveStat label="webhooks failed" value={Number(dStats.failed ?? 0)} tone="red" />
            <LiveBadge source="live" label="LIVE DB" />
          </div>
        </Panel>
      )}

      {/* realtime scanner execution — real hardware/runtime/network scans */}
      {liveScan.source === "live" && lsx && (
        <Panel
          title="Realtime scanners"
          sub={lsx.running
            ? "scan cycle running now — results stream over SSE"
            : lsx.last_run_at
              ? `last cycle ${new Date(lsx.last_run_at).toLocaleString()}${lsx.periodic.enabled ? ` · loop every ${lsx.periodic.interval_seconds}s` : ""}`
              : "no scan cycle has run yet — start one in Operations → Realtime scanners"}
          className="mt"
        >
          <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
            <LiveStat label="cycle" value={lsx.running ? "RUNNING" : "idle"} tone={lsx.running ? "cyan" : ""} />
            <LiveStat label="scanners OK" value={Number(lsx.ok_count ?? 0)} tone={scannerObserved ? "green" : "amber"} />
            <LiveStat label="scanners failed" value={Number(lsx.failed_count ?? 0)} tone={scannerObserved && lsx.failed_count ? "red" : "amber"} />
            {alx && (Number(alx.counts?.CRITICAL ?? 0) + Number(alx.counts?.HIGH ?? 0)) > 0 && (
              <a href="#/alerts" style={{ textDecoration: "none" }}>
                <LiveStat label="critical/high alerts" value={Number(alx.counts?.CRITICAL ?? 0) + Number(alx.counts?.HIGH ?? 0)} tone="red" />
              </a>
            )}
            {(lsx.scanners?.hardware?.summary as Record<string, unknown> | undefined)?.tpm_present === true && (
              <LiveStat label="TPM" value="2.0 present" tone="green" />
            )}
            {lsx.scanners?.runtime?.summary && (
              <LiveStat
                label="crypto processes"
                value={Number((lsx.scanners.runtime.summary as Record<string, unknown>).crypto_processes ?? 0)}
              />
            )}
            {lsx.scanners?.runtime?.summary && (
              <LiveStat
                label="risky libraries"
                value={Number((lsx.scanners.runtime.summary as Record<string, unknown>).risky_libraries ?? 0)}
                tone={Number((lsx.scanners.runtime.summary as Record<string, unknown>).risky_libraries ?? 0) ? "red" : "green"}
              />
            )}
            {lastScanEvent && rt.connected && <LiveBadge source="live" label="SSE LIVE" />}
          </div>
        </Panel>
      )}

      {/* zero-state quick start — one real local scan, no fabricated data */}
      {backend === true && !hasInventory && (
        <Panel title="Start here — run your first real scan" sub="deterministic local hardware + runtime inventory; results land in the live CBOM" className="mt">
          <div className="row" style={{ gap: 14, alignItems: "center", flexWrap: "wrap" }}>
            <button className="btn primary" onClick={() => void runFirstScan()} disabled={firstScanBusy} style={{ fontSize: 14, padding: "11px 20px" }}>
              {firstScanBusy ? "Scanning this host…" : <><IconRunning className="ico" size={ICON_SM} /> Scan this host now</>}
            </button>
            <a href="#/onboarding" className="btn sm" style={{ textDecoration: "none" }}>Set up environments & scope →</a>
            <span className="dim" style={{ fontSize: 12.5 }}>
              Hardware (CPU crypto caps, TPM/HSM, RNG) and runtime (crypto libraries, processes, certificates) are read locally — no targets, no credentials, nothing simulated.
            </span>
          </div>
          {firstScanMsg && <div style={{ marginTop: 10 }}><Badge tone={firstScanMsg.ok ? "green" : "red"}>{firstScanMsg.ok ? <StatusMark ok muted /> : null}{firstScanMsg.text}</Badge></div>}
        </Panel>
      )}

      {/* Five-question KPI strip — what do I have / what changed / what is risky /
          what is quantum-vulnerable / what needs action. All live, zero until real. */}
      <div className="kpi-strip">
        <HeroKpi label="Total assets" q="what do I have?" value={inventoryObserved ? g.totalAssets : "—"} tone={inventoryObserved ? "cyan" : "amber"} to="#/assets" suffix={inventoryObserved ? undefined : "unknown"} />
        <HeroKpi label="Crypto assets" q="what do I have?" value={inventoryObserved ? g.cryptoAssets : "—"} tone={inventoryObserved ? "blue" : "amber"} to="#/cbom" suffix={inventoryObserved ? undefined : "unknown"} />
        <HeroKpi label="Quantum-vulnerable" q="what is quantum-vulnerable?" value={bomObserved ? g.quantumVulnerable : "—"} tone={!bomObserved ? "amber" : g.quantumVulnerable ? "red" : "amber"} to="#/pqc" suffix={bomObserved ? undefined : "unknown"} />
        <HeroKpi label="Critical" q="what is risky?" value={statsObserved ? g.criticalFindings : "—"} tone={!statsObserved ? "amber" : g.criticalFindings ? "red" : "amber"} to="#/risk" suffix={statsObserved ? undefined : "unknown"} />
        <HeroKpi label="Active drift" q="what changed?" value={driftObserved ? g.activeDrift : "—"} tone={!driftObserved ? "amber" : g.activeDrift ? "orange" : "amber"} to="#/drift" suffix={driftObserved ? undefined : "unknown"} />
        <HeroKpi label="Scanners" q="what needs action?" value={agentsObserved ? `${g.agentsHealthy}/${g.agentsTotal}` : "—"} tone={!agentsObserved ? "amber" : g.agentsTotal && g.agentsHealthy === g.agentsTotal ? "green" : "amber"} to="#/scanners" suffix={!agentsObserved ? "unknown" : g.agentsTotal ? (g.agentsHealthy === g.agentsTotal ? "healthy" : "degraded") : "no observations"} />
      </div>

      {/* readiness bars */}
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="PQC readiness" sub="executive posture">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {[
              { k: "PQC ready", v: g.pqcReadyPct, tone: "green", observed: bomObserved },
              { k: "Hybrid ready", v: g.hybridReadyPct, tone: "violet", observed: bomObserved },
              { k: "Migration required", v: g.migrationRequiredPct, tone: "red", observed: bomObserved },
            ].map((r) => (
              <div key={r.k}>
                <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                  <span>{r.k}</span><span className="mono" style={!r.observed ? { color: "var(--amber)" } : undefined}>{r.observed ? `${r.v}%` : "UNKNOWN"}</span>
                </div>
                {r.observed ? <Bar value={r.v / 100} tone={r.tone} /> : <div className="dim" style={{ fontSize: 11 }}>No live evidence returned</div>}
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Live environment" sub="five domains, one graph — populated by discovery">
          <div style={{ display: "flex", flexDirection: "column", gap: 8, fontFamily: "var(--mono)", fontSize: 13 }}>
            <div className="spread"><span>Network</span><Badge tone={!inventoryObserved ? "amber" : networkAssets.length ? "green" : ""}>{inventoryObserved ? `${networkAssets.length} assets` : "UNKNOWN"}</Badge></div>
            <div className="spread"><span>Cloud</span><Badge tone="amber">UNKNOWN — no live cloud projection</Badge></div>
            <div className="spread"><span>Vendor</span><Badge tone="amber">UNKNOWN — no live vendor projection</Badge></div>
            <div className="spread"><span>Hardware</span><Badge tone={!inventoryObserved ? "amber" : hardware.length ? "green" : ""}>{inventoryObserved ? `${hardware.length} devices` : "UNKNOWN"}</Badge></div>
            <div className="spread"><span>Cryptography</span><Badge tone={!statsObserved ? "amber" : g.risks > 0 ? "red" : ""}>{!statsObserved ? "UNKNOWN" : g.risks > 0 ? "FINDINGS" : "no findings yet"}</Badge></div>
          </div>
        </Panel>
      </div>

      {/* kpi strip */}
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Panel title="Telemetry" sub="24h window">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="active scanners" v={statsObserved ? `${g.activeScanners}/${g.totalScanners}` : "UNKNOWN"} tone={statsObserved ? "cyan" : "amber"} />
            <Kpi k="scanner health" v={agentsObserved ? `${g.scannerHealthPct}%` : "UNKNOWN"} tone={agentsObserved ? "cyan" : "amber"} />
            <Kpi k="agents" v={agentsObserved ? `${g.agentsHealthy}/${g.agentsTotal}` : "UNKNOWN"} tone={agentsObserved ? "cyan" : "amber"} />
            <Kpi k="events / sec" v={statsObserved ? g.eventsPerSec : "UNKNOWN"} tone={statsObserved ? "cyan" : "amber"} />
          </div>
        </Panel>
        <Panel title="Findings" sub="evidence-linked">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="critical findings" v={statsObserved ? g.criticalFindings : "UNKNOWN"} tone={statsObserved && g.criticalFindings ? "red" : "amber"} />
            <Kpi k="high findings" v={statsObserved ? g.highFindings : "UNKNOWN"} tone={statsObserved && g.highFindings ? "red" : "amber"} />
            <Kpi k="live changes (24h)" v={statsObserved ? g.liveChanges24h : "UNKNOWN"} tone={statsObserved ? "amber" : "amber"} />
            <Kpi k="evidence health" v={statsObserved ? `${g.evidenceHealthPct}%` : "UNKNOWN"} tone={statsObserved ? "amber" : "amber"} />
          </div>
        </Panel>
        <Panel title="Migration" sub="post-quantum program">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="PQC exposure" v={bomObserved ? `${g.pqcExposurePct}%` : "UNKNOWN"} tone={bomObserved && g.pqcExposurePct ? "red" : "amber"} />
            <Kpi k="migration progress" v={bomObserved ? `${g.migrationProgressPct}%` : "UNKNOWN"} tone={bomObserved ? "cyan" : "amber"} />
            <Kpi k="CBOM status" v={bomObserved ? "OBSERVED" : "UNKNOWN"} tone={bomObserved ? "cyan" : "amber"} />
            <Kpi k="HBOM status" v="UNKNOWN — no HBOM evidence" tone="amber" />
          </div>
        </Panel>
        <Panel title="Risk distribution" sub="portfolio">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Object.entries(riskCounts).map(([lv, n]) => (
              <div key={lv} className="spread">
                <Badge>{lv}</Badge>
                <span className="mono" style={!statsObserved ? { color: "var(--amber)" } : undefined}>{statsObserved ? n : "UNKNOWN"}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* live change alerts */}
      <div className="grid cols-2">
        <Panel title="Live changes" sub={rt.connected ? "realtime SSE stream" : "no live events yet"}>
          <Feed items={feed} />
        </Panel>
        <Panel title="Drift watch" sub={rt.connected ? "baseline vs live — updated by stream events" : "baseline vs live (no baseline yet)"}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { k: "Network", added: 0, removed: 0, detail: "no baseline yet" },
              { k: "Cloud", added: 0, removed: 0, detail: "no baseline yet" },
              { k: "Cryptography", added: 0, removed: 0, detail: "no baseline yet" },
              { k: "Firmware", added: 0, removed: 0, detail: "no baseline yet" },
            ].map((d) => (
              <div className="spread" key={d.k} style={{ fontSize: 13 }}>
                <span>{d.k}</span>
                <span className="dim">{d.detail}</span>
                <Badge tone="amber">UNKNOWN — no baseline</Badge>
              </div>
            ))}
            {rt.connected && rt.events.filter((e) => e.type.includes("drift")).length > 0 && (
              <div className="mono" style={{ fontSize: 11.5, color: "var(--amber)", borderTop: "1px solid var(--line)", paddingTop: 8 }}>
                ⟳ {rt.events.filter((e) => e.type.includes("drift")).length} drift event(s) in the live stream
              </div>
            )}
          </div>
        </Panel>
      </div>
    </>
  );
}

function HeroKpi({ label, q, value, tone, to, suffix }: { label: string; q: string; value: number | string; tone: string; to: string; suffix?: string }) {
  const color = tone === "red" ? "var(--red)" : tone === "orange" ? "var(--orange)" : tone === "amber" ? "var(--amber)"
    : tone === "green" ? "var(--green)" : tone === "blue" ? "var(--blue)" : "var(--cyan)";
  return (
    <a href={to} className="hero-kpi" style={{ textDecoration: "none", borderTopColor: color }}>
      <span className="hero-q">{q}</span>
      <span className="hero-label">{label}</span>
      <span className="hero-v" style={{ color }}>{typeof value === "number" ? value.toLocaleString() : value}</span>
      <span className="hero-suffix" style={{ color }}>● {suffix ?? (Number(value) === 0 ? "none yet" : "live")}</span>
    </a>
  );
}

function LiveStat({ label, value, tone }: { label: string; value: number | string; tone?: "green" | "red" | "cyan" | "amber" | "" }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", minWidth: 120 }}>
      <span className="mono" style={{ fontSize: 28, fontWeight: 700, color: tone === "red" ? "var(--red)" : tone === "green" ? "var(--green)" : tone === "amber" ? "var(--amber)" : tone === "cyan" ? "var(--cyan))" : "var(--text)" }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </span>
      <span className="dim" style={{ fontSize: 11.5, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</span>
    </div>
  );
}
