import { Link } from "react-router-dom";
import React, { useEffect, useState } from "react";
import { Panel, Badge, Kpi, Feed, PageHead, Code } from "../components/ui.jsx";
import {
  apiScope, apiStatsSummary, apiDeliveries, isBackendLive, apiLiveInventory,
  apiLiveScanStatus, apiLiveAlerts, apiLiveScanRun, apiLiveBom, apiLiveDrift,
  ApiResult, LiveBadge,
} from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent, useRealtimeRefresh, RealtimeChip } from "../lib/realtime.js";
import { useLive } from "../lib/useLive.js";
import { ICON_SM, IconRunning, StatusMark } from "../components/icons";

// Missing fields are not zero. An API response (or a successful request with no
// snapshot yet) cannot establish the count of an unobserved estate.
function count(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
function observed(value: number | null): number | string {
  return value ?? "Not available";
}
// A zero from an empty projection only means "no records" if its scanner has
// actually reported successfully. A positive row count is itself an observation.
function projected(value: unknown, sourceSeen: boolean): number | string {
  const n = count(value);
  return n === null ? "Not available" : n > 0 || sourceSeen ? n : "Not observed";
}
function when(value: string | null | undefined): string {
  if (!value) return "time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "time unavailable" : date.toLocaleString();
}

export default function CommandCenter() {
  const recentEvents = useLive<{ events?: Array<{ ts?: string; timestamp?: string; type?: string; payload?: { detail?: string; target?: string } }> }>("/api/v1/events/recent", { events: [] });
  const [firstScanBusy, setFirstScanBusy] = useState(false);
  const [firstScanMsg, setFirstScanMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [backend, setBackend] = useState<boolean | null>(null);
  const [scope, setScope] = useState<ApiResult<Record<string, unknown>>>({ source: "offline", data: null });
  const rt = useRealtime();

  useEffect(() => {
    void isBackendLive().then(setBackend);
    void apiScope().then(setScope);
  }, []);

  const liveStats = usePollingApi(apiStatsSummary, 15000);
  const liveDeliveries = usePollingApi(apiDeliveries, 20000);
  const liveInventory = usePollingApi(apiLiveInventory, 12000);
  const liveScan = usePollingApi(apiLiveScanStatus, 5000);
  const liveAlerts = usePollingApi(apiLiveAlerts, 6000);
  const liveBom = usePollingApi(apiLiveBom, 12000);
  const liveDrift = usePollingApi(apiLiveDrift, 9000);
  useRealtimeRefresh(liveStats.run, liveDeliveries.run, liveInventory.run, liveScan.run, liveAlerts.run, liveBom.run, liveDrift.run);

  const runFirstScan = async () => {
    setFirstScanBusy(true);
    setFirstScanMsg(null);
    const r = await apiLiveScanRun({ scanners: ["hardware", "runtime"] });
    setFirstScanBusy(false);
    if (r.source === "live" && r.data) {
      setFirstScanMsg({ ok: true, text: "scan started — inventory populates after the cycle completes" });
      setTimeout(() => { void liveInventory.run(); void liveScan.run(); }, 6000);
    } else {
      setFirstScanMsg({ ok: false, text: r.error ?? "scan failed to start" });
    }
  };

  const stats = liveStats.source === "live" ? liveStats.data : null;
  const inventory = liveInventory.source === "live" ? liveInventory.data : null;
  const snapshotObserved = Boolean(inventory?.generated_at);
  const bom = liveBom.source === "live" ? liveBom.data : null;
  const bomObserved = Boolean(bom?.generated_at);
  const drift = liveDrift.source === "live" ? liveDrift.data : null;
  const driftObserved = drift?.baseline === true;
  const scan = liveScan.source === "live" ? liveScan.data : null;
  const scanObserved = Boolean(scan?.last_run_at);
  const sourceSeen = {
    hardware_devices: scan?.scanners?.hardware?.ok === true,
    network_assets: scan?.scanners?.network?.ok === true,
    libraries: scan?.scanners?.runtime?.ok === true,
    certificates: scan?.scanners?.runtime?.ok === true || scan?.scanners?.network?.ok === true,
    processes: scan?.scanners?.runtime?.ok === true,
  };
  const alerts = liveAlerts.source === "live" ? liveAlerts.data : null;
  const deliveries = liveDeliveries.source === "live" ? liveDeliveries.data : null;
  const coverage = (stats?.coverage ?? {}) as Record<string, unknown>;
  const openDrift = (stats?.open_drift ?? {}) as Record<string, unknown>;
  const criticalDrift = stats ? count(openDrift.CRITICAL) : null;
  const changes = driftObserved ? count(drift?.change_count) : null;
  const flaggedComponents = bomObserved ? count(bom?.cbom?.counts?.quantum_vulnerable) : null;
  const failed = scanObserved ? count(scan?.failed_count) : null;
  const scannerPosture = !scanObserved
    ? { tone: "amber", label: "LAST SCAN CYCLE: NOT OBSERVED" }
    : failed === null
      ? { tone: "amber", label: "LAST SCAN CYCLE: RESULT UNAVAILABLE" }
      : failed > 0
        ? { tone: "red", label: `LAST SCAN CYCLE: ${failed} FAILED` }
        : { tone: "amber", label: "LAST SCAN CYCLE: 0 FAILED (BLOCKED/UNCONFIGURED EXCLUDED)" };
  const lastScanEvent = rt.events.find((e) =>
    e.type === "live_scan.completed" || e.type === "monitor.live_scan_completed");
  const events = !recentEvents.loading && !recentEvents.error ? (recentEvents.data.events ?? []) : [];
  const liveFeed = rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 6).map((e) => ({
    t: when(e.ts),
    tag: e.type.replace(/^(platform|monitor)\./, "").replace(/_/g, " ").slice(0, 22).toUpperCase(),
    text: String(e.payload?.detail || e.payload?.target || ""),
    severity: severityOf(e.type),
  }));
  const feed = liveFeed.length ? liveFeed : events.slice(0, 6).map((e) => ({
    t: when(e.ts ?? e.timestamp),
    tag: String(e.type ?? "").replace(/^(platform|monitor)\./, "").slice(0, 22).toUpperCase(),
    text: String(e.payload?.detail || e.payload?.target || ""),
    severity: severityOf(e.type ?? ""),
  }));

  return (
    <>
      <PageHead
        crumb="command center"
        title="Command center"
        sub="Latest available control-plane observations; each source has its own scope and freshness"
        right={<>
          <RealtimeChip />
          {backend === null && <Badge>PROBING BACKEND…</Badge>}
          {backend === true && <Badge tone="green"><span className="dot" /> CONTROL PLANE: LIVE</Badge>}
          {backend === false && <Badge tone="amber"><span className="dot" /> CONTROL PLANE: OFFLINE — SIGN IN TO LOAD LIVE DATA</Badge>}
          <Badge tone={scannerPosture.tone}><span className="dot" /> {scannerPosture.label}</Badge>
          <Badge tone="amber">PQC READINESS: NOT MEASURED</Badge>
        </>}
      />

      {scope.data && (
        <Panel title="Platform scope (live manifest)" sub={scope.source === "live" ? "Live scope manifest from the control plane" : "no live data yet — connect the control plane"} className="mt">
          <Code>{JSON.stringify(scope.data, null, 2)}</Code>
        </Panel>
      )}

      {stats && (
        <Panel title="Platform records" sub="Persisted scans and findings, all time; delivery counts are tracked separately" className="mt">
          <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
            <LiveStat label="scan records" value={observed(count(stats.total_scans))} />
            <LiveStat label="evidence findings" value={observed(count(stats.total_findings))} />
            <LiveStat label="PASS findings" value={observed(count(stats.compliant))} />
            <LiveStat label="FAIL findings" value={observed(count(stats.non_compliant))} />
            {deliveries && <>
              <LiveStat label="webhooks delivered" value={observed(count(deliveries.stats?.delivered))} />
              <LiveStat label="webhooks failed" value={observed(count(deliveries.stats?.failed))} />
            </>}
            <LiveBadge source="live" label="LIVE DB" />
          </div>
        </Panel>
      )}

      {scan && (
        <Panel
          title="Realtime scanners"
          sub={scan.running
            ? `scan cycle running now${scanObserved ? ` · last completed cycle ${when(scan.last_run_at)}` : " · no prior completed cycle"}`
            : scanObserved
              ? `last cycle ${when(scan.last_run_at)}${scan.periodic?.enabled ? ` · loop every ${scan.periodic.interval_seconds}s` : ""}`
              : "no completed scan cycle observed — start one in Operations → Realtime scanners"}
          className="mt"
        >
          <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
            <LiveStat label="cycle" value={scan.running ? "RUNNING" : "idle"} />
            <LiveStat label="last cycle scanners OK" value={scanObserved ? observed(count(scan.ok_count)) : "Not observed"} />
            <LiveStat label="last cycle scanners failed" value={scanObserved ? observed(failed) : "Not observed"} />
            {alerts && count(alerts.counts?.CRITICAL) !== null && count(alerts.counts?.HIGH) !== null &&
              (alerts.counts.CRITICAL + alerts.counts.HIGH) > 0 && (
                <Link to="/alerts" style={{ textDecoration: "none" }}>
                  <LiveStat label="live-scan critical/high alerts" value={alerts.counts.CRITICAL + alerts.counts.HIGH} />
                </Link>
              )}
            {scan.scanners?.hardware?.summary?.tpm_present === true && <LiveStat label="last reported TPM" value="present" />}
            {count(scan.scanners?.runtime?.summary?.crypto_processes) !== null &&
              <LiveStat label="last reported crypto processes" value={count(scan.scanners.runtime.summary?.crypto_processes)!} />}
            {count(scan.scanners?.runtime?.summary?.risky_libraries) !== null &&
              <LiveStat label="scanner-reported risky libraries" value={count(scan.scanners.runtime.summary?.risky_libraries)!} />}
            {lastScanEvent && rt.connected && <LiveBadge source="live" label="SSE LIVE" />}
          </div>
          <span className="dim" style={{ fontSize: 11.5 }}>Last-cycle failures exclude blocked and unconfigured scanners; these counts do not measure fleet health.</span>
        </Panel>
      )}

      {backend === true && inventory && !snapshotObserved && (
        <Panel title="Start here — run your first real scan" sub="Local hardware + runtime observation; no inventory snapshot is available yet" className="mt">
          <div className="row" style={{ gap: 14, alignItems: "center", flexWrap: "wrap" }}>
            <button className="btn primary" onClick={() => void runFirstScan()} disabled={firstScanBusy} style={{ fontSize: 14, padding: "11px 20px" }}>
              {firstScanBusy ? "Scanning this host…" : <><IconRunning className="ico" size={ICON_SM} /> Scan this host now</>}
            </button>
            <Link to="/onboarding" className="btn sm" style={{ textDecoration: "none" }}>Set up environments & scope →</Link>
            <span className="dim" style={{ fontSize: 12.5 }}>This scan observes the local host; it does not establish estate-wide coverage.</span>
          </div>
          {firstScanMsg && <div style={{ marginTop: 10 }}><Badge tone={firstScanMsg.ok ? "green" : "red"}>{firstScanMsg.ok ? <StatusMark ok muted /> : null}{firstScanMsg.text}</Badge></div>}
        </Panel>
      )}

      <div className="kpi-strip">
        <HeroKpi label="Host hardware" q="latest local snapshot" value={snapshotObserved ? projected(inventory?.counts?.hardware_devices, sourceSeen.hardware_devices) : "Not observed"} tone="cyan" to="/assets" suffix={snapshotObserved ? `snapshot ${when(inventory?.generated_at)}` : "no inventory snapshot"} />
        <HeroKpi label="Crypto assets" q="estate-wide inventory" value="Not measured" tone="amber" to="/cbom" suffix="needs a deduplicated asset contract" />
        <HeroKpi label="CBOM components" q="latest local CBOM" value={bomObserved ? observed(count(bom?.cbom?.counts?.total)) : "Not observed"} tone="blue" to="/pqc" suffix={bomObserved ? `snapshot ${when(bom?.generated_at)}` : "no CBOM snapshot"} />
        <HeroKpi label="Open critical drift" q="persisted drift events" value={observed(criticalDrift)} tone={criticalDrift ? "red" : "blue"} to="/drift" suffix="all time · OPEN only" />
        <HeroKpi label="Changes vs prior scan" q="latest comparison only" value={driftObserved ? observed(changes) : "Not observed"} tone={changes ? "orange" : "blue"} to="/drift" suffix={driftObserved ? `compared ${when(drift?.ts)}` : "no comparison baseline"} />
        <HeroKpi label="Scan cycle" q="scanner execution" value={scan ? (scan.running ? "Running" : "Idle") : "Not observed"} tone="cyan" to="/scanners" suffix={scanObserved ? `last cycle ${when(scan?.last_run_at)}` : "no completed cycle"} />
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="PQC posture" sub="Readiness and migration require scoped assessment, not inventory coverage">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="PQC readiness" v="Not measured" />
            <Kpi k="Hybrid readiness" v="Not measured" />
            <Kpi k="Migration required" v="Not measured" />
            <Kpi k="CBOM components flagged vulnerable" v={observed(flaggedComponents)} />
            <span className="dim" style={{ fontSize: 11.5 }}>Flagged count is limited to classified components in the latest local CBOM; unknowns are not safe or ready.</span>
          </div>
        </Panel>
        <Panel title="Local inventory" sub={snapshotObserved ? `Local inventory · snapshot ${when(inventory?.generated_at)}` : "No completed local inventory snapshot observed"}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(["hardware_devices", "network_assets", "libraries", "certificates", "processes"] as const).map((key) => (
              <Kpi key={key} k={key.replace(/_/g, " ")} v={snapshotObserved ? projected(inventory?.counts?.[key], sourceSeen[key]) : "Not observed"} />
            ))}
            <span className="dim" style={{ fontSize: 11.5 }}>Source: most recent local scanner output. These categories can overlap and are not a total asset count.</span>
          </div>
        </Panel>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Panel title="Telemetry" sub="Last completed scanner cycle; no 24h window">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="cycle running" v={scan ? (scan.running ? "Yes" : "No") : "Not observed"} />
            <Kpi k="scanners OK (last cycle)" v={scanObserved ? observed(count(scan?.ok_count)) : "Not observed"} />
            <Kpi k="scanners failed (last cycle)" v={scanObserved ? observed(failed) : "Not observed"} />
            <Kpi k="events / sec" v="Not measured" />
          </div>
        </Panel>
        <Panel title="Evidence findings" sub="All persisted scans; no time window">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="total findings" v={stats ? observed(count(stats.total_findings)) : "Not observed"} />
            <Kpi k="PASS findings" v={stats ? observed(count(stats.compliant)) : "Not observed"} />
            <Kpi k="FAIL findings" v={stats ? observed(count(stats.non_compliant)) : "Not observed"} />
            <Kpi k="evidence integrity" v="Not measured" />
          </div>
        </Panel>
        <Panel title="Migration" sub="No measured program or readiness denominator">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="PQC exposure" v="Not measured" />
            <Kpi k="migration progress" v="Not measured" />
            <Kpi k="systems with CBOM" v={stats ? observed(count(coverage.with_cbom)) : "Not observed"} />
            <Kpi k="HBOM snapshot" v={bomObserved ? "Available" : "Not observed"} />
            <span className="dim" style={{ fontSize: 11.5 }}>Systems with CBOM includes current and stale coverage; it is not PQC readiness.</span>
          </div>
        </Panel>
        <Panel title="Open drift" sub="Persisted OPEN drift events by severity; all time">
          <dl style={{ margin: 0, display: "flex", flexDirection: "column", gap: 8 }}>
            {(["CRITICAL", "HIGH", "MEDIUM", "INFO"] as const).map((severity) => (
              <div key={severity} className="spread">
                <dt>{severity}</dt><dd className="mono" style={{ margin: 0 }}>{stats ? observed(count(openDrift[severity])) : "Not observed"}</dd>
              </div>
            ))}
          </dl>
        </Panel>
      </div>

      <div className="grid cols-2">
        <Panel title="Recent events" sub={rt.connected ? "realtime SSE stream; recent sample only" : "recent endpoint sample; no 24h or rate guarantee"}>
          {feed.length ? <Feed items={feed} /> : <span className="dim">{recentEvents.error ? "Recent events unavailable" : "No recent events returned"}</span>}
        </Panel>
        <Panel title="Latest inventory comparison" sub={driftObserved ? `Previous ${when(drift?.previous_ts)} · current ${when(drift?.ts)}` : "Comparison requires two inventory snapshots"}>
          {driftObserved ? <>
            <Kpi k="changes between snapshots" v={observed(changes)} />
            {Array.isArray(drift?.changes) && drift.changes.length > 0 && (
              <ul style={{ marginBottom: 0, paddingLeft: 20 }}>
                {drift.changes.slice(0, 5).map((change, index) => (
                  <li key={index} style={{ fontSize: 12.5 }}>{change.scanner}: {change.title}</li>
                ))}
              </ul>
            )}
          </> : <span className="dim">{drift ? "No comparison baseline yet" : "Comparison unavailable"}</span>}
        </Panel>
      </div>
    </>
  );
}

function HeroKpi({ label, q, value, tone, to, suffix }: { label: string; q: string; value: number | string; tone: string; to: string; suffix: string }) {
  const color = tone === "red" ? "var(--red)" : tone === "orange" ? "var(--orange)" : tone === "amber" ? "var(--amber)"
    : tone === "green" ? "var(--green)" : tone === "blue" ? "var(--blue)" : "var(--cyan)";
  return (
    <Link to={to} className="hero-kpi" style={{ textDecoration: "none", borderTopColor: color }}>
      <span className="hero-q">{q}</span>
      <span className="hero-label">{label}</span>
      <span className="hero-v" style={{ color: "var(--text)", fontSize: typeof value === "number" ? undefined : 18, overflowWrap: "anywhere" }}>{typeof value === "number" ? value.toLocaleString() : value}</span>
      <span className="hero-suffix" style={{ color: "var(--dim)", overflowWrap: "anywhere" }}>{suffix}</span>
    </Link>
  );
}

function LiveStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", minWidth: 120 }}>
      <span className="mono" style={{ fontSize: 28, fontWeight: 700, color: "var(--text)" }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </span>
      <span className="dim" style={{ fontSize: 11.5, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</span>
    </div>
  );
}
