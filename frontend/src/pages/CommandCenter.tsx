import { Link } from "react-router-dom";
import React, { useEffect, useState } from "react";
import { Panel, Badge, Kpi, PageHead } from "../components/ui.jsx";
import {
  apiStatsSummary, apiDeliveries, isBackendLive, apiLiveInventory,
  apiLiveScanStatus, apiLiveAlerts, apiLiveScanRun, apiLiveBom, apiLiveDrift,
  LiveBadge,
} from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent, useRealtimeRefresh, RealtimeChip } from "../lib/realtime.js";
import { useLive } from "../lib/useLive.js";
import { ICON_SM, IconRunning, StatusMark } from "../components/icons";
import { GapBar, HBars, KpiMeter, StackedBar, StateCell, TickStrip, VizEmpty } from "../components/viz";

/* Command center — the control plane's front page.
 *
 * Presentation rule (same as the live monitor): a figure is drawn only when it
 * came back from a read, and a figure that was never measured is drawn as an
 * unmeasured line, not as a zero and not as an empty meter. Every chart here is
 * a rendering of values already in this file's scope — no history is invented,
 * no percentage of a target is computed, and a bar's length is always relative
 * to the largest value in the same group. */

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
const numeric = (value: unknown): number | null => count(value);

const CBOM_LABEL: Record<string, string> = {
  total: "components",
  quantum_vulnerable: "quantum-vulnerable",
  quantum_safe: "quantum-safe",
  classical: "classical only",
  unknown: "unclassified",
};

const QSTATUS_TONE: Record<string, string> = {
  QUANTUM_VULNERABLE: "red",
  MIGRATION_REQUIRED: "red",
  HYBRID_READY: "violet",
  QUANTUM_SAFE: "green",
  PQC_READY: "green",
  UNKNOWN: "slate",
  PQC_UNKNOWN: "slate",
};

export default function CommandCenter() {
  const recentEvents = useLive<{ events?: Array<{ ts?: string; timestamp?: string; type?: string; payload?: { detail?: string; target?: string } }> }>("/api/v1/events/recent", { events: [] });
  const [firstScanBusy, setFirstScanBusy] = useState(false);
  const [firstScanMsg, setFirstScanMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [backend, setBackend] = useState<boolean | null>(null);
  const rt = useRealtime();

  useEffect(() => {
    void isBackendLive().then(setBackend);
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

  // ── measured values that get drawn ──────────────────────────────────
  const findingsPass = stats ? count(stats.compliant) : null;
  const findingsFail = stats ? count(stats.non_compliant) : null;

  const scannerRows = scan
    ? Object.entries(scan.scanners ?? {}).map(([name, s]) => ({
        key: name,
        label: name,
        ok: s?.ok ?? null,
        elapsed: typeof s?.elapsed_s === "number" && Number.isFinite(s.elapsed_s) ? s.elapsed_s : null,
        error: s?.error ?? null,
      }))
    : [];

  const certCenter = snapshotObserved ? inventory?.cert_center : undefined;
  const certRows: Array<{ key: string; label: string; tone: string; value: number }> = certCenter
    ? [
        { key: "expired", label: "expired", value: numeric(certCenter.expired), tone: "red" },
        { key: "expiring30", label: "expiring ≤30d", value: numeric(certCenter.expiring30), tone: "amber" },
        { key: "weak", label: "weak algorithm", value: numeric(certCenter.weak_algorithm), tone: "orange" },
        { key: "unknown", label: "unknown owner", value: numeric(certCenter.unknown_owner), tone: "slate" },
      ].filter((row): row is { key: string; label: string; value: number; tone: string } => row.value !== null)
    : [];

  const cbomCountRows = bomObserved
    ? Object.entries(bom?.cbom?.counts ?? {})
        .map(([key, value]) => ({
          key,
          label: CBOM_LABEL[key] ?? key.replace(/_/g, " "),
          value: numeric(value),
          tone: key === "quantum_vulnerable" ? "red" : key === "quantum_safe" ? "green" : "",
        }))
        .filter((row): row is { key: string; label: string; value: number; tone: string } => row.value !== null)
    : [];

  const cbomStatusSegments = (() => {
    const components = bomObserved ? (bom?.cbom?.components ?? []) : [];
    if (!components.length) return [];
    const tally = new Map<string, number>();
    for (const c of components) {
      const status = (c.quantum_status || "UNCLASSIFIED").toUpperCase();
      tally.set(status, (tally.get(status) ?? 0) + 1);
    }
    return [...tally.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([status, value]) => ({ key: status, label: status.replace(/_/g, " ").toLowerCase(), value, tone: QSTATUS_TONE[status] ?? "slate" }));
  })();

  const driftSeverityRows: Array<{ key: string; label: string; tone: string; value: number }> = [
    { key: "CRITICAL", tone: "red" },
    { key: "HIGH", tone: "orange" },
    { key: "MEDIUM", tone: "amber" },
    { key: "LOW", tone: "green" },
    { key: "INFO", tone: "slate" },
  ]
    .map(({ key, tone }) => ({
      key,
      label: key,
      tone,
      value: driftObserved ? (drift?.changes ?? []).filter((c) => String(c.severity).toUpperCase() === key).length : 0,
    }))
    .filter((row) => row.value > 0);

  const alertRows: Array<{ key: string; label: string; tone: string; value: number }> = alerts
    ? (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const)
        .map((severity) => ({
          key: severity as string,
          label: severity as string,
          value: numeric(alerts.counts?.[severity]) ?? 0,
          tone: severity === "CRITICAL" ? "red" : severity === "HIGH" ? "orange" : severity === "MEDIUM" ? "amber" : "green",
        }))
        .filter((row) => row.value > 0)
    : [];

  const inventoryKeys = ["hardware_devices", "network_assets", "libraries", "certificates", "processes"] as const;
  const inventoryValues = inventoryKeys.map((key) =>
    snapshotObserved ? projected(inventory?.counts?.[key], sourceSeen[key]) : "Not observed");
  const inventoryMax = Math.max(
    1,
    ...inventoryValues.map((v) => (typeof v === "number" ? v : 0)),
  );

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

      {/* ── hero strip: six tiles, each with a state rail ───────────────── */}
      <div className="kpi-strip">
        <HeroKpi label="Host hardware" q="latest local snapshot" value={snapshotObserved ? projected(inventory?.counts?.hardware_devices, sourceSeen.hardware_devices) : "Not observed"} tone="cyan" to="/assets" suffix={snapshotObserved ? `snapshot ${when(inventory?.generated_at)}` : "no inventory snapshot"} />
        <HeroKpi label="Crypto assets" q="estate-wide inventory" value="Not measured" tone="amber" to="/cbom" suffix="needs a deduplicated asset contract" />
        <HeroKpi label="CBOM components" q="latest local CBOM" value={bomObserved ? observed(count(bom?.cbom?.counts?.total)) : "Not observed"} tone="blue" to="/pqc" suffix={bomObserved ? `snapshot ${when(bom?.generated_at)}` : "no CBOM snapshot"} />
        <HeroKpi label="Open critical drift" q="persisted drift events" value={observed(criticalDrift)} tone={criticalDrift ? "red" : "blue"} to="/drift" suffix="all time · OPEN only" />
        <HeroKpi label="Changes vs prior scan" q="latest comparison only" value={driftObserved ? observed(changes) : "Not observed"} tone={changes ? "orange" : "blue"} to="/drift" suffix={driftObserved ? `compared ${when(drift?.ts)}` : "no comparison baseline"} />
        <HeroKpi label="Scan cycle" q="scanner execution" value={scan ? (scan.running ? "Running" : "Idle") : "Not observed"} tone="cyan" to="/scanners" suffix={scanObserved ? `last cycle ${when(scan?.last_run_at)}` : "no completed cycle"} />
      </div>

      {/* ── platform records + findings split ──────────────────────────── */}
      {stats && (
        <Panel title="Platform records" sub="Persisted scans and findings, all time; delivery counts are tracked separately" className="mt">
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10 }}>
            <LiveStat label="scan records" value={observed(count(stats.total_scans))} />
            <LiveStat label="evidence findings" value={observed(count(stats.total_findings))} />
            <LiveStat label="PASS findings" value={observed(findingsPass)} />
            <LiveStat label="FAIL findings" value={observed(findingsFail)} />
            {deliveries && <>
              <LiveStat label="webhooks delivered" value={observed(count(deliveries.stats?.delivered))} />
              <LiveStat label="webhooks failed" value={observed(count(deliveries.stats?.failed))} />
            </>}
          </div>
          <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--line)" }}>
            {findingsPass !== null && findingsFail !== null && findingsPass + findingsFail > 0 ? (
              <StackedBar
                segments={[
                  { key: "pass", label: "PASS", value: findingsPass, tone: "green" },
                  { key: "fail", label: "FAIL", value: findingsFail, tone: "red" },
                ]}
                note={`Split of the ${(findingsPass + findingsFail).toLocaleString()} persisted findings that carry a PASS/FAIL verdict; findings without a verdict are not in this bar.`}
              />
            ) : (
              <VizEmpty
                title="No PASS/FAIL verdict recorded"
                note={findingsPass === null || findingsFail === null ? "The summary did not return both counts." : "Zero findings carry a verdict yet."}
                height={52}
              />
            )}
          </div>
          <div style={{ marginTop: 8 }}><LiveBadge source="live" label="LIVE DB" /></div>
        </Panel>
      )}

      {/* ── scanner matrix ────────────────────────────────────────────── */}
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
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 12 }}>
            <StateCell label="cycle" value={scan.running ? "RUNNING" : "idle"} tone={scan.running ? "green" : "slate"} />
            <StateCell label="scanners OK" value={scanObserved ? observed(count(scan.ok_count)) : "Not observed"} tone={scanObserved ? "green" : "slate"} note="last cycle" />
            <StateCell label="scanners failed" value={scanObserved ? observed(failed) : "Not observed"} tone={failed ? "red" : "slate"} note="blocked/unconfigured excluded" />
            {alerts && numeric(alerts.counts?.CRITICAL) !== null && numeric(alerts.counts?.HIGH) !== null &&
              (numeric(alerts.counts.CRITICAL)! + numeric(alerts.counts.HIGH)!) > 0 && (
                <Link to="/alerts" style={{ textDecoration: "none" }}>
                  <StateCell
                    label="critical/high alerts"
                    value={numeric(alerts.counts.CRITICAL)! + numeric(alerts.counts.HIGH)!}
                    tone="red"
                    note="live-scan alerts, open this screen"
                  />
                </Link>
              )}
            {scan.scanners?.hardware?.summary?.tpm_present === true && <StateCell label="last reported TPM" value="present" tone="green" />}
          </div>

          {/* per-scanner tiles: the dot is the reported result, the bar is the
              reported elapsed time relative to the slowest scanner in the cycle */}
          {scannerRows.length ? (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 8 }}>
              {scannerRows.map((row) => {
                const slowest = Math.max(1, ...scannerRows.map((r) => r.elapsed ?? 0));
                const state = row.ok === true ? { dot: "var(--green)", text: "ok" } : row.ok === false ? { dot: "var(--red)", text: "failed" } : { dot: "var(--slate)", text: "no result" };
                return (
                  <div key={row.key} style={{ padding: "8px 10px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel-2)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ width: 7, height: 7, borderRadius: 999, background: state.dot }} />
                      <span className="mono" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em" }}>{row.label}</span>
                      <span className="mono" style={{ marginLeft: "auto", fontSize: 10.5, color: "var(--dim)" }}>{state.text}</span>
                    </div>
                    <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ flex: 1, height: 4, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1, overflow: "hidden" }}>
                        <span
                          style={{
                            display: "block",
                            height: "100%",
                            width: row.elapsed === null ? "0%" : `${Math.max(2, (row.elapsed / slowest) * 100)}%`,
                            background: row.ok === false ? "var(--red)" : "var(--accent)",
                          }}
                        />
                      </span>
                      <span className="mono" style={{ fontSize: 10, color: "var(--faint)", minWidth: 34, textAlign: "right" }}>
                        {row.elapsed === null ? "—" : `${row.elapsed}s`}
                      </span>
                    </div>
                    {row.error && <div style={{ fontSize: 10, color: "var(--red)", marginTop: 3, overflowWrap: "anywhere" }}>{row.error}</div>}
                  </div>
                );
              })}
            </div>
          ) : (
            <VizEmpty title="No scanner reported in the last cycle" note="The status read returned no per-scanner result to draw." height={54} />
          )}

          {alertRows.length > 0 && (
            <div style={{ marginTop: 12, paddingTop: 10, borderTop: "1px solid var(--line)" }}>
              <HBars rows={alertRows} emptyTitle="No live-scan alert" emptyNote="The alerts read returned no severity count." />
            </div>
          )}
          <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
            Last-cycle failures exclude blocked and unconfigured scanners; these counts do not measure fleet health.
          </div>
          {lastScanEvent && rt.connected && <div style={{ marginTop: 6 }}><LiveBadge source="live" label="SSE LIVE" /></div>}
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

      {/* ── inventory + certificates ──────────────────────────────────── */}
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Local inventory" sub={snapshotObserved ? `Local inventory · snapshot ${when(inventory?.generated_at)}` : "No completed local inventory snapshot observed"}>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {inventoryKeys.map((key, index) => {
              const value = inventoryValues[index];
              return (
                <KpiMeter
                  key={key}
                  k={key.replace(/_/g, " ")}
                  v={value}
                  tone={typeof value === "number" && value > 0 ? "accent" : ""}
                  ratio={typeof value === "number" ? value / inventoryMax : null}
                />
              );
            })}
          </div>
          <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
            Bar length is relative to the largest category in this snapshot. Source: most recent local scanner output. These categories can overlap and are not a total asset count.
          </div>
        </Panel>

        <Panel
          title="Certificate posture"
          sub={certCenter ? `Local certificate centre · ${when(inventory?.generated_at)}` : "No certificate centre in the latest snapshot"}
        >
          {certRows.length ? (
            <>
              <HBars rows={certRows} emptyTitle="No certificate finding" emptyNote="The certificate centre returned no counts." />
              <div className="dim" style={{ fontSize: 11.5, marginTop: 8 }}>
                Counts from the local certificate centre in the latest snapshot
                {typeof certCenter?.total === "number" ? ` of ${certCenter.total.toLocaleString()} certificate(s) read` : ""}. A certificate may appear in more than one column.
              </div>
            </>
          ) : (
            <VizEmpty title="Certificate posture not observed" note="Fills after a completed local scan that includes the certificate centre." height={92} />
          )}
        </Panel>
      </div>

      {/* ── PQC + migration + telemetry + drift ───────────────────────── */}
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Panel title="PQC posture" sub="Readiness and migration require scoped assessment, not inventory coverage">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <GapBar label="PQC readiness" reason="Needs an algorithm inventory with owners, not an asset count." />
            <GapBar label="Hybrid readiness" reason="No hybrid-crypto measurement is recorded for this estate." />
            <GapBar label="Migration required" reason="Requires a scoped migration assessment per system." />
            <Kpi k="CBOM components flagged vulnerable" v={observed(flaggedComponents)} />
            <span className="dim" style={{ fontSize: 11.5 }}>Flagged count is limited to classified components in the latest local CBOM; unknowns are not safe or ready.</span>
          </div>
        </Panel>

        <Panel title="CBOM classification" sub={bomObserved ? `Latest local CBOM · ${when(bom?.generated_at)}` : "No CBOM snapshot observed"}>
          {cbomStatusSegments.length ? (
            <StackedBar
              segments={cbomStatusSegments}
              note="Classification of the components in the latest local CBOM. This is not PQC readiness and does not cover systems without a CBOM."
            />
          ) : cbomCountRows.length ? (
            <HBars rows={cbomCountRows} emptyTitle="No classified component" emptyNote="The snapshot carries counts but no component-level classification." />
          ) : (
            <VizEmpty title="No CBOM component to classify" note="Fills from a completed scan that produces a CBOM." height={92} />
          )}
        </Panel>

        <Panel title="Telemetry" sub="Last completed scanner cycle; no 24h window">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="cycle running" v={scan ? (scan.running ? "Yes" : "No") : "Not observed"} />
            <Kpi k="scanners OK (last cycle)" v={scanObserved ? observed(count(scan?.ok_count)) : "Not observed"} />
            <Kpi k="scanners failed (last cycle)" v={scanObserved ? observed(failed) : "Not observed"} />
            <Kpi k="events / sec" v="Not measured" />
            <GapBar label="event rate" reason="The control plane exposes no measured events-per-second for this estate." />
          </div>
        </Panel>

        <Panel title="Open drift" sub="Persisted OPEN drift events by severity; all time">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {(["CRITICAL", "HIGH", "MEDIUM", "INFO"] as const).map((severity) => {
              const value = stats ? count(openDrift[severity]) : null;
              const max = stats ? Math.max(1, ...(["CRITICAL", "HIGH", "MEDIUM", "INFO"] as const).map((s) => count(openDrift[s]) ?? 0)) : 1;
              return (
                <div key={severity} className="spread">
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                    <span style={{ width: 7, height: 7, borderRadius: 1, background: severity === "CRITICAL" ? "var(--red)" : severity === "HIGH" ? "var(--orange)" : severity === "MEDIUM" ? "var(--amber)" : "var(--slate)" }} />
                    <span>{severity}</span>
                  </span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 8, flex: 1, justifyContent: "flex-end" }}>
                    {value !== null && (
                      <span style={{ width: 70, height: 5, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 1, overflow: "hidden" }}>
                        <span style={{ display: "block", height: "100%", width: `${(value / max) * 100}%`, background: severity === "CRITICAL" ? "var(--red)" : severity === "HIGH" ? "var(--orange)" : severity === "MEDIUM" ? "var(--amber)" : "var(--slate)" }} />
                      </span>
                    )}
                    <span className="mono" style={{ margin: 0, minWidth: 34, textAlign: "right" }}>{stats ? observed(value) : "Not observed"}</span>
                  </span>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="Migration" sub="No measured program or readiness denominator">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <GapBar label="PQC exposure" reason="No estate-wide algorithm inventory has been measured." />
            <GapBar label="migration progress" reason="Needs a migration plan with dated, per-system milestones." />
            <Kpi k="systems with CBOM" v={stats ? observed(count(coverage.with_cbom)) : "Not observed"} />
            <Kpi k="HBOM snapshot" v={bomObserved ? "Available" : "Not observed"} />
            <span className="dim" style={{ fontSize: 11.5 }}>Systems with CBOM includes current and stale coverage; it is not PQC readiness.</span>
          </div>
        </Panel>

        <Panel title="Evidence findings" sub="All persisted scans; no time window">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="total findings" v={stats ? observed(count(stats.total_findings)) : "Not observed"} />
            <Kpi k="PASS findings" v={stats ? observed(findingsPass) : "Not observed"} />
            <Kpi k="FAIL findings" v={stats ? observed(findingsFail) : "Not observed"} />
            <Kpi k="evidence integrity" v="Not measured" />
            <GapBar label="chain verification" reason="Verifying the evidence chain is a per-pack operation, not a dashboard figure." />
          </div>
        </Panel>
      </div>

      {/* ── events + drift comparison ─────────────────────────────────── */}
      <div className="grid cols-2">
        <Panel title="Recent events" sub={rt.connected ? "realtime SSE stream; recent sample only" : "recent endpoint sample; no 24h or rate guarantee"}>
          {feed.length ? (
            <>
              <TickStrip
                ticks={feed.map((item) => ({ ts: item.t, severity: item.severity === "CRITICAL" ? "critical" : item.severity === "HIGH" || item.severity === "MEDIUM" ? "warn" : "info" }))}
                label="Newest events by severity"
                emptyNote="No event to colour."
              />
              <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 10 }}>
                {feed.map((item, index) => (
                  <div key={`${item.tag}-${index}`} style={{ display: "flex", alignItems: "center", gap: 8, padding: "5px 8px", border: "1px solid var(--line)", borderRadius: "var(--r)", background: "var(--panel-2)" }}>
                    <Badge tone={item.severity === "CRITICAL" ? "red" : item.severity === "HIGH" ? "orange" : item.severity === "MEDIUM" ? "amber" : "green"}>{item.severity || "event"}</Badge>
                    <span className="mono" style={{ fontSize: 11, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item.tag}</span>
                    <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)", whiteSpace: "nowrap" }}>{item.t}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <VizEmpty
              title={recentEvents.error ? "Recent events unavailable" : "No recent events returned"}
              note={recentEvents.error ? "The read failed; this is not a claim that nothing happened." : "The endpoint returned an empty sample for this window."}
              height={72}
            />
          )}
        </Panel>

        <Panel title="Latest inventory comparison" sub={driftObserved ? `Previous ${when(drift?.previous_ts)} · current ${when(drift?.ts)}` : "Comparison requires two inventory snapshots"}>
          {driftObserved ? (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 8, marginBottom: 10 }}>
                <StateCell label="changes between snapshots" value={observed(changes)} tone={changes ? "orange" : "green"} />
                <StateCell label="scanner reported" value={new Set((drift?.changes ?? []).map((c) => c.scanner)).size} tone="accent" note="scanners with at least one change" />
              </div>
              {driftSeverityRows.length > 0 && (
                <HBars rows={driftSeverityRows} emptyTitle="No change" emptyNote="The comparison returned no change to draw." />
              )}
              {Array.isArray(drift?.changes) && drift.changes.length > 0 ? (
                <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 4 }}>
                  {drift.changes.slice(0, 5).map((change, index) => (
                    <div key={index} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
                      <Badge tone={String(change.severity).toUpperCase() === "CRITICAL" ? "red" : String(change.severity).toUpperCase() === "HIGH" ? "orange" : "amber"}>
                        {String(change.severity || "change").toUpperCase()}
                      </Badge>
                      <span className="mono" style={{ fontSize: 11, color: "var(--dim)" }}>{change.scanner}</span>
                      <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{change.title}</span>
                    </div>
                  ))}
                  {drift.changes.length > 5 && (
                    <span className="dim" style={{ fontSize: 11 }}>…and {drift.changes.length - 5} more; open Drift for the full comparison.</span>
                  )}
                </div>
              ) : (
                <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>Two snapshots compared with no difference.</div>
              )}
            </>
          ) : (
            <VizEmpty
              title={drift ? "No comparison baseline yet" : "Comparison unavailable"}
              note={drift ? "A comparison needs two completed inventory snapshots." : "The drift read failed; this is not a claim that nothing changed."}
              height={92}
            />
          )}
        </Panel>
      </div>
    </>
  );
}

function HeroKpi({ label, q, value, tone, to, suffix }: { label: string; q: string; value: number | string; tone: string; to: string; suffix: string }) {
  const color = tone === "red" ? "var(--red)" : tone === "orange" ? "var(--orange)" : tone === "amber" ? "var(--amber)"
    : tone === "green" ? "var(--green)" : tone === "blue" ? "var(--blue)" : "var(--cyan)";
  const measured = typeof value === "number";
  return (
    <Link to={to} className="hero-kpi" style={{ textDecoration: "none", borderTopColor: color }}>
      <span className="hero-q">{q}</span>
      <span className="hero-label">{label}</span>
      <span className="hero-v" style={{ color: measured ? "var(--text)" : "var(--slate)", fontSize: measured ? undefined : 18, overflowWrap: "anywhere" }}>{measured ? value.toLocaleString() : value}</span>
      {/* state rail: solid = a figure was read, hatched = nothing was measured.
          The difference between "0" and "not measured" is the point of the tile. */}
      <span
        aria-hidden
        style={{
          display: "block",
          height: 4,
          marginTop: 4,
          borderRadius: 1,
          border: `1px solid ${measured ? "transparent" : "var(--line-strong)"}`,
          background: measured ? color : "none",
          backgroundImage: measured
            ? "none"
            : "repeating-linear-gradient(135deg, transparent 0 4px, color-mix(in srgb, var(--slate) 30%, transparent) 4px 6px)",
          opacity: measured ? 0.9 : 1,
        }}
      />
      <span className="hero-suffix" style={{ color: "var(--dim)", overflowWrap: "anywhere" }}>{suffix}</span>
    </Link>
  );
}

function LiveStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", minWidth: 110 }}>
      <span className="mono" style={{ fontSize: 26, fontWeight: 700, color: typeof value === "number" ? "var(--text)" : "var(--slate)" }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </span>
      <span className="dim" style={{ fontSize: 11.5, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</span>
    </div>
  );
}
