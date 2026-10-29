/* Live monitor — the estate as it is being measured, not as it is described.
 *
 * Layout rule for this screen: every block answers "what was measured, over
 * what window, and how much of it is missing". Prose is demoted to a footnote
 * or a disclosure; a number without a window is a lie dressed as a metric, and
 * a chart without samples renders as an explicit labelled absence (see
 * components/viz.tsx). This page never computes a percentage of a target,
 * never invents history for a chart, and never shows the last good read after
 * a failed one.
 */

import { Link } from "react-router-dom";
import PrivateScope from "../components/PrivateScope";
import EstateSchedulePanel from "../components/EstateSchedulePanel";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Badge, Panel } from "../components/ui";
import { usePollingApi } from "../lib/apiUi";
import { useRealtime, useChannelRefresh, severityOf, isSystemEvent } from "../lib/realtime";
import {
  apiLiveEnvironment,
  apiLiveOrchestratorStatus,
  apiLiveOrchestratorHistory,
  apiLiveOrchestratorStart,
  apiTechBomLive,
  apiEstateRealtime,
  LiveEnvironmentResponse,
  OrchestratorScan,
  ScanRunSummary,
  type EstateRealtime,
} from "../lib/api";
import { DeltaChip, HBars, Meter, Sparkline, StackedBar, StateCell, TickStrip, VizEmpty } from "../components/viz";

type Severity = "info" | "warn" | "critical";

function timeAgo(ts: string | null | undefined): string {
  if (!ts) return "—";
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return "—";
  const d = Math.max(0, Date.now() - t);
  if (d < 1000) return "now";
  if (d < 60_000) return `${Math.floor(d / 1000)}s`;
  if (d < 3600_000) return `${Math.floor(d / 60_000)}m`;
  if (d < 86400_000) return `${Math.floor(d / 3600_000)}h`;
  return `${Math.floor(d / 86400_000)}d`;
}

function clock(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleTimeString();
}

const nf = (n: number) => n.toLocaleString();

type ChangeRecord = {
  id: string;
  ts: string;
  domain: string;
  delta: number;
  from: number;
  to: number;
  severity: Severity;
};

/** One read of this screen. `null` marks a read that failed — a gap, not a zero. */
type Sample = { ts: string; total: number | null; severity: Severity; failed: boolean };

const DOMAIN_META: Record<string, { label: string; tone: string; to: string }> = {
  network: { label: "Network", tone: "cyan", to: "/network" },
  hardware: { label: "Hardware", tone: "amber", to: "/hardware" },
  crypto: { label: "Cryptography", tone: "green", to: "/crypto" },
  vendor: { label: "Vendors", tone: "violet", to: "/vendor" },
  certificate: { label: "Certificates", tone: "red", to: "/certificates" },
  application: { label: "Applications", tone: "cyan", to: "/dev-sec-ops" },
  software: { label: "Software (SBOM)", tone: "cyan", to: "/sbom" },
  techbom: { label: "TechBOM", tone: "violet", to: "/live-asset-intelligence" },
};

const TECHBOM_LAYERS = [
  { k: "sbom", label: "Software", to: "/sbom", tone: "cyan" },
  { k: "cbom", label: "Crypto", to: "/cbom", tone: "green" },
  { k: "hbom", label: "Hardware", to: "/hbom", tone: "amber" },
  { k: "nbom", label: "Network", to: "/nbom", tone: "violet" },
  { k: "vendor", label: "Vendors", to: "/vbom", tone: "slate" },
  { k: "certificates", label: "Certificates", to: "/certificates", tone: "red" },
];

const phaseTone = (phase: string) =>
  phase === "live_monitoring" || phase === "completed" ? "green" : phase === "failed" ? "red" : "amber";

const sevTone = (s: string) => (s === "CRITICAL" ? "red" : s === "HIGH" ? "orange" : s === "MEDIUM" ? "amber" : "green");

const llTone = (live: boolean) => (live ? "green" : "red");

function livenessTone(state?: string) {
  if (state === "LIVE") return "green";
  if (state === "STALE") return "amber";
  if (state === "STOPPED") return "red";
  return "slate";
}

function stateColor(verdict: string | null) {
  if (verdict === "RUNNING") return "var(--green)";
  if (verdict === "DEGRADED") return "var(--red)";
  if (verdict === "WAITING") return "var(--amber)";
  if (verdict === "NOT_RUNNING" || verdict === "IDLE_NO_SCHEDULES") return "var(--slate)";
  return "var(--slate)";
}

const verdictTone = (v: string | null) =>
  v === "RUNNING" ? "green" : v === "DEGRADED" ? "red" : v === "WAITING" ? "amber" : "slate";

const toolbarBtn = (active: boolean, tone = "var(--accent)"): React.CSSProperties => ({
  padding: "4px 9px",
  borderRadius: 2,
  fontSize: 11,
  fontFamily: "var(--mono)",
  fontWeight: 600,
  border: `1px solid ${active ? tone : "var(--line-strong)"}`,
  background: active ? `color-mix(in srgb, ${tone} 14%, transparent)` : "var(--panel)",
  color: active ? tone : "var(--text)",
  cursor: "pointer",
});

export default function LiveMonitor() {
  return (
    <PrivateScope>
      <LiveMonitorPage />
    </PrivateScope>
  );
}

function LiveMonitorPage() {
  const [intervalMs, setIntervalMs] = useState<number>(6000);
  const [isPaused, setIsPaused] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [toneEnabled, setToneEnabled] = useState(false);
  const [uptimeSec, setUptimeSec] = useState(0);
  const [changes, setChanges] = useState<ChangeRecord[]>([]);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [lastReadAt, setLastReadAt] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  const prevRef = useRef<Record<string, number> | null>(null);

  const effectiveInterval = isPaused ? 600000 : intervalMs;
  const lt = usePollingApi(apiLiveEnvironment, effectiveInterval);
  const status = usePollingApi(apiLiveOrchestratorStatus, isPaused ? 600000 : Math.max(6000, intervalMs * 2));
  const history = usePollingApi(apiLiveOrchestratorHistory, isPaused ? 600000 : 15000);
  const techBom = usePollingApi(() => apiTechBomLive(500), isPaused ? 600000 : intervalMs);
  const estate = usePollingApi<EstateRealtime>(apiEstateRealtime, isPaused ? 600000 : 15000, [],
    { channels: ["estate"], liveIntervalMs: 30000 });
  const rt = useRealtime();
  useChannelRefresh(["estate", "crypto", "inventory"], [lt.run, status.run, history.run, techBom.run]);

  const estateState = estate.source === "live" ? estate.data : null;
  const estateVerdict = estateState?.verdict ?? null;
  const env: LiveEnvironmentResponse | null = (lt.data as LiveEnvironmentResponse | null) ?? null;
  const scan: OrchestratorScan | null = env?.scan ?? (status.data as { scan?: OrchestratorScan | null } | null)?.scan ?? null;
  const domains = env?.domains ?? { network: 0, hardware: 0, vendor: 0, crypto: 0, certificate: 0, application: 0, total: 0 };
  const graph = env?.graph ?? ({} as NonNullable<LiveEnvironmentResponse["graph"]>);
  const events = (env?.events?.events ?? []).filter((e) => !isSystemEvent(e.type)).slice(0, 10);
  const runs: ScanRunSummary[] = (history.data as { runs?: ScanRunSummary[] } | null)?.runs ?? [];
  const live = lt.source === "live";
  const techBomState = techBom.data as
    | { total_components?: number; layers?: Record<string, { count?: number }>; components_by_layer?: Record<string, number> }
    | null;
  const techBomTotal = techBomState?.total_components ?? 0;
  const techBomLayers = techBomState?.layers ?? {};
  const byLayer = techBomState?.components_by_layer ?? {};

  useEffect(() => {
    const t = setInterval(() => setUptimeSec((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (isFullscreen) document.documentElement.setAttribute("data-live-fullscreen", "true");
    else document.documentElement.removeAttribute("data-live-fullscreen");
    return () => document.documentElement.removeAttribute("data-live-fullscreen");
  }, [isFullscreen]);

  // ── observation record ────────────────────────────────────────────────
  // One sample per completed read. A failed read is recorded with a null total
  // so the chart draws a gap: the alternative — carrying the previous figure
  // forward — would show a flat line that looks like a stable estate while the
  // API was refusing to answer.
  useEffect(() => {
    const ts = new Date().toISOString();
    if (lt.source === "offline") {
      if (samples.length === 0 || !samples[samples.length - 1].failed) {
        const gap: Sample = { ts, total: null, severity: "warn", failed: true };
        setSamples((prev) => [...prev, gap].slice(-180));
      }
      return;
    }
    if (lt.source !== "live" || !env) return;
    setLastReadAt(ts);
    const total = domains.total;
    setSamples((prev) => {
      const recent = prev.slice(-180);
      const withSample = [...recent, { ts, total, severity: "info" as Severity, failed: false }];
      return withSample.slice(-180);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lt.source, lt.data, env?.domains.total]);

  // ── change detection ──────────────────────────────────────────────────
  useEffect(() => {
    if (!env || lt.source !== "live") return;
    const now = new Date().toISOString();
    const curr: Record<string, number> = {
      network: domains.network,
      hardware: domains.hardware,
      vendor: domains.vendor,
      crypto: domains.crypto,
      certificate: domains.certificate,
      application: domains.application,
      total: domains.total,
      techbom: techBomTotal,
      software: (byLayer["sbom"] ?? techBomLayers?.sbom?.count ?? 0) + domains.application,
    };
    const prev = prevRef.current;
    prevRef.current = curr;
    if (!prev) return;

    const fresh: ChangeRecord[] = [];
    for (const key of Object.keys(curr)) {
      const from = prev[key] ?? 0;
      const to = curr[key] ?? 0;
      if (from === to) continue;
      const delta = to - from;
      const abs = Math.abs(delta);
      const severity: Severity =
        key === "crypto" || key === "certificate" ? (abs >= 3 ? "critical" : "warn") : abs >= 5 ? "warn" : "info";
      fresh.push({ id: `${now}-${key}-${from}-${to}`, ts: now, domain: key, delta, from, to, severity });
    }
    if (!fresh.length) return;

    setChanges((prevChanges) => [...fresh, ...prevChanges].slice(0, 60));
    // The tick that carried these deltas is tinted by the worst of them.
    const worst: Severity = fresh.some((c) => c.severity === "critical")
      ? "critical"
      : fresh.some((c) => c.severity === "warn")
        ? "warn"
        : "info";
    setSamples((prevSamples) => {
      if (!prevSamples.length) return prevSamples;
      const next = [...prevSamples];
      next[next.length - 1] = { ...next[next.length - 1], severity: worst };
      return next;
    });

    if (toneEnabled && fresh.some((c) => c.severity === "critical")) {
      try {
        const Ctx = window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext;
        const ctx = new Ctx();
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = "sine";
        osc.frequency.value = 880;
        gain.gain.value = 0.06;
        osc.connect(gain).connect(ctx.destination);
        osc.start();
        setTimeout(() => {
          osc.stop();
          void ctx.close();
        }, 160);
      } catch {
        /* audio is optional; a refused AudioContext must not break the screen */
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domains.network, domains.hardware, domains.vendor, domains.crypto, domains.certificate, domains.application, domains.total, techBomTotal]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return;
      if (e.code === "Space") {
        e.preventDefault();
        setIsPaused((p) => !p);
      }
      if (e.key.toLowerCase() === "f") setIsFullscreen((f) => !f);
      if (e.key === "Escape") setIsFullscreen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const startScan = async () => {
    setStarting(true);
    try {
      await apiLiveOrchestratorStart();
      setTimeout(() => {
        void lt.run();
        void status.run();
      }, 600);
    } finally {
      setStarting(false);
    }
  };

  const uptimeLabel = useMemo(() => {
    const h = Math.floor(uptimeSec / 3600);
    const m = Math.floor((uptimeSec % 3600) / 60);
    const s = uptimeSec % 60;
    if (h > 0) return `${h}h ${String(m).padStart(2, "0")}m`;
    if (m > 0) return `${m}m ${String(s).padStart(2, "0")}s`;
    return `${s}s`;
  }, [uptimeSec]);

  const collected = samples.filter((s) => !s.failed).length;
  const failedReads = samples.filter((s) => s.failed).length;
  const totals = samples.filter((s) => s.total !== null).map((s) => s.total as number);
  const everObservedAssets = totals.some((t) => t > 0);
  const recentChanges = changes.filter((c) => Date.now() - new Date(c.ts).getTime() < 300_000).length;
  const engineLive = live && !isPaused;

  const domainRows = (["network", "hardware", "crypto", "vendor", "certificate", "application", "software", "techbom"] as const).map((key) => {
    const meta = DOMAIN_META[key];
    const value =
      key === "software"
        ? (byLayer["sbom"] ?? 0) + domains.application
        : key === "techbom"
          ? techBomTotal
          : (domains as unknown as Record<string, number>)[key] ?? 0;
    const lastChange = changes.find((c) => c.domain === key);
    return { key, label: meta.label, value, tone: meta.tone, to: meta.to, delta: lastChange?.delta ?? 0 };
  });

  const graphKinds = Object.entries(graph.by_kind ?? {}).map(([k, v]) => ({
    key: k,
    label: k,
    value: Number(v) || 0,
    tone: "violet",
  }));

  return (
    <div
      style={{
        maxWidth: isFullscreen ? "100%" : 1360,
        margin: "0 auto",
        padding: isFullscreen ? "10px 14px 40px" : "0 0 48px",
      }}
    >
      {isFullscreen && (
        <div
          style={{
            position: "sticky",
            top: 0,
            zIndex: 20,
            display: "flex",
            alignItems: "center",
            gap: 12,
            padding: "8px 12px",
            margin: "0 0 12px",
            background: "var(--bg-2)",
            border: "1px solid var(--line)",
            borderRadius: "var(--r)",
            fontFamily: "var(--mono)",
            fontSize: 11.5,
          }}
        >
          <span style={{ color: engineLive ? "var(--green)" : "var(--slate)" }}>●</span>
          <b>Live monitor — fullscreen</b>
          <span style={{ color: "var(--dim)" }}>F or Esc exits · Space pauses</span>
          <span style={{ marginLeft: "auto" }} />
          <button type="button" onClick={() => setIsFullscreen(false)} style={toolbarBtn(false)}>
            Exit fullscreen
          </button>
        </div>
      )}

      {/* ── header ─────────────────────────────────────────────────── */}
      <div className="topbar" style={{ marginBottom: 14 }}>
        <div>
          <div className="crumb">Operate · live estate</div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 650, letterSpacing: "-0.01em" }}>Live monitor</h1>
          <div className="mono" style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 4 }}>
            {scan ? `scan ${scan.scan_id.slice(0, 8)} · ${scan.phase.replace(/_/g, " ")}` : "no integrated scan recorded"}
            {" · "}
            {collected} read(s) since this screen opened · {uptimeLabel}
          </div>
        </div>
        <div className="row" style={{ alignItems: "center", gap: 6 }}>
          <Badge tone={rt.connected ? "green" : llTone(live)}>{rt.connected ? "SSE LIVE" : live ? "API POLLING" : "API UNREACHABLE"}</Badge>
          <Badge tone={verdictTone(estateVerdict)}>collection {estateVerdict ?? "UNKNOWN"}</Badge>
          <span className="row" style={{ gap: 4 }}>
            {[3000, 6000, 15000, 30000].map((ms) => (
              <button
                key={ms}
                type="button"
                onClick={() => setIntervalMs(ms)}
                style={toolbarBtn(intervalMs === ms && !isPaused)}
                aria-pressed={intervalMs === ms}
                title={`Read the API every ${ms / 1000}s`}
              >
                {ms / 1000}s
              </button>
            ))}
            <button
              type="button"
              onClick={() => setIsPaused((p) => !p)}
              style={toolbarBtn(isPaused, "var(--amber)")}
              aria-pressed={isPaused}
              title="Space toggles polling"
            >
              {isPaused ? "Resume" : "Pause"}
            </button>
            <button type="button" onClick={() => setIsFullscreen((f) => !f)} style={toolbarBtn(isFullscreen)} title="F toggles fullscreen">
              Fullscreen
            </button>
            <button
              type="button"
              onClick={() => setToneEnabled((t) => !t)}
              style={toolbarBtn(toneEnabled, "var(--amber)")}
              aria-pressed={toneEnabled}
              title="Play a tone when a critical delta is first seen (off by default)"
            >
              Tone {toneEnabled ? "on" : "off"}
            </button>
          </span>
        </div>
      </div>

      {/* ── collection state ───────────────────────────────────────── */}
      <section
        role="status"
        aria-label="Estate collection status"
        className="panel"
        style={{ padding: "10px 12px", marginBottom: 12, borderLeft: `2px solid ${stateColor(estateVerdict)}` }}
      >
        <div className="spread" style={{ gap: 10 }}>
          <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
            <span
              className="mono"
              style={{ fontSize: 12.5, fontWeight: 700, letterSpacing: "0.02em", color: stateColor(estateVerdict) }}
            >
              Scheduled collection: {estateVerdict ?? "UNKNOWN"}
            </span>
            <span style={{ fontSize: 12, color: "var(--dim)" }}>
              {estateState?.reason ?? "Current daemon and schedule state unavailable; API connectivity is not collection coverage."}
            </span>
          </div>
          {estateState?.next_action && (
            <span className="mono" style={{ fontSize: 11, color: "var(--amber)", whiteSpace: "nowrap" }}>
              next: {estateState.next_action}
            </span>
          )}
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
            gap: 8,
            marginTop: 10,
          }}
        >
          <StateCell
            label="Daemon liveness"
            value={estateState?.daemon.liveness.state ?? "NOT_READ"}
            tone={livenessTone(estateState?.daemon.liveness.state)}
            note={
              estateState
                ? `${estateState.daemon.liveness.age_seconds === null ? "age unknown" : `heartbeat ${estateState.daemon.liveness.age_seconds}s ago`}`
                : "the status read did not return"
            }
          />
          <StateCell
            label="Schedules"
            value={estateState ? `${estateState.schedules.enabled}/${estateState.schedules.total}` : "—"}
            tone={estateState?.schedules.enabled ? "green" : "slate"}
            note={`${estateState?.schedules.enabled ?? 0} enabled schedule(s)`}
          />
          <StateCell
            label="Last completed run"
            value={estateState?.runs.last_finished_at ? `${timeAgo(estateState.runs.last_finished_at)} ago` : "none"}
            tone={estateState?.runs.last_finished_at ? "green" : "slate"}
            note={`last completed run ${estateState?.runs.last_finished_at ?? "none"}`}
          />
          <StateCell
            label="Next due"
            value={estateState?.schedules.next_due_at ? clock(estateState.schedules.next_due_at) : "—"}
            note={estateState?.schedules.seconds_until_due === null || estateState?.schedules.seconds_until_due === undefined
              ? "no cadence registered"
              : `in ${estateState.schedules.seconds_until_due}s`}
          />
        </div>

        <details style={{ marginTop: 8 }}>
          <summary className="mono" style={{ fontSize: 10.5, color: "var(--faint)", cursor: "pointer" }}>
            What this state proves, and what it does not
          </summary>
          <p style={{ fontSize: 11, color: "var(--faint)", margin: "6px 0 0", lineHeight: 1.5, maxWidth: 900 }}>
            Scheduled discovery reprojects stored observations. A heartbeat, an empty result, or an enabled cadence is
            not proof that a collector acquired new evidence. API connectivity is not collection coverage.
          </p>
        </details>
      </section>

      {/* ── observation record + composition ───────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 12, marginBottom: 12 }}>
        <Panel
          title="Observation record"
          sub={`${collected} successful read(s) · ${failedReads} failed · interval ${isPaused ? "paused" : `${intervalMs / 1000}s`} · last read ${lastReadAt ? `${timeAgo(lastReadAt)} ago` : "—"}`}
        >
          <Sparkline
            series={samples.map((s) => s.total)}
            label="Total estate assets per read"
            tone="accent"
            height={74}
            emptyNote="Nothing has been read yet. The chart fills from the values this screen actually received."
          />
          <div style={{ marginTop: 8 }}>
            <TickStrip
              ticks={samples.map((s) => ({ ts: s.ts, severity: s.severity }))}
              label="Ticks by change severity"
              emptyNote="No read has completed, so there is no tick to colour."
            />
          </div>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 8 }}>
            <span style={{ fontSize: 10.5, color: "var(--faint)" }}>
              <span style={{ color: "var(--green)" }}>▮</span> tick with no delta
            </span>
            <span style={{ fontSize: 10.5, color: "var(--faint)" }}>
              <span style={{ color: "var(--amber)" }}>▮</span> warning delta
            </span>
            <span style={{ fontSize: 10.5, color: "var(--faint)" }}>
              <span style={{ color: "var(--red)" }}>▮</span> critical delta
            </span>
            <span style={{ fontSize: 10.5, color: "var(--faint)" }}>┊ dashed = read failed (gap, not zero)</span>
          </div>
          {collected > 0 && !everObservedAssets && (
            <p style={{ margin: "8px 0 0", fontSize: 11, color: "var(--dim)" }}>
              Every read returned 0 assets. That is a measurement of an empty estate — not an error, and not coverage.
            </p>
          )}
        </Panel>

        <Panel title="Estate composition" sub={`${nf(domains.total)} asset(s) attributed to a domain`}>
          <StackedBar
            segments={[
              { key: "network", label: "Network", value: domains.network, tone: "cyan" },
              { key: "hardware", label: "Hardware", value: domains.hardware, tone: "amber" },
              { key: "crypto", label: "Crypto", value: domains.crypto, tone: "green" },
              { key: "vendor", label: "Vendor", value: domains.vendor, tone: "violet" },
              { key: "application", label: "Application", value: domains.application, tone: "slate" },
              { key: "certificate", label: "Certificate", value: domains.certificate, tone: "red" },
            ]}
            note="Shares are of what the API returned for this tenant, not of the bank's real estate."
          />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 12 }}>
            <StateCell label="Graph nodes" value={nf(graph.node_count ?? 0)} tone={(graph.node_count ?? 0) ? "violet" : "slate"} note="dependency view" />
            <StateCell label="Graph edges" value={nf(graph.edge_count ?? 0)} tone={(graph.edge_count ?? 0) ? "violet" : "slate"} note="dependency view" />
          </div>
          <Link to="/graph" className="mono" style={{ display: "inline-block", marginTop: 10, fontSize: 11, color: "var(--accent)" }}>
            open dependency graph →
          </Link>
        </Panel>
      </div>

      {/* ── coverage by domain ─────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))", gap: 12, marginBottom: 12 }}>
        <Panel
          title="Assets by domain"
          sub="Bar length is relative to the largest domain in this read; the chip is the last delta seen on this screen."
        >
          {/* No read, no rows: a zero row would be a claim that the domain was
              measured and came back empty, which is a different statement. */}
          <HBars
            rows={env ? domainRows : []}
            emptyTitle="No domain returned a count"
            emptyNote="The environment read has not returned; this is an unread panel, not an empty estate."
          />
          {env && domainRows.every((r) => r.value === 0) && (
            <p style={{ margin: "8px 0 0", fontSize: 11, color: "var(--faint)" }}>
              All eight domains measured 0 in this read. The table says what the API returned for this tenant.
            </p>
          )}
        </Panel>

        <Panel title="TechBOM layers" sub={`${nf(techBomTotal)} component(s) reported across ${Object.keys(techBomLayers).length} layer(s)`}>
          <HBars
            rows={TECHBOM_LAYERS.map((l) => ({
              key: l.k,
              label: l.label,
              value: byLayer[l.k] ?? techBomLayers[l.k]?.count ?? 0,
              tone: l.tone,
              to: l.to,
            }))}
            emptyTitle="TechBOM is empty"
            emptyNote="Layers fill from a completed integrated scan or an onboarding import."
          />
          <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px solid var(--line)" }}>
            <HBars
              rows={graphKinds}
              emptyTitle="No graph kinds recorded"
              emptyNote="Dependency topology appears after discovery attributes assets to a graph."
            />
          </div>
        </Panel>
      </div>

      {/* ── assessment cadences ────────────────────────────────────── */}
      <EstateSchedulePanel />

      {/* ── orchestrator ───────────────────────────────────────────── */}
      <Panel
        title="Scan orchestrator"
        sub="One global scan id · phase machine · per-scanner progress as reported by the runner"
      >
        {scan ? (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 16 }}>
            <div>
              <div className="mono" style={{ fontSize: 15, fontWeight: 700, wordBreak: "break-all" }}>{scan.scan_id}</div>
              <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 4 }}>
                {scan.org_name || "—"} · started {timeAgo(scan.started_at)} ago
              </div>
              <div style={{ display: "flex", gap: 6, marginTop: 8, flexWrap: "wrap" }}>
                <Badge tone={phaseTone(scan.phase)}>{scan.phase.replace(/_/g, " ")}</Badge>
                <Badge tone={scan.status === "running" || scan.status === "completed" ? "green" : "amber"}>{scan.status}</Badge>
                <Badge tone={scan.scope_validated ? "green" : "amber"}>
                  scope {scan.scope_validated ? "validated" : "pending"}
                </Badge>
              </div>
              {scan.error && <div style={{ fontSize: 11, color: "var(--red)", marginTop: 8 }}>{scan.error}</div>}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10 }}>
              {Object.entries(scan.progress ?? {}).length ? (
                Object.entries(scan.progress).slice(0, 12).map(([k, v]) => (
                  <Meter key={k} label={k.replace(/_/g, " ")} value={v} tone={v >= 100 ? "green" : "accent"} />
                ))
              ) : (
                <div style={{ gridColumn: "1 / -1" }}>
                  <VizEmpty title="No scanner has reported progress" note="The runner writes progress per scanner; an empty map means none reported." height={64} />
                </div>
              )}
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ flex: "1 1 320px" }}>
              <VizEmpty
                title="No integrated scan recorded"
                note="Submit a scan to create a scan id. It runs as a job; this screen reads its state, it does not advance it."
                height={64}
              />
            </div>
            <button type="button" className="btn btn-primary" onClick={() => void startScan()} disabled={starting}>
              {starting ? "Submitting…" : "Start scan"}
            </button>
          </div>
        )}
        {scan && (
          <div style={{ marginTop: 12 }}>
            <button type="button" className="btn" onClick={() => void startScan()} disabled={starting}>
              {starting ? "Submitting…" : "Start another scan"}
            </button>
          </div>
        )}
      </Panel>

      {/* ── deltas + events ────────────────────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12, marginTop: 12 }}>
        <Panel
          title="Deltas observed on this screen"
          sub={`${changes.length} recorded · ${recentChanges} in the last 5m · local poll-to-poll diff, not a server claim`}
        >
          {changes.length ? (
            <div style={{ maxHeight: 300, overflowY: "auto" }}>
              <table className="tbl" style={{ width: "100%", fontSize: 11.5 }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: "left" }}>Observed</th>
                    <th style={{ textAlign: "left" }}>Domain</th>
                    <th style={{ textAlign: "right" }}>From → to</th>
                    <th style={{ textAlign: "right" }}>Δ</th>
                    <th style={{ textAlign: "left" }}>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {changes.slice(0, 25).map((c) => (
                    <tr key={c.id}>
                      <td className="mono" style={{ whiteSpace: "nowrap" }}>{timeAgo(c.ts)} ago</td>
                      <td>{DOMAIN_META[c.domain]?.label ?? c.domain}</td>
                      <td className="mono" style={{ textAlign: "right" }}>{c.from} → {c.to}</td>
                      <td style={{ textAlign: "right" }}><DeltaChip value={c.delta} /></td>
                      <td><Badge tone={c.severity === "critical" ? "red" : c.severity === "warn" ? "amber" : "green"}>{c.severity}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <VizEmpty
              title="No delta yet"
              note={`A delta is recorded only when two reads return different counts. Nothing has changed in ${collected} read(s).`}
            />
          )}
        </Panel>

        <Panel
          title="Estate events"
          sub={`${events.length} newest retained event(s) · ${rt.connected ? "streamed over SSE" : "polled, stream not connected"}`}
        >
          {events.length ? (
            <div style={{ maxHeight: 300, overflowY: "auto" }}>
              <table className="tbl" style={{ width: "100%", fontSize: 11.5 }}>
                <thead>
                  <tr>
                    <th style={{ textAlign: "left" }}>Age</th>
                    <th style={{ textAlign: "left" }}>Type</th>
                    <th style={{ textAlign: "left" }}>Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td className="mono" style={{ whiteSpace: "nowrap" }}>{timeAgo(e.ts)} ago</td>
                      <td className="mono" style={{ wordBreak: "break-all" }}>{e.type}</td>
                      <td><Badge tone={sevTone(severityOf(e.type))}>{severityOf(e.type)}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <VizEmpty
              title={rt.connected ? "No estate event retained" : "Event stream not connected"}
              note={rt.connected
                ? "The stream is open and has delivered no estate event. An open stream is not evidence of activity."
                : "Open the stream by signing in on this screen; until then this list is a read of stored events, not a live feed."}
            />
          )}
        </Panel>
      </div>

      {/* ── run history ────────────────────────────────────────────── */}
      <Panel
        title="Scan run history"
        sub={`${runs.length} durable run(s) · ${(history.data as { source?: string } | null)?.source === "live" ? "read from the backend" : "backend did not answer"}`}
      >
        {runs.length ? (
          <div style={{ maxHeight: 300, overflowY: "auto" }}>
            <table className="tbl" style={{ width: "100%", fontSize: 11.5 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left" }}>Run</th>
                  <th style={{ textAlign: "left" }}>Phase</th>
                  <th style={{ textAlign: "left" }}>Status</th>
                  <th style={{ textAlign: "left" }}>Started</th>
                  <th style={{ textAlign: "left" }}>Duration</th>
                </tr>
              </thead>
              <tbody>
                {runs.slice(0, 12).map((r) => {
                  const secs = r.started_at && r.ended_at
                    ? Math.max(0, Math.round((new Date(r.ended_at).getTime() - new Date(r.started_at).getTime()) / 1000))
                    : null;
                  const longest = runs.reduce((acc, x) => {
                    const s = x.started_at && x.ended_at
                      ? Math.max(0, Math.round((new Date(x.ended_at).getTime() - new Date(x.started_at).getTime()) / 1000))
                      : 0;
                    return Math.max(acc, s);
                  }, 0);
                  return (
                    <tr key={r.scan_id}>
                      <td className="mono">{r.scan_id.slice(0, 12)}…</td>
                      <td><Badge tone={phaseTone(r.phase ?? "completed")}>{(r.phase ?? "—").replace(/_/g, " ")}</Badge></td>
                      <td><Badge tone={r.status === "completed" ? "green" : r.status === "failed" ? "red" : "amber"}>{r.status}</Badge></td>
                      <td style={{ color: "var(--dim)" }}>{r.started_at ? `${timeAgo(r.started_at)} ago` : "—"}</td>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <span style={{ flex: 1, height: 5, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: 2, overflow: "hidden" }}>
                            <span style={{ display: "block", height: "100%", width: `${longest ? ((secs ?? 0) / longest) * 100 : 0}%`, background: "var(--accent)" }} />
                          </span>
                          <span className="mono" style={{ minWidth: 40, textAlign: "right" }}>{secs === null ? "—" : `${secs}s`}</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <VizEmpty
            title={(history.data as { source?: string } | null)?.source === "live" ? "No run recorded" : "History not available"}
            note={(history.data as { source?: string } | null)?.source === "live"
              ? "No integrated scan has completed against this tenant."
              : "The read failed; this is not a claim that no run exists."}
          />
        )}
      </Panel>
    </div>
  );
}
