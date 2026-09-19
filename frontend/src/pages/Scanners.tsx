import React, { useEffect, useMemo, useRef, useState } from "react";
import { Panel, Badge, Table, PageHead, Kpi } from "../components/ui.jsx";
import {
  apiDiscover, apiControlAgents, apiLiveScanStatus,
  ApiResult, LiveScanStatus,
} from "../lib/api.js";
import { useLive, LiveStatus } from "../lib/useLive.js";
import { useRealtime } from "../lib/realtime.jsx";
import { useI18n } from "../i18n/I18n.jsx";

/* Scanner control center — the deterministic §1 discovery platform.
   Every element reflects a live backend response:
   • pipeline stepper = the fixed Discover→Identify→Correlate→Verify→Monitor
     stages the universal engine actually executes (no fake progress).
   • five-domain cards  = the domains a discover run exercised (sources_run).
   • scan progress      = /live-scan/status + live_scan.* SSE ticks.
   • plugin registry    = /discovery/plugins (health + capabilities).
   Nothing is simulated: a brand-new tenant sees honest empty states. */

interface Plugin {
  plugin_id: string;
  plugin_version?: string;
  capabilities?: string[];
  health?: { ok?: boolean; detail?: string };
}
interface MonitorStatus {
  overview?: { targets_total?: number; by_type?: Record<string, number>; enabled?: number };
  needs_attention?: unknown[];
}
interface DiscoverReport {
  asset_count?: number;
  relationship_count?: number;
  sources_run?: string[];
  monitor_plan?: Array<{ domain: string; targets: string[]; cadence_seconds: number }>;
  verified?: Record<string, boolean>;
  generated_at?: string;
}

const PIPELINE = [
  { key: "discover", glyph: "⬚", titleKey: "scanners.stageDiscover", sub: "domain adapters" },
  { key: "identify", glyph: "◈", titleKey: "scanners.stageIdentify", sub: "stable identity" },
  { key: "correlate", glyph: "⌗", titleKey: "scanners.stageCorrelate", sub: "cross-domain links" },
  { key: "verify", glyph: "✓", titleKey: "scanners.stageVerify", sub: "source · type" },
  { key: "monitor", glyph: "◉", titleKey: "scanners.stageMonitor", sub: "24/7 cadence" },
] as const;

const DOMAINS = [
  { key: "network", glyph: "◈", nameKey: "scanners.domainNetwork", mode: "passive / active" },
  { key: "cloud", glyph: "☁", nameKey: "scanners.domainCloud", mode: "read-only" },
  { key: "hardware", glyph: "⌬", nameKey: "scanners.domainHardware", mode: "HSM · TPM · CPU" },
  { key: "vendor", glyph: "▤", nameKey: "scanners.domainVendor", mode: "metadata" },
  { key: "crypto", glyph: "⚿", nameKey: "scanners.domainCrypto", mode: "cert · library" },
] as const;

const SCANNER_LABEL: Record<string, string> = {
  hardware: "Hardware (CPU / TPM / HSM)",
  runtime: "Runtime host crypto",
  network: "Network TLS probe",
  container: "Container / image",
  ot: "OT / ICS (passive logs)",
  cloud: "Cloud (read-only live)",
  source: "Static source (crypto API)",
  universal: "Universal crypto",
};

export default function Scanners() {
  const { t } = useI18n();
  const plugins = useLive<{ plugins: Plugin[] }>("/api/v1/discovery/plugins", { plugins: [] });
  const monitor = useLive<MonitorStatus>("/api/v1/monitor/status", {});
  const realtime = useRealtime();

  const [agents, setAgents] = useState<any[]>([]);
  const [report, setReport] = useState<DiscoverReport | null>(null);
  const [reportError, setReportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scan, setScan] = useState<LiveScanStatus | null>(null);
  const [runningNow, setRunningNow] = useState<Set<string>>(new Set());
  const seenEv = useRef<Set<number>>(new Set());

  // ── agents (control plane) ──────────────────────────────────────────────
  useEffect(() => {
    void apiControlAgents().then((r) => {
      if (r.ok && r.data) {
        const d = r.data as any;
        setAgents(d.agents ?? (Array.isArray(d) ? d : []));
      }
    });
  }, []);

  // ── live scanner status (poll backstop) ─────────────────────────────────
  const refreshScan = async () => {
    const r = await apiLiveScanStatus();
    if (r.ok && r.data) {
      setScan(r.data as LiveScanStatus);
      if (!r.data.running) setRunningNow(new Set());
    }
  };
  useEffect(() => {
    refreshScan();
    const id = setInterval(refreshScan, 4000);
    return () => clearInterval(id);
  }, []);

  // ── live_scan.* SSE → pipeline / progress state ─────────────────────────
  useEffect(() => {
    for (const ev of realtime.events) {
      if (seenEv.current.has(ev.id)) continue;
      let type = ev.type;
      if (type.startsWith("monitor.live_scan_")) {
        type = "live_scan." + type.slice("monitor.live_scan_".length);
      }
      if (!type.startsWith("live_scan.") && type !== "platform.discovery_completed") continue;
      seenEv.current.add(ev.id);
      const p = ev.payload || {};
      if (type === "live_scan.scanner_started") {
        setRunningNow((prev) => new Set(prev).add(String(p.scanner)));
      } else if (type === "live_scan.scanner_completed" || type === "live_scan.completed") {
        if (type === "live_scan.completed") setRunningNow(new Set());
        else setRunningNow((prev) => {
          const n = new Set(prev); n.delete(String(p.scanner)); return n;
        });
        void refreshScan();
      } else if (type === "live_scan.started") {
        const list = (p.scanners as string[]) || [];
        setRunningNow(new Set(list));
      }
    }
  }, [realtime.events]);

  // ── actions ─────────────────────────────────────────────────────────────
  const runDiscovery = async () => {
    setBusy(true);
    setReportError(null);
    const r = await apiDiscover({ network: {}, cloud: {}, vendor: {}, hardware: {}, crypto: {} });
    setBusy(false);
    if (r.ok && r.data) setReport(r.data as DiscoverReport);
    else setReportError(r.error || "Discovery did not complete.");
  };

  // ── derived state ───────────────────────────────────────────────────────
  const plugs = plugins.data.plugins ?? [];
  const healthy = plugs.filter((p) => p.health?.ok !== false).length;
  const targets = monitor.data.overview?.targets_total ?? 0;
  const ranDomains = useMemo(() => new Set(report?.sources_run ?? []), [report]);
  const verifiedValues = Object.values(report?.verified ?? {});
  const verifiedOk = verifiedValues.filter(Boolean).length;
  const hasReport = !!report && (report.asset_count ?? 0) >= 0 && !!report.generated_at;
  // pipeline stage state — derived deterministically from the report
  const stageState = (i: number): "done" | "active" | "idle" | "error" => {
    if (busy) return i === 0 ? "active" : "idle";
    if (!hasReport) return "idle";
    // after a completed run the whole deterministic pipeline has executed
    if (i <= 3) return verifiedValues.length && verifiedOk < verifiedValues.length ? "error" : "done";
    return (report?.monitor_plan?.length ?? 0) > 0 ? "done" : "idle";
  };

  const scanEntries = Object.entries(scan?.scanners ?? {});
  const ago = scan?.last_run_at
    ? Math.max(0, Math.round((Date.now() - new Date(scan.last_run_at).getTime()) / 1000))
    : null;

  return (
    <>
      <PageHead
        crumb="operate / scanners"
        title="Scanner control center"
        sub="Deterministic discovery pipeline · live scanner fleet · registered plugins — no simulation"
        right={
          <div className="row">
            <Badge tone={healthy === plugs.length && plugs.length > 0 ? "green" : "amber"}>
              <span className="dot" /> {healthy}/{plugs.length} plugins
            </Badge>
            <button className="btn sm primary" onClick={() => void runDiscovery()} disabled={busy}>
              {busy ? t("scanners.runningDiscovery") : t("scanners.runDiscovery")}
            </button>
          </div>
        }
      />
      <div style={{ marginBottom: 14 }}><LiveStatus loading={plugins.loading} error={plugins.error} /></div>

      {/* ── KPI strip ─────────────────────────────────────────────────── */}
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Kpi k="scanner plugins" v={plugs.length} tone="cyan" />
        <Kpi k="plugins healthy" v={`${healthy}/${plugs.length}`} tone={healthy === plugs.length ? "green" : "amber"} />
        <Kpi k="monitor targets" v={targets} />
        <Kpi k="agents connected" v={agents.length} tone={agents.length ? "green" : undefined} />
      </div>

      {/* ── deterministic discovery pipeline ──────────────────────────── */}
      <Panel
        title="Discovery pipeline"
        sub="The fixed five stages every unified discovery run executes (§1) — deterministic, no AI"
      >
        <div className="stepper">
          {PIPELINE.map((s, i) => {
            const st = busy ? stageState(i) : stageState(i);
            return (
              <div key={s.key} className={`step state-${st}`}>
                <div className="node">{s.glyph}</div>
                <div className="stitle">{t(s.titleKey)}</div>
                <div className="ssub">{s.sub}</div>
              </div>
            );
          })}
        </div>
        <div style={{ marginTop: 14 }}>
          {busy && (
            <p className="dim" style={{ fontSize: 12.5, margin: 0 }}>
              <Badge tone="cyan"><span className="dot pulse" /> running</Badge>{" "}
              executing domain adapters → identify → correlate → verify → monitor plan…
            </p>
          )}
          {!busy && !hasReport && (
            <p className="dim" style={{ fontSize: 12.5, margin: 0 }}>
              No discovery run in this session yet — press <b>Run discovery</b>. The pipeline stays
              idle until real scope is supplied; empty adapters are skipped, not faked.
            </p>
          )}
          {!busy && hasReport && (
            <div className="row" style={{ flexWrap: "wrap", gap: 8 }}>
              <Badge tone="green"><span className="dot" /> complete</Badge>
              <Badge tone="cyan">{report!.asset_count} assets</Badge>
              <Badge tone="blue">{report!.relationship_count} relationships</Badge>
              <Badge tone={verifiedOk === verifiedValues.length && verifiedValues.length ? "green" : "amber"}>
                {verifiedOk}/{verifiedValues.length} verified
              </Badge>
              <Badge tone="violet">{report!.monitor_plan?.length ?? 0} monitored domains</Badge>
            </div>
          )}
          {reportError && <p style={{ color: "var(--red)", fontSize: 12.5, margin: "6px 0 0" }}>{reportError}</p>}
        </div>
      </Panel>

      {/* ── five domains ──────────────────────────────────────────────── */}
      <Panel
        title="Discovery domains"
        sub="Five passive-first domains · state reflects the last live discover run"
        className="mt"
      >
        <div className="domain-grid">
          {DOMAINS.map((d) => {
            const ran = ranDomains.has(d.key);
            const plan = report?.monitor_plan?.find((m) => m.domain === d.key);
            const stateCls = ran ? "state-ran" : report ? "state-idle" : "state-target";
            return (
              <div key={d.key} className={`domain-card ${stateCls}`}>
                <div className="d-icon">{d.glyph}</div>
                <div className="d-name">{t(d.nameKey)}</div>
                <div className="d-mode">{d.mode}</div>
                <div className="d-stat">
                  {ran ? (
                    <Badge tone="green"><span className="dot" /> ran{plan ? ` · ${plan.targets.length} tgt` : ""}</Badge>
                  ) : report ? (
                    <Badge tone="slate">no input</Badge>
                  ) : (
                    <Badge tone="cyan">queued</Badge>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Panel>

      {/* ── live scanner fleet progress ───────────────────────────────── */}
      <Panel
        title="Live scanner fleet"
        sub={scan?.running
          ? "scan in progress — progress streams over SSE"
          : ago !== null
            ? `last cycle ${ago}s ago · ${scan?.ok_count ?? 0} ok / ${scan?.failed_count ?? 0} failed`
            : "no live scan cycle yet — start one in Realtime scanners"}
        className="mt"
      >
        {scanEntries.length === 0 ? (
          <p className="dim" style={{ fontSize: 13, margin: 0 }}>
            No scanner results yet. Run a live cycle (hardware & runtime run without a target) from
            Operations → Realtime scanners; results appear here and stream live on every worker.
          </p>
        ) : (
          <div className="scan-prog">
            {scanEntries.map(([key, s]) => {
              const isRunning = scan?.running || runningNow.has(key);
              const failed = s.ok === false;
              const cls = isRunning ? "is-running" : failed ? "is-failed" : "is-ok";
              const detail = s.error
                ? s.error
                : s.summary
                  ? Object.entries(s.summary)
                      .filter(([, v]) => v !== null && v !== undefined && v !== "")
                      .slice(0, 4)
                      .map(([k, v]) => `${k}=${typeof v === "boolean" ? (v ? "yes" : "no") : v}`)
                      .join("  ·  ")
                  : "";
              return (
                <div key={key} className={`scan-row ${cls}`}>
                  <div className="s-ico">
                    {isRunning ? "▶" : failed ? "✗" : "✓"}
                  </div>
                  <div className="s-meta">
                    <div className="s-name">{SCANNER_LABEL[key] ?? key}</div>
                    {detail && <div className="s-detail">{detail}</div>}
                  </div>
                  <div className="s-right">
                    {isRunning
                      ? <Badge tone="cyan"><span className="dot pulse" /> scanning</Badge>
                      : failed
                        ? <Badge tone="red">failed</Badge>
                        : <Badge tone="green">ok</Badge>}
                    {typeof s.elapsed_s === "number" && !isRunning && (
                      <span className="s-elapsed">{s.elapsed_s.toFixed(2)}s</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      {/* ── plugin registry ───────────────────────────────────────────── */}
      <Panel
        title="Registered scanner plugins"
        sub={`${plugs.length} plugins discovered · ${targets} monitor target(s)`}
        className="mt"
      >
        {plugs.length === 0 ? (
          <p className="dim" style={{ fontSize: 13 }}>
            {plugins.loading ? "Loading registered plugins…" : "No scanner plugins registered yet."}
          </p>
        ) : (
          <div className="plug-grid">
            {plugs.map((p) => {
              const bad = p.health?.ok === false;
              return (
                <div key={p.plugin_id} className="plug-card">
                  <div className="plug-head">
                    <span className="plug-id">{p.plugin_id}</span>
                    <Badge tone={bad ? "red" : "green"}>{bad ? "unhealthy" : "ok"}</Badge>
                  </div>
                  <div className="plug-ver">v{p.plugin_version ?? "—"}</div>
                  <div className="caps">
                    {(p.capabilities ?? []).map((c) => <span key={c} className="cap-chip">{c}</span>)}
                  </div>
                  {bad && p.health?.detail && (
                    <div className="s-detail" style={{ color: "var(--red)" }}>{p.health.detail}</div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      {/* ── agents + policy ───────────────────────────────────────────── */}
      <div className="grid cols-2 mt">
        <Panel title="Agents" sub={`${agents.length} registered`}>
          <Table
            head={["agent", "host", "version", "status"]}
            rows={agents.map((a) => [
              <span className="mono">{a.agent_id ?? a.id ?? "—"}</span>,
              <span className="mono">{a.host ?? a.hostname ?? "—"}</span>,
              <span className="num">{a.version ?? "—"}</span>,
              <Badge tone={a.status === "HEALTHY" || a.healthy ? "green" : "amber"}>
                {a.status ?? (a.healthy ? "HEALTHY" : "unknown")}
              </Badge>,
            ])}
          />
          {agents.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No agents connected.</p>}
        </Panel>
        <Panel title="Monitor & scan policy" sub="safe by default — read-only, scoped, scheduled">
          <div className="mono" style={{ fontSize: 12.5, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">targets monitored:</span> {targets}</div>
            <div><span className="faint">enabled:</span> {monitor.data.overview?.enabled ?? 0}</div>
            <div><span className="faint">needs attention:</span> {(monitor.data.needs_attention ?? []).length}</div>
            <div><span className="faint">policy:</span> SAFE · READ_ONLY · SCOPED</div>
            <div><span className="faint">OT:</span> PASSIVE-FIRST · SIS/ESD NEVER PROBED</div>
            <div><Badge tone="green">credentials in vault · never stored in state</Badge></div>
          </div>
        </Panel>
      </div>
    </>
  );
}
