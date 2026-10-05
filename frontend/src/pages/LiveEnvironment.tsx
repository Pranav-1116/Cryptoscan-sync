import React, { useState } from "react";
import { Panel, Badge, PageHead, Table } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, useRealtimeRefresh, severityOf, isSystemEvent } from "../lib/realtime.js";
import { IconNetwork, IconHardware, IconTenant, IconCrypto, IconCode, IconCertificate, IconEstate, type Icon } from "../components/icons";
import {
  apiLiveEnvironment, apiLiveOrchestratorStart, apiLiveOrchestratorStatus, apiLiveOrchestratorHistory,
  LiveEnvironmentResponse, OrchestratorScan, ScanRunSummary,
} from "../lib/api.js";

/* LIVE ENVIRONMENT — one graph across network, cloud, vendor, hardware,
   cryptography and applications. Every value comes from the unified
   /live/environment aggregate: the same inventory, the same correlation graph
   and the same live event stream the whole platform shares. The SCAN
   ORCHESTRATOR gives every integrated run ONE global scan id and a phase state
   machine (discovery → correlation → risk calculation → live monitoring). */

const phaseTone = (phase: string) =>
  phase === "live_monitoring" ? "green" : phase === "completed" ? "green" : phase === "failed" ? "red" : "amber";

const sevTone = (s: string) =>
  s === "CRITICAL" ? "red" : s === "HIGH" ? "amber" : s === "MEDIUM" ? "amber" : "green";

function timeAgo(ts: string): string {
  const d = Math.max(0, Date.now() - new Date(ts).getTime());
  if (!ts || Number.isNaN(d)) return "—";
  if (d < 1000) return "now";
  if (d < 60_000) return `${Math.floor(d / 1000)}s`;
  if (d < 3600_000) return `${Math.floor(d / 60_000)}m`;
  return `${Math.floor(d / 3600_000)}h`;
}

export default function LiveEnvironment() {
  const lt = usePollingApi(apiLiveEnvironment, 6000);
  const status = usePollingApi(apiLiveOrchestratorStatus, 6000);
  const history = usePollingApi(apiLiveOrchestratorHistory, 9000);
  useRealtimeRefresh(lt.run, status.run, history.run);
  const rt = useRealtime();

  const [starting, setStarting] = useState(false);
  const env: LiveEnvironmentResponse | null = lt.data ?? null;
  const scan: OrchestratorScan | null = env?.scan ?? status.data?.scan ?? null;

  const domains = env?.domains ?? { network: 0, hardware: 0, vendor: 0, crypto: 0, certificate: 0, application: 0, total: 0 };
  const graph = env?.graph ?? {};
  const events = (env?.events?.events ?? []).filter((e) => !isSystemEvent(e.type)).slice(0, 6);
  const runs: ScanRunSummary[] = history.data?.runs ?? [];
  const live = lt.source === "live";
  const hasData = domains.total > 0 || (graph.node_count ?? 0) > 0;

  const startScan = async () => {
    setStarting(true);
    try {
      await apiLiveOrchestratorStart();
      setTimeout(() => { lt.run(); status.run(); }, 500);
    } finally {
      setStarting(false);
    }
  };

  const domainTiles: { name: string; icon: Icon; value: number; active: boolean }[] = [
    { name: "Network", icon: IconNetwork, value: domains.network, active: domains.network > 0 },
    { name: "Hardware", icon: IconHardware, value: domains.hardware, active: domains.hardware > 0 },
    { name: "Vendor", icon: IconTenant, value: domains.vendor, active: domains.vendor > 0 },
    { name: "Cryptography", icon: IconCrypto, value: domains.crypto, active: domains.crypto > 0 },
  ];

  return (
    <>
      <PageHead
        crumb="command center / live environment"
        title="Live environment"
        sub="One graph across network, cloud, vendor, hardware, cryptography and applications — one integrated scan, one global scan id"
        right={
          <>
            <Badge tone={live ? "green" : ""}><span className="dot" /> {live ? (rt.connected ? "SSE LIVE" : "LIVE") : "OFFLINE"}</Badge>
            {scan?.scope_validated ? <Badge tone="green">SCOPE: AUTHORIZED</Badge> : <Badge tone="amber">SCOPE: EMPTY</Badge>}
          </>
        }
      />

      {/* SCAN ORCHESTRATOR — the "one product" control flow */}
      <Panel title="Scan orchestrator" sub="one global scan id · scope & credential gated · real scanners">
        {scan ? (
          <div className="row" style={{ gap: 18, flexWrap: "wrap", alignItems: "center" }}>
            <div>
              <div className="kicker">global scan id</div>
              <div className="mono" style={{ fontSize: 18, fontWeight: 700 }}>{scan.scan_id}</div>
              <div className="dim" style={{ fontSize: 12 }}>{scan.org_name || "—"} · started {timeAgo(scan.started_at)}</div>
            </div>
            <div>
              <div className="kicker">phase</div>
              <Badge tone={phaseTone(scan.phase)}>{scan.phase.replace(/_/g, " ")}</Badge>
              <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>status: {scan.status}</div>
            </div>
            <div className="kpi-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", gap: 10, flex: 1 }}>
              {Object.entries(scan.progress || {}).slice(0, 8).map(([k, v]) => (
                <div key={k} style={{ minWidth: 110 }}>
                  <div className="dim" style={{ fontSize: 11, marginBottom: 3 }}>{k}</div>
                  <div className="bar-row" style={{ height: 8, background: "var(--line)", borderRadius: "var(--r)", overflow: "hidden" }}>
                    <div className="bar" style={{ width: `${v}%`, height: "100%", background: v >= 100 ? "var(--green)" : "var(--amber)" }} />
                  </div>
                  <div className="num" style={{ fontSize: 11, marginTop: 2 }}>{v}%</div>
                </div>
              ))}
              {!(scan.progress && Object.keys(scan.progress).length) && <div className="dim" style={{ fontSize: 12 }}>awaiting first scanner…</div>}
            </div>
            <button className="btn btn-primary" disabled={starting} onClick={startScan} style={{ padding: "7px 14px" }}>Restart scan</button>
          </div>
        ) : (
          <div className="row" style={{ gap: 14, alignItems: "center", flexWrap: "wrap" }}>
            <div className="dim" style={{ fontSize: 13, flex: 1 }}>
              {status.source === "live" ? "No integrated scan run yet — start one to discover the authorized scope in one pass." : "Backend offline — orchestrator unavailable."}
            </div>
            <button className="btn btn-primary" disabled={starting} onClick={startScan} style={{ padding: "7px 14px" }}>{starting ? "Starting…" : "Start integrated scan"}</button>
          </div>
        )}
      </Panel>

      <Panel title="Unified environment map" sub="every domain feeds the same pipeline — evidence → normalization → identity → graph → CBOM/HBOM/SBOM → risk → PQC → live state">
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14, padding: "18px 0 8px", overflowX: "auto" }}>
          <div className="row" style={{ justifyContent: "center", gap: 16, flexWrap: "wrap" }}>
            {domainTiles.map((d) => <EnvNode key={d.name} name={d.name} icon={d.icon} count={d.value} active={d.active} />)}
          </div>
          <svg width="560" height="26"><path d="M70 0 v14 H280 v-14" stroke="color-mix(in srgb, var(--accent) 50%, transparent)" fill="none" /><path d="M210 0 v14" stroke="color-mix(in srgb, var(--accent) 50%, transparent)" fill="none" /><path d="M490 0 v14 H280 v-14" stroke="color-mix(in srgb, var(--accent) 50%, transparent)" fill="none" /></svg>
          <div className="row" style={{ justifyContent: "center", gap: 16, flexWrap: "wrap" }}>
            <EnvNode name="Applications" icon={IconCode} count={domains.application} active={domains.application > 0} />
            <EnvNode name="Certificates" icon={IconCertificate} count={domains.certificate} active={domains.certificate > 0} />
            <EnvNode name="Total estate" icon={IconEstate} count={domains.total} active={domains.total > 0} />
          </div>
        </div>
        <div className="dim" style={{ fontSize: 12, textAlign: "center", marginTop: 4 }}>
          correlation graph · {graph.node_count ?? 0} nodes / {graph.edge_count ?? 0} edges
          {graph.by_kind ? ` · ${Object.entries(graph.by_kind).map(([k, v]) => `${k} ${v}`).join(", ")}` : ""} · {graph.backend ? `backend ${graph.backend}` : "backend (in-memory)"}
        </div>
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Live events" sub="real state changes streamed over SSE">
          {events.length ? (
            <div className="feed">
              {events.map((e) => (
                <div key={e.id} className="feed-row" style={{ display: "flex", gap: 8, alignItems: "center", padding: "5px 0", fontSize: 13 }}>
                  <Badge tone={sevTone(severityOf(e.type))}>{severityOf(e.type)}</Badge>
                  <span className="mono" style={{ flex: 1 }}>{e.type}</span>
                  <span className="dim" style={{ fontSize: 12 }}>{timeAgo(e.ts)}</span>
                </div>
              ))}
            </div>
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>{rt.connected ? "No live events yet — run a scan." : "Backend offline — no event stream."}</div>
          )}
          <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>{env?.events ? `${env.events.latest_id} events buffered · ${env.events.subscribers} subscriber(s)` : ""}</div>
        </Panel>
        <Panel title="Dependency topology" sub="interactive graph — click any asset for full detail">
          <Table
            head={["asset kind", "count"]}
            rows={Object.entries(graph.by_kind ?? {}).map(([k, v]) => [<span key={k} className="mono">{k}</span>, v])}
          />
          <a className="mono" href="#/graph" style={{ fontSize: 12, display: "inline-block", marginTop: 10 }}>open full dependency graph →</a>
          {!hasData && (
            <div className="dim" style={{ fontSize: 12.5, marginTop: 12, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
              Hierarchy populates from onboarding scope and discovery. Configure your estate in <a href="#/onboarding">Onboarding</a>, then run an integrated scan.
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Scan run history" sub="rebuilt from the durable platform event log — survives restarts, visible from any worker">
        {runs.length ? (
          <Table
            head={["run", "phase", "status", "started", "duration", "scope", "error"]}
            rows={runs.map((r) => [
              <span key={r.scan_id} className="mono" style={{ fontSize: 12 }}>{r.scan_id}</span>,
              <Badge key="p" tone={phaseTone(r.phase ?? "completed")}>{(r.phase ?? "—").replace(/_/g, " ")}</Badge>,
              <Badge key="s" tone={r.status === "completed" ? "green" : r.status === "failed" ? "red" : "amber"}>{r.status}</Badge>,
              <span key="t" className="dim" style={{ fontSize: 12 }}>{r.started_at ? timeAgo(r.started_at) : "—"}</span>,
              <span key="d" className="dim" style={{ fontSize: 12 }}>
                {r.started_at && r.ended_at ? `${Math.max(0, Math.round((new Date(r.ended_at).getTime() - new Date(r.started_at).getTime()) / 1000))}s` : "—"}
              </span>,
              r.scope_validated == null ? <span key="v" className="dim" style={{ fontSize: 12 }}>—</span>
                : <Badge key="v" tone={r.scope_validated ? "green" : "red"}>{r.scope_validated ? "yes" : "no"}</Badge>,
              <span key="e" className="dim" style={{ fontSize: 12 }}>{r.error ?? "—"}</span>,
            ])}
          />
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>
            {history.source === "live" ? "No integrated scans run yet — start one above to record history." : "Backend offline — run history unavailable."}
          </div>
        )}
      </Panel>
    </>
  );
}

function EnvNode({ name, icon: I, count, active }: { name: string; icon: Icon; count: number; active?: boolean }) {
  return (
    <div className="frame" style={{
      border: "1px solid var(--line-strong)", borderRadius: "var(--r)", padding: "14px 26px",
      background: "color-mix(in srgb, var(--bg) 60%, transparent)", opacity: active ? 1 : 0.55, textAlign: "center", minWidth: 150,
    }}>
      <div style={{ color: "var(--accent)", lineHeight: 0 }}><I size={24} /></div>
      <div style={{ fontWeight: 700, fontSize: 15, marginTop: 4 }}>{name}</div>
      <div className="mono faint" style={{ fontSize: 11 }}>{count.toLocaleString()}</div>
    </div>
  );
}
