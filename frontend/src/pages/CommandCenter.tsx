import React, { useEffect, useState } from "react";
import { Panel, Badge, Bar, Kpi, Feed, PageHead, Code } from "../components/ui.jsx";
import { globalState, events, risk } from "../data/demo.js";
import { apiScope, apiStatsSummary, apiDeliveries, isBackendLive, ApiResult, LiveBadge } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent } from "../lib/realtime.js";

export default function CommandCenter() {
  const g = globalState;
  const [backend, setBackend] = useState<boolean | null>(null);
  const [scope, setScope] = useState<ApiResult<Record<string, unknown>>>({ source: "demo", data: null });
  const rt = useRealtime();

  useEffect(() => {
    void isBackendLive().then(setBackend);
    void apiScope().then(setScope);
  }, []);

  // Live operational counts straight from the platform database (polled).
  const liveStats = usePollingApi(apiStatsSummary, 15000);
  const liveDeliveries = usePollingApi(apiDeliveries, 20000);
  const ls = (liveStats.data ?? {}) as Record<string, number>;
  const dStats = ((liveDeliveries.data as Record<string, unknown> | null)?.stats ?? {}) as Record<string, number>;

  /* realtime feed — live stream events when connected, demo baseline otherwise */
  const liveFeed = rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 6).map((e) => ({
    t: new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false }),
    tag: e.type.replace(/^(platform|monitor|demo)\./, "").replace(/_/g, " ").slice(0, 22).toUpperCase(),
    text: String(e.payload?.detail || e.payload?.target || ""),
    severity: severityOf(e.type),
  }));
  const feed = rt.connected ? liveFeed : events.slice(0, 6).map((e) => ({ ...e, severity: e.severity || "LOW" }));

  return (
    <>
      <PageHead
        crumb="command center"
        title="Command center"
        sub="Global security state across network, cloud, vendor, hardware and cryptography"
        right={
          <>
            {backend === null && <Badge>PROBING BACKEND…</Badge>}
            {backend === true && <Badge tone="green"><span className="dot" /> CONTROL PLANE: LIVE</Badge>}
            {backend === false && <Badge tone="amber"><span className="dot" /> CONTROL PLANE: OFFLINE (DEMO DATA)</Badge>}
            <Badge tone="green"><span className="dot" /> ALL SCANNERS NOMINAL</Badge>
            <Badge tone="violet">PQC {g.pqcReadyPct}% READY</Badge>
          </>
        }
      />

      {scope.data && (
        <Panel title="Platform scope (live manifest)" sub={scope.source === "live" ? "GET /api/v1/platform/scope — served by the control plane" : "demo manifest — backend offline"} className="mt">
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

      {/* global security state */}
      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <Panel title="Assets" sub="total inventory">
          <div className="grad-text" style={{ fontSize: 44, fontWeight: 700 }}>{g.totalAssets.toLocaleString()}</div>
          <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>+312 this week · 611 new endpoints</div>
        </Panel>
        <Panel title="Crypto assets" sub="algorithms · certs · keys · libraries">
          <div className="grad-text" style={{ fontSize: 44, fontWeight: 700 }}>{g.cryptoAssets.toLocaleString()}</div>
          <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>42391 crypto assets · 184 unknown</div>
        </Panel>
        <Panel title="Risks" sub="active findings">
          <div className="grad-text" style={{ fontSize: 44, fontWeight: 700 }}>{g.risks.toLocaleString()}</div>
          <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>
            <Badge tone="red">42 CRITICAL</Badge> <Badge tone="red">184 HIGH</Badge>
          </div>
        </Panel>
      </div>

      {/* readiness bars */}
      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Panel title="PQC readiness" sub="executive posture">
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {[
              { k: "PQC ready", v: g.pqcReadyPct, tone: "green" },
              { k: "Hybrid ready", v: g.hybridReadyPct, tone: "violet" },
              { k: "Migration required", v: g.migrationRequiredPct, tone: "red" },
            ].map((r) => (
              <div key={r.k}>
                <div className="spread" style={{ marginBottom: 4, fontSize: 13 }}>
                  <span>{r.k}</span><span className="mono">{r.v}%</span>
                </div>
                <Bar value={r.v / 100} tone={r.tone} />
              </div>
            ))}
          </div>
        </Panel>
        <Panel title="Live environment" sub="five domains, one graph">
          <div style={{ display: "flex", flexDirection: "column", gap: 8, fontFamily: "var(--mono)", fontSize: 13 }}>
            <div className="spread"><span>Network</span><Badge tone="green">611 assets</Badge></div>
            <div className="spread"><span>Cloud</span><Badge tone="green">318 resources</Badge></div>
            <div className="spread"><span>Vendor</span><Badge tone="green">14 vendors</Badge></div>
            <div className="spread"><span>Hardware</span><Badge tone="green">259 devices</Badge></div>
            <div className="spread"><span>Cryptography</span><Badge tone="red">HIGH RISK</Badge></div>
          </div>
        </Panel>
      </div>

      {/* kpi strip */}
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Panel title="Telemetry" sub="24h window">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="active scanners" v={`${g.activeScanners}/${g.totalScanners}`} tone="green" />
            <Kpi k="scanner health" v={`${g.scannerHealthPct}%`} tone="green" />
            <Kpi k="agents" v={`${g.agentsHealthy}/${g.agentsTotal}`} tone="green" />
            <Kpi k="events / sec" v={g.eventsPerSec} tone="cyan" />
          </div>
        </Panel>
        <Panel title="Findings" sub="evidence-linked">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="critical findings" v={g.criticalFindings} tone="red" />
            <Kpi k="high findings" v={g.highFindings} tone="red" />
            <Kpi k="live changes (24h)" v={g.liveChanges24h} tone="amber" />
            <Kpi k="evidence health" v={`${g.evidenceHealthPct}%`} tone="green" />
          </div>
        </Panel>
        <Panel title="Migration" sub="post-quantum program">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Kpi k="PQC exposure" v={`${g.pqcExposurePct}%`} tone="red" />
            <Kpi k="migration progress" v={`${g.migrationProgressPct}%`} tone="cyan" />
            <Kpi k="CBOM status" v={`v${g.cbomVersion}`} tone="green" />
            <Kpi k="HBOM status" v={`v${g.hbomVersion}`} tone="green" />
          </div>
        </Panel>
        <Panel title="Risk distribution" sub="portfolio">
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {Object.entries(risk.counts).map(([lv, n]) => (
              <div key={lv} className="spread">
                <Badge tone={lv === "CRITICAL" || lv === "HIGH" ? "red" : lv === "MEDIUM" ? "amber" : "green"}>{lv}</Badge>
                <span className="mono">{n}</span>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* live change alerts */}
      <div className="grid cols-2">
        <Panel title="Live changes" sub={rt.connected ? "realtime SSE stream" : "recent events (demo)"}>
          <Feed items={feed} />
        </Panel>
        <Panel title="Drift watch" sub={rt.connected ? "baseline vs live — updated by stream events" : "baseline vs live (demo)"}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { k: "Network", added: 1, removed: 0, detail: "sw-dc-03 joined" },
              { k: "Cryptography", added: 1, removed: 0, detail: "ML-KEM-768 now active" },
              { k: "Firmware", added: 0, removed: 0, detail: "fw-edge-01 PAN-OS 11.1.1 → 11.1.2" },
              { k: "PQC readiness", added: 1, removed: 0, detail: "HYBRID_READY → PQC_READY" },
            ].map((d) => (
              <div className="spread" key={d.k} style={{ fontSize: 13 }}>
                <span>{d.k}</span>
                <span className="dim">{d.detail}</span>
                <Badge tone={d.added ? "red" : "green"}>{d.added ? `+${d.added}` : "clean"}</Badge>
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

function LiveStat({ label, value, tone }: { label: string; value: number; tone?: "green" | "red" }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", minWidth: 120 }}>
      <span className="mono" style={{ fontSize: 28, fontWeight: 700, color: tone === "red" ? "var(--red)" : tone === "green" ? "var(--green)" : "var(--text)" }}>
        {value.toLocaleString()}
      </span>
      <span className="dim" style={{ fontSize: 11.5, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</span>
    </div>
  );
}
