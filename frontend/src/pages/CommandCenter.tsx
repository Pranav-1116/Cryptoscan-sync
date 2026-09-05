import React, { useEffect, useState } from "react";
import { Panel, Badge, Bar, Kpi, Feed, PageHead, Code } from "../components/ui.jsx";
import { globalState, events, risk, networkAssets, cloudResources, vendors, hardware } from "../data/initial.js";
import { apiScope, apiStatsSummary, apiDeliveries, isBackendLive, apiLiveScanStatus, apiLiveAlerts, ApiResult, LiveBadge, LiveScanStatus, LiveAlertsResponse } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent } from "../lib/realtime.js";

export default function CommandCenter() {
  const g = globalState;
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
  const lastScanEvent = rt.events.find((e) => e.type === "live_scan.completed");
  const liveAlerts = usePollingApi(apiLiveAlerts, 6000);
  const alx = (liveAlerts.data ?? null) as LiveAlertsResponse | null;
  const ls = (liveStats.data ?? {}) as Record<string, number>;
  const dStats = ((liveDeliveries.data as Record<string, unknown> | null)?.stats ?? {}) as Record<string, number>;

  /* realtime feed — shows only events streamed live from the control plane */
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
            {backend === false && <Badge tone="amber"><span className="dot" /> CONTROL PLANE: OFFLINE — SIGN IN TO LOAD LIVE DATA</Badge>}
            <Badge tone="green"><span className="dot" /> ALL SCANNERS NOMINAL</Badge>
            <Badge tone="violet">PQC {g.pqcReadyPct}% READY</Badge>
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
            <LiveStat label="scanners OK" value={Number(lsx.ok_count ?? 0)} tone="green" />
            <LiveStat label="scanners failed" value={Number(lsx.failed_count ?? 0)} tone={lsx.failed_count ? "red" : "green"} />
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

      {/* global security state */}
      <div className="grid cols-3" style={{ marginBottom: 16 }}>
        <Panel title="Assets" sub="total inventory">
          <div className="grad-text" style={{ fontSize: 44, fontWeight: 700 }}>{g.totalAssets.toLocaleString()}</div>
          <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>{g.totalAssets === 0 ? "no assets discovered — run discovery" : "live inventory"}</div>
        </Panel>
        <Panel title="Crypto assets" sub="algorithms · certs · keys · libraries">
          <div className="grad-text" style={{ fontSize: 44, fontWeight: 700 }}>{g.cryptoAssets.toLocaleString()}</div>
          <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>{g.cryptoAssets === 0 ? "no crypto inventory yet — run a scan" : "from live scans"}</div>
        </Panel>
        <Panel title="Risks" sub="active findings">
          <div className="grad-text" style={{ fontSize: 44, fontWeight: 700 }}>{g.risks.toLocaleString()}</div>
          <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>
            <Badge tone="red">{g.criticalFindings} CRITICAL</Badge> <Badge tone="red">{g.highFindings} HIGH</Badge>
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
        <Panel title="Live environment" sub="five domains, one graph — populated by discovery">
          <div style={{ display: "flex", flexDirection: "column", gap: 8, fontFamily: "var(--mono)", fontSize: 13 }}>
            <div className="spread"><span>Network</span><Badge tone={networkAssets.length ? "green" : ""}>{networkAssets.length} assets</Badge></div>
            <div className="spread"><span>Cloud</span><Badge tone={cloudResources.length ? "green" : ""}>{cloudResources.length} resources</Badge></div>
            <div className="spread"><span>Vendor</span><Badge tone={vendors.length ? "green" : ""}>{vendors.length} vendors</Badge></div>
            <div className="spread"><span>Hardware</span><Badge tone={hardware.length ? "green" : ""}>{hardware.length} devices</Badge></div>
            <div className="spread"><span>Cryptography</span><Badge tone={g.risks > 0 ? "red" : ""}>{g.risks > 0 ? "FINDINGS" : "no findings yet"}</Badge></div>
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

function LiveStat({ label, value, tone }: { label: string; value: number | string; tone?: "green" | "red" | "cyan" | "" }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", minWidth: 120 }}>
      <span className="mono" style={{ fontSize: 28, fontWeight: 700, color: tone === "red" ? "var(--red)" : tone === "green" ? "var(--green)" : tone === "cyan" ? "var(--cyan, var(--accent))" : "var(--text)" }}>
        {typeof value === "number" ? value.toLocaleString() : value}
      </span>
      <span className="dim" style={{ fontSize: 11.5, textTransform: "uppercase", letterSpacing: 0.5 }}>{label}</span>
    </div>
  );
}
