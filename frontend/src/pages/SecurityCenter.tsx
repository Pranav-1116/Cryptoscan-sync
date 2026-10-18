import React, { useEffect, useMemo, useRef, useState } from "react";
import { Panel, Badge, Table, PageHead, Kpi, Bar, Code, Feed } from "../components/ui.jsx";
import { useLive } from "../lib/useLive.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent, useRealtimeRefresh } from "../lib/realtime.jsx";
import {
  getToken,
  tenantFetch,
  apiControlAgents,
  apiP2Plugins,
  apiP2AnomalyFlags,
  apiAuditVerify,
  apiAuditList,
  apiControlHealth,
  apiLiveInventory,
  apiMyGrants,
  apiSafeScanPolicy,
  apiSecurityPosture,
  apiSecurityPostureTrend,
  apiSecurityAlerts,
  apiAnomalyAck,
  type SecurityPosture,
  type PostureComponent,
  type PostureTrend,
  type SecurityAlert,
} from "../lib/api.js";

/* ZELNX Security Operations Center (#23, realtime) — a 24/7 SOC view of the
   control plane, driven by the backend SSE stream rather than a polled demo.

   Live surfaces:
   - server-owned posture score (GET /api/v1/security/posture/stream, SSE)
   - posture-over-time & per-signal drift (GET /api/v1/security/posture/trend)
   - unified live threat feed (GET /api/v1/security/alerts) + SSE event ticker
   - posture-drop banner when the score regresses (deterministic delta)

   Doctrine: every number comes from a real control-plane signal; an empty /
   quiet store reads low (never a fabricated green); no simulated events. */

const SEV_TONE: Record<string, string> = { CRITICAL: "red", HIGH: "red", MEDIUM: "amber", LOW: "amber", INFO: "" };

interface AgentRow {
  id?: string; status?: string; healthy?: boolean; health_ok?: boolean;
  version?: string; last_heartbeat_at?: string | null; [k: string]: unknown;
}
interface PluginRow {
  id?: string; name?: string; state?: string; verified?: boolean;
  version?: string; [k: string]: unknown;
}
interface AnomalyRow {
  id?: string; pk?: string; severity?: string; rule?: string;
  description?: string; explanation?: string; status?: string; [k: string]: unknown;
}

export default function SecurityCenter() {
  // ── realtime bone: the SSE event stream (existing provider) ──
  const rt = useRealtime();
  const postureStream = usePostureStream(30000);
  const posture = usePollingApi(() => apiSecurityPosture(), 30000, []);
  const trend = usePollingApi(() => apiSecurityPostureTrend(24, 30), 60000, []);
  const alerts = usePollingApi(() => apiSecurityAlerts(60), 20000, []);
  const agents = usePollingApi(() => apiControlAgents(), 15000, []);
  const plugins = usePollingApi(() => apiP2Plugins(), 30000, []);
  const anomaly = usePollingApi(() => apiP2AnomalyFlags(), 20000, []);
  const auditVerify = usePollingApi(() => apiAuditVerify(), 30000, []);
  const audit = usePollingApi(() => apiAuditList({ page: 1, page_size: 100 }), 30000, []);
  const health = usePollingApi(() => apiControlHealth(), 20000, []);
  const inv = usePollingApi(() => apiLiveInventory(), 20000, []);
  const grants = useLive<{ principal: string; roles: string[]; grants: Array<Record<string, unknown>>; count: number; abac_enforced: boolean }>(
    "/api/v1/control/me/grants",
    { principal: "", roles: [], grants: [], count: 0, abac_enforced: false },
  );
  const policy = usePollingApi(() => apiSafeScanPolicy(), 30000, []);
  useRealtimeRefresh(posture.run, trend.run, alerts.run, agents.run, plugins.run, anomaly.run, auditVerify.run, audit.run, health.run, inv.run, policy.run);
  const [, forceTick] = useState(0);

  const agentRows = (agents.data ?? []) as AgentRow[];
  const pluginRows = (plugins.data ?? []) as PluginRow[];
  const anomalyRows = (anomaly.data ?? []) as AnomalyRow[];
  const alertRows = (alerts.data?.alerts ?? []) as SecurityAlert[];

  const agentsHealthy = agentRows.filter((a) => a.healthy || a.health_ok).length;
  const agentsWarning = agentRows.filter((a) => !(a.healthy || a.health_ok)).length;
  const pluginsVerified = pluginRows.filter((p) => p.verified || String(p.state ?? "").toLowerCase().includes("active")).length;
  const pluginsUntrusted = pluginRows.length - pluginsVerified;
  const openThreats = anomalyRows.filter((f) => String(f.status ?? "").toUpperCase() !== "ACKNOWLEDGED").length;
  const criticalThreats = anomalyRows.filter((f) => ["CRITICAL", "HIGH"].includes(String(f.severity ?? "").toUpperCase())).length;
  const failedLogins = audit.data?.events?.filter((e) => String(e.outcome ?? "").toUpperCase() === "FAILURE" && String(e.action ?? "").includes("login")).length ?? 0;
  const certCenter = (inv.data as any)?.cert_center ?? null;
  const certTotal = Number(certCenter?.total ?? 0);
  const certValid = certTotal > 0 ? Math.max(0, Math.round(((certTotal - Number(certCenter?.expired ?? 0) - Number(certCenter?.expiring30 ?? 0)) / certTotal) * 100)) : null;
  const auditOk = auditVerify.data?.status === "OK";
  const auditEntries = audit.data?.events?.length ?? 0;

  // ── live posture: prefer the SSE stream frame, fall back to the snapshot ──
  const livePosture = postureStream.posture ?? (posture.data as SecurityPosture | null) ?? null;
  const score = livePosture?.score ?? 0;
  const components = (livePosture?.components ?? {}) as Record<string, PostureComponent>;
  const dropped = postureStream.delta.dropped || (livePosture as any)?.dropped === true;
  const scoreDelta = postureStream.delta.delta ?? (livePosture as any)?.delta ?? null;
  const scorePrevious = postureStream.delta.previous_score ?? (livePosture as any)?.previous_score ?? null;

  // ── live event feed (SSE) ──
  const liveEvents = useMemo(
    () => rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 14),
    [rt.events],
  );

  const ack = async (a: SecurityAlert) => {
    if (a.ack_href) {
      const id = a.ack_href.split("/").filter(Boolean).pop();
      if (id) await apiAnomalyAck(id);
      forceTick((n) => n + 1);
    }
  };

  return (
    <>
      <PageHead
        crumb="platform / security operations center"
        title="ZELNX Security Operations Center"
        sub="24/7 SOC — server-owned posture, posture-over-time drift, live threat feed & event stream, all from the control plane"
        right={
          <Badge tone={score >= 80 ? "green" : score >= 50 ? "amber" : "red"}>
            <span className="dot" /> {postureStream.live ? "LIVE" : posture.source === "live" ? "LIVE" : "OFFLINE"} POSTURE {score}/100
          </Badge>
        }
      />

      {dropped && (
        <div className="banner" style={{ background: "color-mix(in srgb, var(--red) 10%, transparent)", border: "1px solid var(--red)", padding: "10px 14px", borderRadius: "var(--r)" }}>
          <b>Attention — security posture regressed.</b>{" "}
          <span style={{ fontSize: 13 }}>score dropped {scorePrevious ?? "—"} → {score} (Δ {scoreDelta}). Review the live threat feed below.</span>
        </div>
      )}

      {/* Composite posture — live via SSE */}
      <Panel title="Security posture" sub="Live security posture score from the control plane" className="mt">
        <div className="kpi-strip">
          <ScoreBox score={score} live={postureStream.live || posture.source === "live"} delta={scoreDelta} />
          <Kpi k="open threats" v={livePosture?.threats_open ?? openThreats} tone={(livePosture?.threats_open ?? openThreats) ? "red" : "green"} />
          <Kpi k="critical/high" v={livePosture?.threats_critical ?? criticalThreats} tone={(livePosture?.threats_critical ?? criticalThreats) ? "red" : "green"} />
          <Kpi k="failed logins (recent)" v={livePosture?.failed_logins ?? failedLogins} tone={(livePosture?.failed_logins ?? failedLogins) ? "amber" : "green"} />
          <Kpi k="agents healthy" v={`${livePosture?.agents_healthy ?? agentsHealthy}/${livePosture?.agents_total ?? agentRows.length}`} tone={(livePosture?.agents_healthy ?? agentsHealthy) ? "green" : "amber"} />
        </div>
        <div style={{ marginTop: 14 }}>
          <div className="spread" style={{ marginBottom: 4, fontSize: 12.5 }}>
            <span>Composite control integrity</span><span className="mono">{score}%</span>
          </div>
          <Bar value={score / 100} tone={score >= 80 ? "green" : score >= 50 ? "amber" : "red"} />
        </div>
        <div className="grid cols-3" style={{ marginTop: 16 }}>
          <ComponentStat label="audit chain" c={components.audit} />
          <ComponentStat label="certificates" c={components.cert} />
          <ComponentStat label="auth" c={components.auth} />
          <ComponentStat label="threats" c={components.threat} />
          <ComponentStat label="agent fleet" c={components.fleet} />
          <ComponentStat label="plugin trust" c={components.plugin} />
        </div>
      </Panel>

      {/* Posture over time + drift */}
      <Panel title="Posture over time" sub="Security score minimum, average and maximum, with trends for each signal" className="mt">
        <PostureTrendChart trend={trend.data as PostureTrend | null} />
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Live threat feed" sub="anomaly flags · live-scan alerts · runtime findings · failed logins — triage + acknowledge">
          {alertRows.length === 0 && <div className="dim" style={{ fontSize: 13 }}>No open alerts — the platform is quiet (and stays honest about it).</div>}
          {alertRows.length > 0 && (
            <Table
              head={["severity", "source", "title", "action"]}
              rows={alertRows.slice(0, 12).map((a) => [
                <Badge tone={SEV_TONE[String(a.severity).toUpperCase()] ?? ""}>{String(a.severity)}</Badge>,
                <span className="mono" style={{ fontSize: 11 }}>{String(a.source)}</span>,
                <span>{String(a.title)}</span>,
                a.ack_href
                  ? <button className="link" onClick={() => void ack(a)}>acknowledge</button>
                  : <span className="dim" style={{ fontSize: 11 }}>—</span>,
              ])}
            />
          )}
        </Panel>
        <Panel title="Live event stream" sub={rt.conn === "live" ? "Live platform events" : `stream ${rt.conn}`}>
          {liveEvents.length === 0 && <div className="dim" style={{ fontSize: 13 }}>No platform events yet — they appear as the control plane emits them.</div>}
          {liveEvents.length > 0 && (
            <Feed items={liveEvents.map((e) => ({
              t: new Date(e.ts).toLocaleTimeString(),
              tag: severityOf(e.type),
              text: `${e.type.replace(/\./g, " · ")}`,
            }))} />
          )}
          {liveEvents.length === 0 && rt.conn === "live" && (
            <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>Connected — waiting for the next platform event.</div>
          )}
        </Panel>
      </div>

      {/* Detail panels kept live */}
      <div className="grid cols-2 mt">
        <Panel title="Agents" sub={health.source === "live" ? "enrolled scanner agents (fleet health from control plane)" : "backend offline"}>
          {agentRows.length === 0 && <div className="dim" style={{ fontSize: 13 }}>No agents enrolled yet — install an agent or run a local scan.</div>}
          <div className="mono-list">
            <Row k="healthy" v={<Badge tone="green">{agentsHealthy}</Badge>} />
            <Row k="warning / degraded" v={<Badge tone="amber">{agentsWarning}</Badge>} />
            <Row k="enrolled" v={agentRows.length} />
          </div>
        </Panel>
        <Panel title="Plugins" sub="scanner / integration plugins — trust & signature posture">
          {pluginRows.length === 0 && <div className="dim" style={{ fontSize: 13 }}>No marketplace plugins installed yet.</div>}
          <div className="mono-list">
            <Row k="verified" v={<Badge tone="green">{pluginsVerified}</Badge>} />
            <Row k="untrusted / quarantined" v={<Badge tone={pluginsUntrusted ? "red" : "green"}>{pluginsUntrusted}</Badge>} />
            <Row k="total" v={pluginRows.length} />
          </div>
        </Panel>
      </div>

      <Panel title="Audit & evidence integrity" sub="immutable hash chain + tenant isolation + approval gates" className="mt">
        <div className="mono-list">
          <Row k="audit chain" v={<Badge tone={auditOk ? "green" : "red"}>{String(auditVerify.data?.status ?? "—")}</Badge>} />
          <Row k="entries checked" v={auditVerify.data?.checked ?? 0} />
          <Row k="ABAC enforcement" v={grants.data?.abac_enforced ? <Badge tone="green">enforced</Badge> : <Badge tone="amber">no grants/dev</Badge>} />
        </div>
      </Panel>

      <Panel title="Control-plane health" sub={health.source === "live" ? "Queue, worker fleet, credentials, database and cache health" : "backend offline"} className="mt">
        <Code>{JSON.stringify(health.data ?? {}, null, 2).slice(0, 1200)}</Code>
      </Panel>
    </>
  );
}

/* ── Live posture stream hook (fetch-backed SSE; EventSource can't set auth) ── */
function usePostureStream(intervalMs = 30000) {
  const [posture, setPosture] = useState<SecurityPosture | null>(null);
  const [live, setLive] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [delta, setDelta] = useState<{ dropped: boolean; delta: number | null; previous_score: number | null }>({ dropped: false, delta: null, previous_score: null });
  const abortRef = useRef<AbortController | null>(null);
  const stopRef = useRef(false);

  useEffect(() => {
    stopRef.current = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const connect = async () => {
      if (stopRef.current) return;
      const token = getToken();
      if (!token) return;
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      try {
        const resp = await tenantFetch(`/api/v1/security/posture/stream?interval=${Math.max(5, Math.round(intervalMs / 1000))}`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: ac.signal,
        });
        if (!resp.ok || !resp.body) throw new Error(`stream http ${resp.status}`);
        setLive(true); setError(undefined);
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        while (!stopRef.current) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) >= 0) {
            const frame = buf.slice(0, idx); buf = buf.slice(idx + 2);
            let eventType = "message"; let data = "";
            for (const line of frame.split("\n")) {
              if (line.startsWith(":")) continue;
              if (line.startsWith("event:")) eventType = line.slice(6).trim();
              else if (line.startsWith("data:")) data += line.slice(5).trim();
            }
            if (!data) continue;
            try {
              const obj = JSON.parse(data);
              if (eventType === "security.posture") {
                setPosture(obj);
                setDelta({ dropped: !!obj.dropped, delta: obj.delta ?? null, previous_score: obj.previous_score ?? null });
              } else if (eventType === "security.posture_drop") {
                setDelta({ dropped: true, delta: obj.delta ?? null, previous_score: obj.previous_score ?? null });
              }
            } catch { /* partial frame */ }
          }
        }
      } catch (e) {
        if (!stopRef.current) { setLive(false); setError(String(e)); }
      }
      if (!stopRef.current) timer = setTimeout(connect, 5000);
    };

    void connect();
    return () => { stopRef.current = true; abortRef.current?.abort(); if (timer) clearTimeout(timer); };
  }, [intervalMs]);

  return { posture, live, error, delta };
}

function PostureTrendChart({ trend }: { trend: PostureTrend | null }) {
  const buckets = trend?.buckets ?? [];
  const scores = buckets.map((b) => b.score_avg ?? 0);
  const max = 100;
  const W = 600, H = 120, pad = 4;
  const points = scores.map((s, i) => {
    const x = buckets.length > 1 ? pad + (i * (W - 2 * pad)) / (buckets.length - 1) : W / 2;
    const y = H - pad - ((Math.min(max, Math.max(0, s)) / max) * (H - 2 * pad));
    return [x, y] as const;
  });
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = points.length ? `M ${points[0][0]},${H - pad} L ${points.map(([x, y]) => `${x},${y}`).join(" L ")} L ${points[points.length - 1][0]},${H - pad} Z` : "";

  return (
    <div>
      <div className="spread" style={{ marginBottom: 8, fontSize: 12.5 }}>
        <span className="dim">score (avg per bucket) · {trend?.window_hours ?? 24}h window</span>
        <span className="mono">{trend?.count ?? 0} snapshots</span>
      </div>
      {buckets.length === 0 && <div className="dim" style={{ fontSize: 13 }}>No posture snapshots yet — the chart fills as snapshots accrue.</div>}
      {buckets.length > 0 && (
        <>
          <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto", background: "transparent" }}>
            {[0, 25, 50, 75, 100].map((g) => {
              const y = H - pad - (g / max) * (H - 2 * pad);
              return <line key={g} x1={pad} x2={W - pad} y1={y} y2={y} stroke="var(--line)" strokeWidth={1} />;
            })}
            {area && <path d={area} fill="color-mix(in srgb, var(--green) 10%, transparent)" stroke="none" />}
            <polyline points={line} fill="none" stroke={scoreTone(buckets[buckets.length - 1]?.score_avg ?? 0)} strokeWidth={2.2} strokeLinejoin="round" strokeLinecap="round" />
            {points.map(([x, y], i) => (
              <circle key={i} cx={x} cy={y} r={2.5} fill={scoreTone(scores[i] ?? 0)} />
            ))}
          </svg>
          <div className="grid cols-5" style={{ marginTop: 10 }}>
            {["audit", "cert", "auth", "threat", "fleet"].map((k) => (
              <PerSignal key={k} label={k} value={latestComponent(trend, k)} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function latestComponent(trend: PostureTrend | null, key: string): number {
  if (!trend) return 0;
  for (let i = trend.buckets.length - 1; i >= 0; i--) {
    const v = trend.buckets[i].components?.[key] ?? null;
    if (v !== null) return Math.round((v as number) * 100);
  }
  return 0;
}

function scoreTone(s: number): string {
  return s >= 80 ? "var(--green)" : s >= 50 ? "var(--amber)" : "var(--red)";
}

function PerSignal({ label, value }: { label: string; value: number }) {
  return (
    <div style={{ textAlign: "center" }}>
      <div className="dim" style={{ fontSize: 11 }}>{label}</div>
      <div className="mono" style={{ fontSize: 15, color: scoreTone(value) }}>{value}%</div>
      <div style={{ background: "var(--line)", height: 4, borderRadius: "var(--r)", marginTop: 4 }}>
        <div style={{ width: `${value}%`, height: 4, borderRadius: "var(--r)", background: scoreTone(value) }} />
      </div>
    </div>
  );
}

function ScoreBox({ score, live, delta }: { score: number; live: boolean; delta: number | null }) {
  const tone = score >= 80 ? "var(--green)" : score >= 50 ? "var(--amber)" : "var(--red)";
  return (
    <div className="kpi" style={{ borderTop: `3px solid ${tone}` }}>
      <span className="k">security score</span>
      <span className="v" style={{ color: tone, fontSize: 34, fontWeight: 800 }}>{score}</span>
      <span className="dim" style={{ fontSize: 11.5 }}>
        {live ? "server-owned · live SSE" : "backend offline"}
        {delta !== null ? ` · Δ ${delta > 0 ? "+" : ""}${delta}` : ""}
      </span>
    </div>
  );
}

function ComponentStat({ label, c }: { label: string; c?: PostureComponent }) {
  const pct = Math.round((c?.value ?? 0) * 100);
  const tone = pct >= 80 ? "var(--green)" : pct >= 50 ? "var(--amber)" : "var(--red)";
  return (
    <div className="kpi" style={{ borderTop: `3px solid ${tone}` }}>
      <span className="k">{label}</span>
      <span className="v" style={{ color: tone, fontSize: 24, fontWeight: 800 }}>{pct}%</span>
      <span className="dim" style={{ fontSize: 11 }}>{c?.note ?? "no data"}</span>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="spread" style={{ fontSize: 13, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="dim">{k}</span>
      <span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}
