import React, { useEffect, useMemo, useRef, useState } from "react";
import { Panel, Badge, Table, Bar, Ring, Code, Feed } from "../components/ui";
import { IconSecurity, IconComponent, IconTarget, IconClock, IconHardware, IconInfo, IconCloud } from "../components/icons";
import { useLive } from "../lib/useLive.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtime, severityOf, isSystemEvent, useRealtimeRefresh } from "../lib/realtime.jsx";
import { getToken, tenantFetch, apiControlAgents, apiP2Plugins, apiP2AnomalyFlags, apiAuditVerify, apiAuditList, apiControlHealth, apiLiveInventory, apiMyGrants, apiSafeScanPolicy, apiSecurityPosture, apiSecurityPostureTrend, apiSecurityAlerts, apiAnomalyAck, type SecurityPosture, type PostureComponent, type PostureTrend, type SecurityAlert } from "../lib/api.js";

const SEV_TONE: Record<string, string> = { CRITICAL: "red", HIGH: "red", MEDIUM: "amber", LOW: "amber", INFO: "" };
interface AgentRow { id?: string; status?: string; healthy?: boolean; health_ok?: boolean; version?: string; last_heartbeat_at?: string | null; [k: string]: unknown; }
interface PluginRow { id?: string; name?: string; state?: string; verified?: boolean; version?: string; [k: string]: unknown; }
interface AnomalyRow { id?: string; pk?: string; severity?: string; rule?: string; description?: string; explanation?: string; status?: string; [k: string]: unknown; }

export default function SecurityCenter() {
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
  const grants = useLive<{ principal: string; roles: string[]; grants: Array<Record<string, unknown>>; count: number; abac_enforced: boolean }>("/api/v1/control/me/grants", { principal: "", roles: [], grants: [], count: 0, abac_enforced: false });
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
  const auditOk = auditVerify.data?.status === "OK";
  const livePosture = postureStream.posture ?? (posture.data as SecurityPosture | null) ?? null;
  const score = livePosture?.score ?? 0;
  const components = (livePosture?.components ?? {}) as Record<string, PostureComponent>;
  const dropped = postureStream.delta.dropped || (livePosture as any)?.dropped === true;
  const scoreDelta = postureStream.delta.delta ?? (livePosture as any)?.delta ?? null;
  const scorePrevious = postureStream.delta.previous_score ?? (livePosture as any)?.previous_score ?? null;
  const liveEvents = useMemo(() => rt.events.filter((e) => !isSystemEvent(e.type)).slice(0, 14), [rt.events]);
  const ack = async (a: SecurityAlert) => { if (a.ack_href) { const id = a.ack_href.split("/").filter(Boolean).pop(); if (id) await apiAnomalyAck(id); forceTick((n) => n + 1); } };
  const heroTone = score >= 80 ? "green" as const : score >= 50 ? "amber" as const : score > 0 ? "red" as const : "slate" as const;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Hero */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--red) 12%, transparent)", border: "1px solid var(--red)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--red)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--red)" }} /> GOVERNANCE · 24/7 SECURITY OPERATIONS CENTER · LIVE SSE
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--red)", color: "#fff" }}><IconSecurity size={18} /></span>
            ZELNX Security Operations Center
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            Server-owned posture, posture-over-time drift, live threat feed & event stream — <b style={{ color: "var(--text)" }}>every number from a real control-plane signal</b>. Empty reads low, never fabricated green.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>POSTURE STREAM SSE · ABAC · AUDIT CHAIN · AGENT FLEET</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <Badge tone={postureStream.live ? "green" : posture.source === "live" ? "green" : "amber"}><span className="dot" /> {postureStream.live ? "LIVE SSE" : posture.source === "live" ? "LIVE" : "OFFLINE"} {score}/100</Badge>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 170, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={score / 100} label={String(score)} sub="/100" tone={heroTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>SECURITY SCORE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 145, lineHeight: 1.4 }}>{postureStream.live || posture.source === "live" ? "server-owned · live" : "backend offline"}{scoreDelta !== null ? ` · Δ ${scoreDelta > 0 ? "+" : ""}${scoreDelta}` : ""}</div>
              <div style={{ marginTop: 6 }}><Bar value={score / 100} tone={heroTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{rt.conn === "live" ? "● event stream live" : `stream ${rt.conn}`}</span>
            <span style={{ fontSize: 11, color: "var(--dim)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "6px 10px", textAlign: "center" }}>{alertRows.length} open alerts · {openThreats} threats</span>
          </div>
        </div>
      </div>

      {dropped && (
        <div style={{ background: "color-mix(in srgb, var(--red) 10%, transparent)", border: "1px solid var(--red)", padding: "10px 14px", borderRadius: "var(--r)", marginBottom: 16, display: "flex", gap: 10, alignItems: "center" }}>
          <span style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: "var(--red)", color: "#fff" }}><IconInfo size={14} /></span>
          <div><b style={{ fontSize: 13 }}>Attention — security posture regressed.</b><span style={{ fontSize: 12, color: "var(--dim)", marginLeft: 8 }}>score dropped {scorePrevious ?? "—"} → {score} (Δ {scoreDelta}). Review the live threat feed below.</span></div>
        </div>
      )}

      {/* KPI strip — visual borderTop cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `3px solid var(--${heroTone})` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SECURITY SCORE</div><div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", lineHeight: 1, color: `var(--${heroTone})` }}>{score}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{postureStream.live ? "live SSE" : "snapshot"} · composite integrity</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: `color-mix(in srgb, var(--${heroTone}) 14%, transparent)`, border: `1px solid var(--${heroTone})`, color: `var(--${heroTone})` }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={score / 100} tone={heroTone} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>0 hostile · 100 hardened</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(livePosture?.threats_open ?? openThreats) ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>OPEN THREATS</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: (livePosture?.threats_open ?? openThreats) ? "var(--red)" : "var(--green)" }}>{livePosture?.threats_open ?? openThreats}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>unacknowledged anomaly flags</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (livePosture?.threats_open ?? openThreats) ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid ${(livePosture?.threats_open ?? openThreats) ? "var(--red)" : "var(--green)"}`, color: (livePosture?.threats_open ?? openThreats) ? "var(--red)" : "var(--green)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={Math.min(1, (livePosture?.threats_open ?? openThreats) / 10)} tone={(livePosture?.threats_open ?? openThreats) ? "red" : "green"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{livePosture?.threats_critical ?? criticalThreats} critical/high</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(livePosture?.failed_logins ?? failedLogins) ? "var(--amber)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>FAILED LOGINS (RECENT)</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{livePosture?.failed_logins ?? failedLogins}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>auth failures in audit ledger</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (livePosture?.failed_logins ?? failedLogins) ? "color-mix(in srgb, var(--amber) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${(livePosture?.failed_logins ?? failedLogins) ? "var(--amber)" : "var(--line)"}`, color: (livePosture?.failed_logins ?? failedLogins) ? "var(--amber)" : "var(--faint)" }}><IconInfo size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={Math.min(1, (livePosture?.failed_logins ?? failedLogins) / 20)} tone={(livePosture?.failed_logins ?? failedLogins) ? "amber" : "slate"} /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${(livePosture?.agents_healthy ?? agentsHealthy) ? "var(--green)" : "var(--amber)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>AGENTS HEALTHY</div><div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{livePosture?.agents_healthy ?? agentsHealthy}/{livePosture?.agents_total ?? agentRows.length}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{agentsWarning ? `${agentsWarning} warning/degraded` : "all healthy"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (livePosture?.agents_healthy ?? agentsHealthy) ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${(livePosture?.agents_healthy ?? agentsHealthy) ? "var(--green)" : "var(--line)"}`, color: (livePosture?.agents_healthy ?? agentsHealthy) ? "var(--green)" : "var(--faint)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={agentRows.length ? (livePosture?.agents_healthy ?? agentsHealthy) / Math.max(1, livePosture?.agents_total ?? agentRows.length) : 0} tone={(livePosture?.agents_healthy ?? agentsHealthy) ? "green" : "slate"} /></div>
        </div>
      </div>

      <Panel title="Security posture" sub="Live composite control integrity — server-owned, not polled demo">
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12, marginBottom: 14 }}>
          <ComponentStat label="audit chain" c={components.audit} />
          <ComponentStat label="certificates" c={components.cert} />
          <ComponentStat label="auth" c={components.auth} />
          <ComponentStat label="threats" c={components.threat} />
          <ComponentStat label="agent fleet" c={components.fleet} />
          <ComponentStat label="plugin trust" c={components.plugin} />
        </div>
        <div style={{ marginTop: 10, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 12, color: "var(--dim)" }}>Composite control integrity</span><span style={{ fontFamily: "var(--mono)", fontWeight: 700, color: `var(--${heroTone})` }}>{score}%</span>
        </div>
        <div style={{ marginTop: 8 }}><Bar value={score / 100} tone={heroTone} /></div>
      </Panel>

      <Panel title="Posture over time" sub="Score min/avg/max per bucket with per-signal drift — snapshots accrue live" style={{ marginTop: 14 }}>
        <PostureTrendChart trend={trend.data as PostureTrend | null} />
      </Panel>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(340px, 1fr))", gap: 14, marginTop: 14 }}>
        <Panel title="Live threat feed" sub="anomaly flags · live-scan alerts · runtime findings · failed logins — triage + acknowledge">
          {alertRows.length === 0 && <div style={{ padding: 16, textAlign: "center", color: "var(--faint)", fontSize: 13, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}><div style={{ fontWeight: 700, color: "var(--text)" }}>No open alerts</div><div style={{ fontSize: 12, marginTop: 4 }}>The platform is quiet — and stays honest about it.</div></div>}
          {alertRows.length > 0 && <Table head={["severity", "source", "title", "action"]} rows={alertRows.slice(0, 12).map((a) => [<Badge tone={SEV_TONE[String(a.severity).toUpperCase()] ?? ""}>{String(a.severity)}</Badge>, <span className="mono" style={{ fontSize: 11 }}>{String(a.source)}</span>, <span style={{ fontSize: 12 }}>{String(a.title)}</span>, a.ack_href ? <button className="link" onClick={() => void ack(a)} style={{ fontSize: 12, color: "var(--cyan)", background: "none", border: "none", cursor: "pointer", textDecoration: "underline" }}>acknowledge</button> : <span className="dim" style={{ fontSize: 11 }}>—</span>])} />}
        </Panel>
        <Panel title="Live event stream" sub={rt.conn === "live" ? "Live platform events" : `stream ${rt.conn}`}>
          {liveEvents.length === 0 && <div style={{ padding: 16, textAlign: "center", color: "var(--faint)", fontSize: 13, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>No platform events yet — they appear as the control plane emits them.</div>}
          {liveEvents.length > 0 && <Feed items={liveEvents.map((e) => ({ t: new Date(e.ts).toLocaleTimeString(), tag: severityOf(e.type), text: `${e.type.replace(/\./g, " · ")}` }))} />}
          {liveEvents.length === 0 && rt.conn === "live" && <div className="dim" style={{ fontSize: 12, marginTop: 10, textAlign: "center" }}>Connected — waiting for the next platform event.</div>}
        </Panel>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14, marginTop: 14 }}>
        <Panel title="Agents" sub={health.source === "live" ? "enrolled scanner agents (fleet health from control plane)" : "backend offline"}>
          {agentRows.length === 0 && <div className="dim" style={{ fontSize: 12, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center" }}>No agents enrolled — install an agent or run a local scan.</div>}
          <div style={{ display: "grid", gap: 6 }}><Row k="healthy" v={<Badge tone="green">{agentsHealthy}</Badge>} /><Row k="warning / degraded" v={<Badge tone="amber">{agentsWarning}</Badge>} /><Row k="enrolled" v={agentRows.length} /><div style={{ marginTop: 6 }}><Bar value={agentRows.length ? agentsHealthy / agentRows.length : 0} tone={agentsHealthy ? "green" : "slate"} /></div></div>
        </Panel>
        <Panel title="Plugins" sub="scanner / integration plugins — trust & signature posture">
          {pluginRows.length === 0 && <div className="dim" style={{ fontSize: 12, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, textAlign: "center" }}>No marketplace plugins installed yet.</div>}
          <div style={{ display: "grid", gap: 6 }}><Row k="verified" v={<Badge tone="green">{pluginsVerified}</Badge>} /><Row k="untrusted / quarantined" v={<Badge tone={pluginsUntrusted ? "red" : "green"}>{pluginsUntrusted}</Badge>} /><Row k="total" v={pluginRows.length} /><div style={{ marginTop: 6 }}><Bar value={pluginRows.length ? pluginsVerified / pluginRows.length : 0} tone={pluginsVerified ? "green" : "slate"} /></div></div>
        </Panel>
        <Panel title="Audit & evidence integrity" sub="immutable hash chain + tenant isolation + approval gates">
          <div style={{ display: "grid", gap: 6 }}><Row k="audit chain" v={<Badge tone={auditOk ? "green" : "red"}>{String(auditVerify.data?.status ?? "—")}</Badge>} /><Row k="entries checked" v={auditVerify.data?.checked ?? 0} /><Row k="ABAC enforcement" v={grants.data?.abac_enforced ? <Badge tone="green">enforced</Badge> : <Badge tone="amber">no grants/dev</Badge>} /></div>
        </Panel>
      </div>

      <Panel title="Control-plane health" sub={health.source === "live" ? "Queue, worker fleet, credentials, database and cache health" : "backend offline"} style={{ marginTop: 14 }}>
        <Code>{JSON.stringify(health.data ?? {}, null, 2).slice(0, 1200)}</Code>
      </Panel>
    </div>
  );
}

function usePostureStream(intervalMs = 30000) {
  const [posture, setPosture] = useState<SecurityPosture | null>(null);
  const [live, setLive] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const [delta, setDelta] = useState<{ dropped: boolean; delta: number | null; previous_score: number | null }>({ dropped: false, delta: null, previous_score: null });
  const abortRef = useRef<AbortController | null>(null);
  const stopRef = useRef(false);
  useEffect(() => {
    stopRef.current = false; let timer: ReturnType<typeof setTimeout> | null = null;
    const connect = async () => {
      if (stopRef.current) return;
      const token = getToken(); if (!token) return;
      abortRef.current?.abort(); const ac = new AbortController(); abortRef.current = ac;
      try {
        const resp = await tenantFetch(`/api/v1/security/posture/stream?interval=${Math.max(5, Math.round(intervalMs / 1000))}`, { headers: { Authorization: `Bearer ${token}` }, signal: ac.signal });
        if (!resp.ok || !resp.body) throw new Error(`stream http ${resp.status}`);
        setLive(true); setError(undefined);
        const reader = resp.body.getReader(); const decoder = new TextDecoder(); let buf = "";
        while (!stopRef.current) {
          const { value, done } = await reader.read(); if (done) break;
          buf += decoder.decode(value, { stream: true }); let idx: number;
          while ((idx = buf.indexOf("\n\n")) >= 0) {
            const frame = buf.slice(0, idx); buf = buf.slice(idx + 2); let eventType = "message"; let data = "";
            for (const line of frame.split("\n")) { if (line.startsWith(":")) continue; if (line.startsWith("event:")) eventType = line.slice(6).trim(); else if (line.startsWith("data:")) data += line.slice(5).trim(); }
            if (!data) continue;
            try { const obj = JSON.parse(data); if (eventType === "security.posture") { setPosture(obj); setDelta({ dropped: !!obj.dropped, delta: obj.delta ?? null, previous_score: obj.previous_score ?? null }); } else if (eventType === "security.posture_drop") setDelta({ dropped: true, delta: obj.delta ?? null, previous_score: obj.previous_score ?? null }); } catch {}
          }
        }
      } catch (e) { if (!stopRef.current) { setLive(false); setError(String(e)); } }
      if (!stopRef.current) timer = setTimeout(connect, 5000);
    };
    void connect();
    return () => { stopRef.current = true; abortRef.current?.abort(); if (timer) clearTimeout(timer); };
  }, [intervalMs]);
  return { posture, live, error, delta };
}

function PostureTrendChart({ trend }: { trend: PostureTrend | null }) {
  const buckets = trend?.buckets ?? []; const scores = buckets.map((b) => b.score_avg ?? 0); const max = 100; const W = 600, H = 120, pad = 4;
  const points = scores.map((s, i) => { const x = buckets.length > 1 ? pad + (i * (W - 2 * pad)) / (buckets.length - 1) : W / 2; const y = H - pad - ((Math.min(max, Math.max(0, s)) / max) * (H - 2 * pad)); return [x, y] as const; });
  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" "); const area = points.length ? `M ${points[0][0]},${H - pad} L ${points.map(([x, y]) => `${x},${y}`).join(" L ")} L ${points[points.length - 1][0]},${H - pad} Z` : "";
  return (
    <div>
      <div className="spread" style={{ marginBottom: 8, fontSize: 12 }}><span className="dim">score (avg per bucket) · {trend?.window_hours ?? 24}h window</span><span className="mono" style={{ background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "2px 8px" }}>{trend?.count ?? 0} snapshots</span></div>
      {buckets.length === 0 && <div className="dim" style={{ fontSize: 13, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 14, textAlign: "center" }}>No posture snapshots yet — the chart fills as snapshots accrue.</div>}
      {buckets.length > 0 && <>
        <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}>
          {[0, 25, 50, 75, 100].map((g) => { const y = H - pad - (g / max) * (H - 2 * pad); return <line key={g} x1={pad} x2={W - pad} y1={y} y2={y} stroke="var(--line)" strokeWidth={1} />; })}
          {area && <path d={area} fill="color-mix(in srgb, var(--green) 10%, transparent)" stroke="none" />}
          <polyline points={line} fill="none" stroke={scoreTone(buckets[buckets.length - 1]?.score_avg ?? 0)} strokeWidth={2.2} strokeLinejoin="round" strokeLinecap="round" />
          {points.map(([x, y], i) => <circle key={i} cx={x} cy={y} r={2.5} fill={scoreTone(scores[i] ?? 0)} />)}
        </svg>
        <div className="grid cols-5" style={{ marginTop: 12 }}>
          {["audit", "cert", "auth", "threat", "fleet"].map((k) => <PerSignal key={k} label={k} value={latestComponent(trend, k)} />)}
        </div>
      </>}
    </div>
  );
}
function latestComponent(trend: PostureTrend | null, key: string): number { if (!trend) return 0; for (let i = trend.buckets.length - 1; i >= 0; i--) { const v = trend.buckets[i].components?.[key] ?? null; if (v !== null) return Math.round((v as number) * 100); } return 0; }
function scoreTone(s: number): string { return s >= 80 ? "var(--green)" : s >= 50 ? "var(--amber)" : "var(--red)"; }
function PerSignal({ label, value }: { label: string; value: number }) {
  return <div style={{ textAlign: "center", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 6px" }}><div className="dim" style={{ fontSize: 10, letterSpacing: ".06em" }}>{label.toUpperCase()}</div><div className="mono" style={{ fontSize: 15, color: scoreTone(value), fontWeight: 800 }}>{value}%</div><div style={{ background: "var(--line)", height: 4, borderRadius: "var(--r)", marginTop: 6 }}><div style={{ width: `${value}%`, height: 4, borderRadius: "var(--r)", background: scoreTone(value) }} /></div></div>;
}
function ComponentStat({ label, c }: { label: string; c?: PostureComponent }) {
  const pct = Math.round((c?.value ?? 0) * 100); const tone = pct >= 80 ? "var(--green)" : pct >= 50 ? "var(--amber)" : "var(--red)";
  return <div className="kpi" style={{ borderTop: `3px solid ${tone}`, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "12px 14px" }}><span className="k" style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>{label.toUpperCase()}</span><span className="v" style={{ color: tone, fontSize: 22, fontWeight: 800 }}>{pct}%</span><span className="dim" style={{ fontSize: 11 }}>{c?.note ?? "no data"}</span><div style={{ marginTop: 8 }}><Bar value={pct / 100} tone={pct >= 80 ? "green" : pct >= 50 ? "amber" : "red"} /></div></div>;
}
function Row({ k, v }: { k: string; v: React.ReactNode }) { return <div className="spread" style={{ fontSize: 12, padding: "7px 0", borderBottom: "1px solid var(--line)" }}><span className="dim">{k}</span><span style={{ textAlign: "right" }}>{v}</span></div>; }
