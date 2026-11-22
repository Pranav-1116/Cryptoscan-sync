/* Live estate — the bank's business systems as the agents see them right now.
 *
 * One combined read every 15 s (/api/v1/operations/{monitor,fleet,hosts}):
 *   - the estate connection and the twin the screen reads;
 *   - each business system with its hosts, their liveness, load, collector completeness,
 *     quantum-vulnerable algorithm uses and the alerts that name it;
 *   - collection health across every plane and source.
 * Systems come only from what agents declare; a host with no declared system is listed as such. */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiOpsFleet, apiOpsHosts, apiOpsMonitor, type ApiResult, type OpsAgent, type OpsFleet, type OpsHost, type OpsHosts, type OpsMonitor } from "../lib/api.js";
import { IconEstate } from "../components/icons";
import {
  KpiTile, LIVENESS_COLOR, LiveBar, LivenessPill, OPS_SEV_COLOR, OpsHeader, OpsLoadStates, PLANE_COLOR, SOURCE_COLOR,
  SOURCE_MEANING, SevBadge, card, fmtAge, fmtWhen, kicker, metricValue, pctColor, useLive,
} from "../components/opsUi";

interface EstateView { monitor: OpsMonitor; fleet: OpsFleet; hosts: OpsHosts }

async function readEstate(): Promise<ApiResult<EstateView>> {
  const [m, f, h] = await Promise.all([apiOpsMonitor(), apiOpsFleet(), apiOpsHosts()]);
  if (!m.data || !f.data || !h.data) {
    const failed = [m, f, h].find((r) => !r.data);
    return { ...(failed as ApiResult<unknown>), data: null } as ApiResult<EstateView>;
  }
  return { ...m, data: { monitor: m.data, fleet: f.data, hosts: h.data } } as ApiResult<EstateView>;
}

const CRIT_RANK: Record<string, number> = { "tier-0": 0, tier0: 0, critical: 0, "tier-1": 1, high: 1, "tier-2": 2, medium: 2 };
const rank = (c?: string | null) => CRIT_RANK[String(c ?? "").toLowerCase()] ?? 5;

interface SystemCard {
  name: string; criticality: string | null; owner: string | null;
  agents: OpsAgent[]; hosts: OpsHost[]; alerts: OpsMonitor["alerts"];
}

function Bar({ parts, label }: { parts: Array<[string, number, string]>; label: string }) {
  const total = parts.reduce((a, [, n]) => a + n, 0) || 1;
  return (
    <div role="img" aria-label={label} style={{ display: "flex", height: 10, borderRadius: 99, overflow: "hidden", background: "var(--line)" }}>
      {parts.filter(([, n]) => n > 0).map(([k, n, c]) => (
        <span key={k} title={`${k}: ${n}`} style={{ width: `${(n / total) * 100}%`, background: c }} />
      ))}
    </div>
  );
}

function SystemTile({ s, late, offline }: { s: SystemCard; late: number; offline: number }) {
  const worst = s.agents.some((a) => a.liveness.state === "OFFLINE") ? "OFFLINE"
    : s.agents.some((a) => a.liveness.state === "LATE") ? "LATE"
    : s.agents.some((a) => a.liveness.state === "NEVER_REPORTED") ? "NEVER_REPORTED" : "LIVE";
  const color = LIVENESS_COLOR[worst];
  const vuln = s.hosts.reduce((a, h) => a + (h.counts.quantum_vulnerable ?? 0), 0);
  const services = s.hosts.reduce((a, h) => a + (h.counts.running_services ?? 0), 0);
  const planes: Record<string, number> = {};
  s.agents.forEach((a) => Object.entries(a.plane_states ?? {}).forEach(([k, n]) => { planes[k] = (planes[k] ?? 0) + n; }));
  const topAlert = s.alerts[0];
  return (
    <section aria-label={`System ${s.name}`} style={{ ...card, borderTop: `3px solid ${color}`, display: "grid", gap: 10, alignContent: "start" }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
        <div>
          <div style={{ fontWeight: 800, fontSize: 14.5 }}>{s.name}</div>
          <div style={{ fontSize: 11.5, color: "var(--dim)" }}>{s.criticality ?? "criticality not declared"}{s.owner ? ` · ${s.owner}` : ""}</div>
        </div>
        <LivenessPill state={worst} />
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6, fontSize: 11.5 }}>
        <div><div style={kicker}>Hosts</div><b style={{ fontSize: 16 }}>{s.agents.length}</b></div>
        <div><div style={kicker}>Services</div><b style={{ fontSize: 16 }}>{services}</b></div>
        <div><div style={kicker}>Q-vulnerable</div><b style={{ fontSize: 16, color: vuln ? "var(--red)" : "var(--green)" }}>{vuln}</b></div>
      </div>
      <div style={{ display: "grid", gap: 6 }}>
        {s.agents.map((a) => {
          const cpu = metricValue(a.performance.latest, "cpu_pct");
          const age = a.liveness.age_seconds;
          return (
            <div key={a.name} style={{ display: "grid", gridTemplateColumns: "10px 1fr auto auto", gap: 8, alignItems: "center", fontSize: 11.5 }}>
              <span title={a.liveness.state} style={{ width: 8, height: 8, borderRadius: 99, background: LIVENESS_COLOR[a.liveness.state] }} />
              <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.name}>{a.host.name ?? a.name}</span>
              <span style={{ fontFamily: "var(--mono)", color: pctColor(cpu) }}>{cpu === null ? "—" : `${cpu.toFixed(0)}%`}</span>
              <span style={{ fontFamily: "var(--mono)", color: age === null || age > late ? (age !== null && age <= offline ? "var(--amber)" : "var(--red)") : "var(--faint)" }}>
                {age === null ? "never" : fmtAge(age)}
              </span>
            </div>
          );
        })}
      </div>
      <div>
        <div style={{ ...kicker, marginBottom: 4 }}>Collectors</div>
        <Bar label={`Plane states of ${s.name}`} parts={Object.entries(planes).map(([k, n]) => [k, n, PLANE_COLOR[k] ?? "var(--faint)"])} />
        <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 3 }}>{Object.entries(planes).map(([k, n]) => `${n} ${k.toLowerCase()}`).join(" · ") || "no plane reported"}</div>
      </div>
      {topAlert ? (
        <div style={{ fontSize: 11.5, padding: "6px 8px", borderRadius: 6, background: "var(--panel-2)", borderLeft: `3px solid ${OPS_SEV_COLOR[topAlert.severity]}` }}>
          <b>{topAlert.title}</b>{s.alerts.length > 1 ? <span style={{ color: "var(--faint)" }}> (+{s.alerts.length - 1})</span> : null}
        </div>
      ) : <div style={{ fontSize: 11.5, color: "var(--faint)" }}>no alert names this system</div>}
    </section>
  );
}

export default function LiveEstate() {
  const live = useLive<EstateView>(readEstate, 15000);
  const { data, state, error, refresh } = live;
  const [onlyAttention, setOnlyAttention] = useState(false);

  const systems = useMemo<SystemCard[]>(() => {
    if (!data) return [];
    const byName = new Map<string, SystemCard>();
    const hostByAgent = new Map(data.hosts.hosts.map((h) => [h.agent, h]));
    for (const a of data.fleet.agents) {
      const name = a.system?.name ?? "No system declared";
      const s = byName.get(name) ?? { name, criticality: a.system?.criticality ?? null, owner: a.system?.owner ?? null, agents: [], hosts: [], alerts: [] };
      s.agents.push(a);
      const h = hostByAgent.get(a.name); if (h) s.hosts.push(h);
      byName.set(name, s);
    }
    for (const al of data.monitor.alerts) {
      const s = al.system ? byName.get(al.system) : undefined;
      if (s) s.alerts.push(al);
    }
    return Array.from(byName.values()).sort((x, y) => rank(x.criticality) - rank(y.criticality) || x.name.localeCompare(y.name));
  }, [data]);

  const shown = onlyAttention
    ? systems.filter((s) => s.alerts.length || s.agents.some((a) => a.liveness.state !== "LIVE" || a.issues.length))
    : systems;

  const m = data?.monitor;
  const t = data?.fleet.totals;
  const sources = t?.source_states ?? {};
  const unscoped = m?.alerts.filter((a) => !a.system) ?? [];

  return (
    <>
      <OpsHeader
        crumb="Operations / Live estate"
        title="Live estate"
        icon={<IconEstate size={18} />}
        sub="The bank's business systems as the agents see them right now: which hosts serve each, whether they are reporting, how loaded they are, and the quantum-vulnerable crypto running on them."
        right={<LiveBar live={live} />}
      />
      {state !== "ready" || !data || !m ? (
        <OpsLoadStates state={state} error={error} refresh={refresh} what="The live estate" />
      ) : (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
            <KpiTile label="Estate connection" ariaLabel="Estate connection" value={m.connection.state}
              color={m.connection.state === "LIVE" ? "var(--green)" : "var(--amber)"}
              sub={m.connection.seconds_since === null ? "no observation yet" : `last observation ${fmtAge(m.connection.seconds_since)} ago`} />
            <KpiTile label="Systems watched" ariaLabel="Systems watched" value={systems.filter((s) => s.name !== "No system declared").length}
              sub={`${t?.agents ?? 0} hosts with an agent`} />
            <KpiTile label="Hosts live" ariaLabel="Hosts live" value={<>{t?.live ?? 0}<span style={{ fontSize: 14, color: "var(--faint)" }}> / {t?.agents ?? 0}</span></>}
              color={t && t.live === t.agents ? "var(--green)" : "var(--amber)"} sub={`heartbeat every ${fmtAge(data.fleet.heartbeat_seconds)}`} />
            <KpiTile label="Quantum-vulnerable uses" ariaLabel="Quantum-vulnerable uses" value={data.hosts.totals.quantum_vulnerable ?? 0}
              color={(data.hosts.totals.quantum_vulnerable ?? 0) ? "var(--red)" : "var(--green)"} sub="Shor-breakable algorithms on hosts" />
            <KpiTile label="Open alerts" ariaLabel="Open alerts" value={m.alerts.length}
              color={(m.alert_counts.CRITICAL ?? 0) + (m.alert_counts.HIGH ?? 0) ? "var(--red)" : m.alerts.length ? "var(--amber)" : "var(--green)"}
              sub={<Link to="/live-monitor" style={{ color: "var(--cyan)" }}>open Live monitor →</Link>} />
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", margin: "4px 0 10px", gap: 10, flexWrap: "wrap" }}>
            <div style={{ fontWeight: 700, fontSize: 14 }}>Business systems <span style={{ color: "var(--faint)", fontWeight: 500 }}>most critical first</span></div>
            <label style={{ fontSize: 12, color: "var(--dim)", display: "flex", gap: 6, alignItems: "center" }}>
              <input type="checkbox" checked={onlyAttention} onChange={(e) => setOnlyAttention(e.target.checked)} /> only systems needing attention
            </label>
          </div>
          <div aria-label="Systems" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 12 }}>
            {shown.map((s) => <SystemTile key={s.name} s={s} late={data.fleet.late_after_seconds} offline={data.fleet.offline_after_seconds} />)}
          </div>
          {shown.length === 0 ? (
            <div style={{ ...card, fontSize: 12.5, color: "var(--dim)" }}>
              {systems.length === 0 ? "No agent is enrolled, so no system is being watched. Enroll Cryptava agents on the bank's hosts." : "Every system is reporting and no alert names one."}
            </div>
          ) : null}

          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 14 }}>
            <section aria-label="Collection health" style={{ ...card, flex: "1 1 420px" }}>
              <div style={{ fontWeight: 700, fontSize: 14 }}>Collection health</div>
              <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 10 }}>every source behind every collector, across the fleet</div>
              <Bar label="Source states" parts={Object.entries(sources).map(([k, n]) => [k, n, SOURCE_COLOR[k] ?? "var(--faint)"])} />
              <div style={{ display: "grid", gap: 4, marginTop: 10 }}>
                {Object.entries(sources).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                  <div key={k} style={{ display: "grid", gridTemplateColumns: "130px 50px 1fr", gap: 8, fontSize: 11.5 }}>
                    <b style={{ color: SOURCE_COLOR[k] ?? "var(--dim)", fontFamily: "var(--mono)" }}>{k}</b>
                    <span style={{ fontVariantNumeric: "tabular-nums" }}>{n}</span>
                    <span style={{ color: "var(--faint)" }}>{SOURCE_MEANING[k] ?? ""}</span>
                  </div>
                ))}
              </div>
              {m.coverage ? (
                <div style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 10 }}>
                  Coverage {typeof m.coverage.coverage_percent === "number" ? `${m.coverage.coverage_percent.toFixed(1)}%` : "—"} — {m.coverage.collected ?? "?"} of {m.coverage.expected ?? "?"} expected targets collected.
                </div>
              ) : null}
            </section>
            <section aria-label="Estate-wide alerts" style={{ ...card, flex: "1 1 420px" }}>
              <div style={{ fontWeight: 700, fontSize: 14 }}>Estate-wide</div>
              <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 10 }}>alerts not tied to one system, and the twin this screen reads</div>
              <div style={{ display: "grid", gap: 6 }}>
                {unscoped.map((a) => (
                  <div key={a.id} style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 12 }}>
                    <SevBadge severity={a.severity} />
                    <div><b>{a.title}</b><div style={{ color: "var(--dim)", fontSize: 11.5 }}>{a.next_action}</div></div>
                  </div>
                ))}
                {unscoped.length === 0 ? <div style={{ fontSize: 12, color: "var(--faint)" }}>no estate-wide alert</div> : null}
              </div>
              <div style={{ ...kicker, marginTop: 12 }}>
                twin {m.twin.run_id?.slice(0, 8) ?? "—"} · recorded {fmtWhen(m.twin.recorded_at)} · {m.twin.assets ?? "?"} assets · {m.twin.evidence ?? "?"} evidence
              </div>
              <div style={{ fontSize: 11.5, marginTop: 8, display: "flex", gap: 14, flexWrap: "wrap" }}>
                <Link to="/live-stream" style={{ color: "var(--cyan)" }}>Activity →</Link>
                <Link to="/live-scanners" style={{ color: "var(--cyan)" }}>Live scanners →</Link>
                <Link to="/runtime" style={{ color: "var(--cyan)" }}>Runtime hosts →</Link>
              </div>
            </section>
          </div>
          <details style={{ ...card, marginTop: 14 }}>
            <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 600 }}>What this screen proves, and what it does not</summary>
            <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--dim)", lineHeight: 1.6 }}>
              {[...new Set([...data.fleet.limits, ...data.hosts.limits])].map((l) => <li key={l}>{l}</li>)}
            </ul>
          </details>
        </>
      )}
    </>
  );
}
