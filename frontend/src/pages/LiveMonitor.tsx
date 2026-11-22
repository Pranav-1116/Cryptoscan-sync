/* Live monitor — is the estate being watched right now, and what needs somebody's attention?
 *
 * One read (/api/v1/operations/monitor) every few seconds:
 *   - the overall state, from the agents' heartbeats and the deterministic alert rules;
 *   - every alert, with its rule, its threshold, since when, and what to do;
 *   - every agent's heartbeat age against the late and offline thresholds, and its signed
 *     CPU / memory samples.
 * Nothing here scans. A quiet screen means the agents are reporting, not that the estate is safe. */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiOpsMonitor, type OpsMonitor } from "../lib/api.js";
import { IconHealth } from "../components/icons";
import {
  AgeBar, KpiTile, LiveBar, LivenessPill, MiniSpark, OPS_SEV_COLOR, OpsHeader, OpsLoadStates, SevBadge,
  card, chip, fmtAge, fmtWhen, agoFrom, kicker, metricValue, pctColor, useLive,
} from "../components/opsUi";

const STATUS_COLOR: Record<string, string> = {
  OPERATIONAL: "var(--green)", DEGRADED: "var(--amber)", DOWN: "var(--red)", NOT_CONNECTED: "var(--faint)",
};
const STATUS_LABEL: Record<string, string> = {
  OPERATIONAL: "Operational", DEGRADED: "Degraded", DOWN: "Down", NOT_CONNECTED: "Not connected",
};

function StatusBanner({ data }: { data: OpsMonitor }) {
  const color = STATUS_COLOR[data.status.state] ?? "var(--faint)";
  return (
    <section aria-label="Estate status" style={{
      ...card, display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap", marginBottom: 14,
      borderColor: `color-mix(in srgb, ${color} 45%, var(--line))`,
      background: `linear-gradient(90deg, color-mix(in srgb, ${color} 14%, var(--panel)) 0%, var(--panel) 60%)`,
    }}>
      <div style={{ width: 14, height: 14, borderRadius: 99, background: color, boxShadow: `0 0 0 6px color-mix(in srgb, ${color} 20%, transparent)` }} />
      <div style={{ flex: "1 1 360px" }}>
        <div style={{ fontSize: 20, fontWeight: 800, color }}>{STATUS_LABEL[data.status.state] ?? data.status.state}</div>
        <div style={{ fontSize: 13.5, fontWeight: 600, marginTop: 2 }}>{data.status.headline}</div>
        <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 2 }}>{data.status.meaning}</div>
      </div>
      <div style={{ fontSize: 11.5, color: "var(--dim)", fontFamily: "var(--mono)", textAlign: "right", lineHeight: 1.6 }}>
        <div>estate connection <b style={{ color: data.connection.state === "LIVE" ? "var(--green)" : "var(--amber)" }}>{data.connection.state}</b></div>
        <div>last observation {fmtWhen(data.connection.last_observation)}</div>
      </div>
    </section>
  );
}

function AlertsPanel({ data, now }: { data: OpsMonitor; now: number }) {
  const [sev, setSev] = useState<string | null>(null);
  const shown = useMemo(() => data.alerts.filter((a) => !sev || a.severity === sev), [data.alerts, sev]);
  return (
    <section aria-label="Alerts" style={{ ...card, flex: "1 1 520px", minWidth: 320 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14 }}>Alerts</div>
          <div style={{ fontSize: 11.5, color: "var(--dim)" }}>deterministic rules over what the agents reported — thresholds stated on each</div>
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          <button style={chip(sev === null)} onClick={() => setSev(null)}>All {data.alerts.length}</button>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
            <button key={s} aria-label={`Only ${s}`} style={chip(sev === s, OPS_SEV_COLOR[s])} onClick={() => setSev(sev === s ? null : s)}>
              {s} {data.alert_counts[s] ?? 0}
            </button>
          ))}
        </div>
      </div>
      {shown.length === 0 ? (
        <div style={{ padding: "18px 4px", fontSize: 12.5, color: "var(--dim)" }}>
          {data.alerts.length === 0 ? "No rule fired. Every agent is reporting inside its interval." : "No alert at this severity."}
        </div>
      ) : (
        <ol aria-label="Alert list" style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 8 }}>
          {shown.map((a) => (
            <li key={a.id} aria-label={`Alert ${a.title}`} style={{
              display: "grid", gridTemplateColumns: "auto 1fr auto", gap: 10, alignItems: "start", padding: "10px 12px",
              borderRadius: "var(--r)", background: "var(--panel-2)", borderLeft: `3px solid ${OPS_SEV_COLOR[a.severity]}`,
            }}>
              <SevBadge severity={a.severity} />
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 700, fontSize: 13 }}>{a.title}</div>
                {a.detail ? <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 2, overflowWrap: "anywhere" }}>{a.detail}</div> : null}
                <div style={{ fontSize: 11.5, marginTop: 4 }}><span style={{ color: "var(--faint)" }}>Next: </span>{a.next_action}</div>
                <div style={{ fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)", marginTop: 4 }}>
                  {a.rule}{a.system ? ` · ${a.system}` : ""}{a.agent ? ` · ${a.agent}` : ""}
                </div>
              </div>
              <div style={{ textAlign: "right", fontSize: 11, color: "var(--dim)", whiteSpace: "nowrap" }}>
                {a.since ? <div title={fmtWhen(a.since)}>{fmtAge(agoFrom(a.since, now))} ago</div> : null}
                {a.link ? <Link to={a.link} style={{ color: "var(--cyan)" }}>Open</Link> : null}
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

function FleetGrid({ data }: { data: OpsMonitor }) {
  const f = data.fleet;
  return (
    <section aria-label="Agent freshness" style={{ ...card, flex: "1 1 520px", minWidth: 320 }}>
      <div style={{ fontWeight: 700, fontSize: 14 }}>Agent freshness</div>
      <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 10 }}>
        heartbeat age per agent — late after {fmtAge(f.late_after_seconds)}, offline after {fmtAge(f.offline_after_seconds)}
      </div>
      {f.agents.length === 0 ? (
        <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No agent is enrolled.</div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: 10 }}>
          {f.agents.map((a) => {
            const cpu = metricValue(a.performance.latest, "cpu_pct");
            const ram = metricValue(a.performance.latest, "ram_pct");
            const cpuSeries = (a.performance.series?.cpu_pct ?? []).map((p) => p[1]);
            return (
              <div key={a.name} aria-label={`Agent ${a.name}`} style={{ padding: 12, borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "flex-start" }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 700, fontSize: 12.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={a.name}>
                      {a.host.name ?? a.name}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--dim)" }}>{a.system?.name ?? "no system declared"}</div>
                  </div>
                  <LivenessPill state={a.liveness.state} />
                </div>
                <div style={{ margin: "10px 0 4px", display: "flex", justifyContent: "space-between", fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)" }}>
                  <span>heartbeat</span><span>{a.liveness.age_seconds === null ? "never" : `${fmtAge(a.liveness.age_seconds)} ago`}</span>
                </div>
                <AgeBar age={a.liveness.age_seconds} late={f.late_after_seconds} offline={f.offline_after_seconds}
                  label={`Heartbeat age of ${a.name}`} />
                <div style={{ display: "flex", gap: 12, marginTop: 10, alignItems: "flex-end", justifyContent: "space-between" }}>
                  <div style={{ fontSize: 11.5, fontFamily: "var(--mono)", lineHeight: 1.5 }}>
                    <div>CPU <b style={{ color: pctColor(cpu) }}>{cpu === null ? "—" : `${cpu.toFixed(0)}%`}</b></div>
                    <div>RAM <b style={{ color: pctColor(ram) }}>{ram === null ? "—" : `${ram.toFixed(0)}%`}</b></div>
                  </div>
                  {a.performance.state === "NOT_SAMPLED" ? (
                    <span style={{ fontSize: 10.5, color: "var(--faint)" }}>not sampled</span>
                  ) : (
                    <MiniSpark points={cpuSeries} max={100} color={pctColor(cpu)} label={`CPU of ${a.name}`} width={110} />
                  )}
                </div>
                {a.issues.length ? (
                  <div style={{ marginTop: 8, fontSize: 11, color: "var(--amber)" }}>{a.issues[0]}{a.issues.length > 1 ? ` (+${a.issues.length - 1})` : ""}</div>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default function LiveMonitor() {
  const live = useLive<OpsMonitor>(apiOpsMonitor, 10000);
  const { data, state, error, refresh, now } = live;
  const [wall, setWall] = useState(false);

  const totals = data?.fleet.totals;
  const urgent = (data?.alert_counts.CRITICAL ?? 0) + (data?.alert_counts.HIGH ?? 0);
  const coverage = data?.coverage?.coverage_percent;

  return (
    <div style={wall ? { position: "fixed", inset: 0, zIndex: 50, background: "var(--bg)", overflow: "auto", padding: 24 } : undefined}>
      <OpsHeader
        crumb="Operations / Live monitor"
        title="Live monitor"
        icon={<IconHealth size={18} />}
        sub="Is the estate being watched right now, and what needs attention. Read from the agents' heartbeats, their signed performance samples and the estate change feed."
        right={
          <div style={{ display: "flex", flexDirection: "column", gap: 8, alignItems: "flex-end" }}>
            <LiveBar live={live} />
            <button className="btn" style={{ padding: "4px 10px", fontSize: 11.5 }} onClick={() => setWall(!wall)}>
              {wall ? "Exit wallboard" : "Wallboard"}
            </button>
          </div>
        }
      />
      {state !== "ready" || !data ? (
        <OpsLoadStates state={state} error={error} refresh={refresh} what="The live monitor" />
      ) : (
        <>
          <StatusBanner data={data} />
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
            <KpiTile label="Agents live" ariaLabel="Agents live"
              value={<>{totals?.live ?? 0}<span style={{ fontSize: 14, color: "var(--faint)" }}> / {totals?.agents ?? 0}</span></>}
              color={totals && totals.live === totals.agents && totals.agents > 0 ? "var(--green)" : "var(--amber)"}
              sub={`${totals?.reporting ?? 0} reporting · ${(totals?.by_liveness.OFFLINE ?? 0)} offline`} />
            <KpiTile label="Critical & high alerts" ariaLabel="Critical and high alerts" value={urgent}
              color={urgent ? "var(--red)" : "var(--green)"} sub={`${data.alerts.length} alert(s) in total`} />
            <KpiTile label="Estate age" ariaLabel="Estate age" value={fmtAge(data.connection.seconds_since)}
              color={data.connection.state === "LIVE" ? "var(--green)" : "var(--amber)"}
              sub={`stale after ${fmtAge(data.connection.stale_after_seconds)}`} />
            <KpiTile label="Collection coverage" ariaLabel="Collection coverage"
              value={typeof coverage === "number" ? `${coverage.toFixed(1)}%` : "—"}
              color={typeof coverage === "number" ? pctColor(100 - coverage, 20, 40) : "var(--faint)"}
              sub={data.coverage ? `${data.coverage.collected ?? "?"} of ${data.coverage.expected ?? "?"} expected targets` : "no coverage recorded"} />
            <KpiTile label="Unreviewed changes" ariaLabel="Unreviewed changes" value={data.changes.unacknowledged}
              color={data.changes.unacknowledged ? "var(--amber)" : "var(--green)"}
              sub={data.changes.last_at ? `last ${fmtAge(agoFrom(data.changes.last_at, now))} ago` : "no change stored"} />
          </div>
          <div style={{ display: "flex", gap: 14, flexWrap: "wrap", alignItems: "flex-start" }}>
            <AlertsPanel data={data} now={now} />
            <FleetGrid data={data} />
          </div>
          <details style={{ ...card, marginTop: 14 }}>
            <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 600 }}>What this screen proves, and what it does not</summary>
            <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--dim)", lineHeight: 1.6 }}>
              {data.limits.map((l) => <li key={l}>{l}</li>)}
            </ul>
            <div style={{ ...kicker, marginTop: 8 }}>twin {data.twin.run_id?.slice(0, 8) ?? "—"} · recorded {fmtWhen(data.twin.recorded_at)} · {data.twin.assets ?? "?"} assets</div>
          </details>
        </>
      )}
    </div>
  );
}
