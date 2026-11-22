/* Live scanners — the agents scanning the bank, and what each of their collectors read.
 *
 * Every Cryptava agent runs six collectors (HBOM, SBOM, NBOM, CBOM, VBOM, TechBOM) on its
 * host. This page shows, per agent: its heartbeat against the interval, delivery health,
 * link, version, its slice of the estate, and each plane with every source behind it (READ,
 * EMPTY, ABSENT, DISABLED, NOT_CONFIGURED…). Read from /api/v1/operations/fleet.
 * The on-demand scanners that run on the CryptoScan server itself sit below, collapsed. */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiOpsFleet, type OpsAgent, type OpsFleet } from "../lib/api.js";
import { IconSatellite } from "../components/icons";
import ServerScanners from "../components/ServerScanners";
import {
  AgeBar, Disclosure, KpiTile, LIVENESS_COLOR, LIVENESS_LABEL, LiveBar, LivenessPill, OpsHeader, OpsLoadStates,
  PLANE_COLOR, SOURCE_COLOR, SOURCE_MEANING, card, chip, fmtAge, fmtWhen, inputStyle, kicker, useLive,
} from "../components/opsUi";

const BOM_ORDER = ["HBOM", "SBOM", "NBOM", "CBOM", "VBOM", "TECHBOM"];

function PlaneChips({ agent }: { agent: OpsAgent }) {
  const byBom = new Map(agent.planes.map((p) => [p.bom, p]));
  return (
    <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }} aria-label={`Planes of ${agent.name}`}>
      {BOM_ORDER.map((bom) => {
        const p = byBom.get(bom);
        const color = p ? PLANE_COLOR[p.status] ?? "var(--faint)" : "var(--line-strong)";
        return (
          <span key={bom} title={p ? `${p.plane}: ${p.status} — ${p.reason ?? ""}` : `${bom}: not reported`} style={{
            fontSize: 10, fontFamily: "var(--mono)", padding: "2px 6px", borderRadius: 5, fontWeight: 700,
            color, border: `1px solid color-mix(in srgb, ${color} 45%, var(--line))`,
            background: `color-mix(in srgb, ${color} 10%, transparent)`,
          }}>{bom === "TECHBOM" ? "TECH" : bom}</span>
        );
      })}
    </div>
  );
}

function AgentDetail({ agent, fleet }: { agent: OpsAgent; fleet: OpsFleet }) {
  return (
    <div aria-label={`Collectors of ${agent.name}`} style={{ padding: "12px 4px 4px", display: "grid", gap: 12 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
        {[
          ["Host", agent.host.fqdn ?? agent.host.name ?? "—"],
          ["IP", agent.host.ip_addresses.join(", ") || "—"],
          ["OS", [agent.host.os, agent.host.kernel].filter(Boolean).join(" · ") || "—"],
          ["System", agent.system ? `${agent.system.name} · ${agent.system.criticality ?? "?"} · ${agent.system.owner ?? "no owner"}` : "none declared"],
          ["Agent", `${agent.version ?? "?"}${agent.target_version ? ` → ${agent.target_version}` : ""} · ${agent.platform ?? "?"} · link ${agent.link ?? "?"}`],
          ["Signed by", agent.slice?.key_id ? `${agent.slice.key_id} (${agent.slice.authenticity})` : "—"],
          ["Last heartbeat", fmtWhen(agent.liveness.last_heartbeat_at)],
          ["Slice last changed", fmtWhen(agent.slice?.last_changed_at)],
        ].map(([k, v]) => (
          <div key={k}><div style={kicker}>{k}</div><div style={{ fontSize: 12, marginTop: 2, overflowWrap: "anywhere" }}>{v}</div></div>
        ))}
      </div>
      {agent.issues.length ? (
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: "var(--amber)" }}>
          {agent.issues.map((i) => <li key={i}>{i}</li>)}
        </ul>
      ) : null}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 10 }}>
        {agent.planes.map((p) => (
          <div key={p.plane ?? p.bom} aria-label={`Plane ${p.plane}`} style={{ padding: 12, borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", borderTop: `3px solid ${PLANE_COLOR[p.status] ?? "var(--faint)"}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
              <span style={{ fontWeight: 700, fontSize: 12.5 }}>{p.plane}</span>
              <span style={{ fontSize: 10.5, fontWeight: 800, fontFamily: "var(--mono)", color: PLANE_COLOR[p.status] ?? "var(--faint)" }}>{p.status}</span>
            </div>
            <div style={{ fontSize: 11.5, color: "var(--dim)", margin: "4px 0 8px" }}>{p.reason}</div>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <tbody>
                {p.sources.map((s, i) => (
                  <tr key={`${s.source}-${i}`} style={{ borderTop: "1px solid var(--line)" }}>
                    <td style={{ padding: "4px 6px 4px 0", fontFamily: "var(--mono)", overflowWrap: "anywhere" }} title={s.reads ?? undefined}>{s.source}</td>
                    <td style={{ padding: "4px 0", whiteSpace: "nowrap", textAlign: "right" }} title={SOURCE_MEANING[s.state ?? ""] ?? undefined}>
                      <span style={{ color: SOURCE_COLOR[s.state ?? ""] ?? "var(--dim)", fontWeight: 700, fontFamily: "var(--mono)" }}>{s.state}</span>
                      {typeof s.found === "number" ? <span style={{ color: "var(--faint)" }}> · {s.found}</span> : null}
                      {s.note ? <div style={{ color: "var(--faint)", fontSize: 10.5 }}>{s.note}</div> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
        {agent.planes.length === 0 ? <div style={{ fontSize: 12, color: "var(--dim)" }}>This agent has no slice in the estate yet.</div> : null}
      </div>
      <div style={{ fontSize: 11, color: "var(--faint)" }}>
        Late after {fmtAge(fleet.late_after_seconds)}, offline after {fmtAge(fleet.offline_after_seconds)} without a heartbeat.
        {" "}<Link to="/runtime" style={{ color: "var(--cyan)" }}>Open this host in Runtime hosts →</Link>
      </div>
    </div>
  );
}

export default function LiveScanners() {
  const live = useLive<OpsFleet>(apiOpsFleet, 10000);
  const { data, state, error, refresh } = live;
  const [query, setQuery] = useState("");
  const [liveness, setLiveness] = useState<string | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());

  const agents = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data?.agents ?? []).filter((a) =>
      (!liveness || (liveness === "ISSUES" ? a.issues.length > 0 : a.liveness.state === liveness)) &&
      (!q || [a.name, a.host.name, a.host.fqdn, a.system?.name, ...a.host.ip_addresses].some((v) => String(v ?? "").toLowerCase().includes(q))));
  }, [data, query, liveness]);

  const t = data?.totals;
  const planes = t?.plane_states ?? {};
  const sources = t?.source_states ?? {};
  const totalPlanes = Object.values(planes).reduce((a, b) => a + b, 0);
  const totalSources = Object.values(sources).reduce((a, b) => a + b, 0);
  const toggle = (name: string) => setOpen((s) => { const n = new Set(s); if (n.has(name)) n.delete(name); else n.add(name); return n; });

  return (
    <>
      <OpsHeader
        crumb="Operations / Live scanners"
        title="Live scanners"
        icon={<IconSatellite size={18} />}
        sub="The Cryptava agents scanning the bank's servers, and what each of their six collectors read on its host: every plane, every source, and whether it yielded data."
        right={<LiveBar live={live} />}
      />
      {state !== "ready" || !data ? (
        <OpsLoadStates state={state} error={error} refresh={refresh} what="The scanner fleet" />
      ) : (
        <>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 14 }}>
            <KpiTile label="Agents live" ariaLabel="Agents live" value={<>{t?.live ?? 0}<span style={{ fontSize: 14, color: "var(--faint)" }}> / {t?.agents ?? 0}</span></>}
              color={t && t.live === t.agents ? "var(--green)" : "var(--amber)"} onClick={() => setLiveness(liveness === "LIVE" ? null : "LIVE")} active={liveness === "LIVE"}
              sub={`heartbeat every ${fmtAge(data.heartbeat_seconds)}`} />
            <KpiTile label="Not reporting" ariaLabel="Not reporting" value={(t?.by_liveness.OFFLINE ?? 0) + (t?.by_liveness.NEVER_REPORTED ?? 0)}
              color={(t?.by_liveness.OFFLINE ?? 0) ? "var(--red)" : "var(--green)"} onClick={() => setLiveness(liveness === "OFFLINE" ? null : "OFFLINE")} active={liveness === "OFFLINE"}
              sub={`${t?.by_liveness.LATE ?? 0} late · ${t?.by_liveness.NEVER_REPORTED ?? 0} never reported`} />
            <KpiTile label="Agents with issues" ariaLabel="Agents with issues" value={t?.with_issues ?? 0}
              color={t?.with_issues ? "var(--amber)" : "var(--green)"} onClick={() => setLiveness(liveness === "ISSUES" ? null : "ISSUES")} active={liveness === "ISSUES"}
              sub={`${t?.buffered ?? 0} undelivered observation(s)`} />
            <KpiTile label="Planes complete" ariaLabel="Planes complete" value={`${planes.COMPLETE ?? 0} / ${totalPlanes}`}
              color={(planes.FAILED ?? 0) ? "var(--red)" : (planes.PARTIAL ?? 0) ? "var(--amber)" : "var(--green)"}
              sub={`${planes.PARTIAL ?? 0} partial · ${planes.FAILED ?? 0} failed`} />
            <KpiTile label="Sources read" ariaLabel="Sources read" value={`${sources.READ ?? 0} / ${totalSources}`}
              sub={`${sources.NOT_CONFIGURED ?? 0} need configuration · ${sources.DISABLED ?? 0} disabled`} />
          </div>

          <section aria-label="Scanner fleet" style={card}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontWeight: 700, fontSize: 14, marginRight: "auto" }}>Agents <span style={{ color: "var(--faint)", fontWeight: 500 }}>{agents.length} of {data.agents.length}</span></div>
              <input aria-label="Search agents" placeholder="Search host, IP, system…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ ...inputStyle, minWidth: 220 }} />
              {(["LIVE", "LATE", "OFFLINE", "NEVER_REPORTED"] as const).map((s) => (
                <button key={s} aria-label={`Only ${LIVENESS_LABEL[s]}`} style={chip(liveness === s, LIVENESS_COLOR[s])} onClick={() => setLiveness(liveness === s ? null : s)}>
                  {LIVENESS_LABEL[s]} {t?.by_liveness[s] ?? 0}
                </button>
              ))}
            </div>
            <div style={{ overflowX: "auto" }}>
              <table aria-label="Agents" style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--faint)", fontSize: 10.5, fontFamily: "var(--mono)", letterSpacing: ".06em" }}>
                    {["AGENT / HOST", "SYSTEM", "STATUS", "HEARTBEAT", "DELIVERY", "PLANES", "SLICE", ""].map((h) => <th key={h} style={{ padding: "6px 8px", fontWeight: 600 }}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {agents.map((a) => (
                    <React.Fragment key={a.name}>
                      <tr style={{ borderTop: "1px solid var(--line)", verticalAlign: "top" }}>
                        <td style={{ padding: "10px 8px" }}>
                          <div style={{ fontWeight: 700 }}>{a.host.name ?? a.name}</div>
                          <div style={{ fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>{a.name}</div>
                          <div style={{ fontSize: 11, color: "var(--dim)" }}>{a.host.ip_addresses.join(", ")}</div>
                        </td>
                        <td style={{ padding: "10px 8px" }}>
                          <div>{a.system?.name ?? <span style={{ color: "var(--faint)" }}>none declared</span>}</div>
                          {a.system?.criticality ? <div style={{ fontSize: 11, color: "var(--dim)" }}>{a.system.criticality}</div> : null}
                        </td>
                        <td style={{ padding: "10px 8px" }}><LivenessPill state={a.liveness.state} /></td>
                        <td style={{ padding: "10px 8px", minWidth: 130 }}>
                          <div style={{ fontSize: 11.5, fontFamily: "var(--mono)", marginBottom: 4 }}>{a.liveness.age_seconds === null ? "never" : `${fmtAge(a.liveness.age_seconds)} ago`}</div>
                          <AgeBar age={a.liveness.age_seconds} late={data.late_after_seconds} offline={data.offline_after_seconds} label={`Heartbeat age of ${a.name}`} />
                        </td>
                        <td style={{ padding: "10px 8px", fontSize: 11.5 }}>
                          {a.healthy === false ? <span style={{ color: "var(--red)", fontWeight: 700 }}>failing</span>
                            : a.buffered ? <span style={{ color: "var(--amber)", fontWeight: 700 }}>{a.buffered} buffered</span>
                            : a.healthy ? <span style={{ color: "var(--green)" }}>delivering</span> : <span style={{ color: "var(--faint)" }}>—</span>}
                          <div style={{ color: "var(--faint)" }}>{a.link ?? ""}{a.version ? ` · v${a.version}` : ""}</div>
                        </td>
                        <td style={{ padding: "10px 8px" }}><PlaneChips agent={a} /></td>
                        <td style={{ padding: "10px 8px", fontSize: 11.5, color: "var(--dim)", whiteSpace: "nowrap" }}>
                          {a.slice ? <>{a.slice.assets} assets<br />{a.slice.evidence} evidence</> : "no slice"}
                        </td>
                        <td style={{ padding: "10px 8px", textAlign: "right" }}>
                          <button className="btn" aria-expanded={open.has(a.name)} aria-label={`Collectors for ${a.name}`} style={{ padding: "4px 10px", fontSize: 11.5 }} onClick={() => toggle(a.name)}>
                            {open.has(a.name) ? "Hide" : "Collectors"}
                          </button>
                        </td>
                      </tr>
                      {open.has(a.name) ? (
                        <tr><td colSpan={8} style={{ padding: "0 8px 12px" }}><AgentDetail agent={a} fleet={data} /></td></tr>
                      ) : null}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
              {agents.length === 0 ? <div style={{ padding: 14, fontSize: 12.5, color: "var(--dim)" }}>No agent matches.</div> : null}
            </div>
            <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginTop: 12, fontSize: 11, color: "var(--faint)" }}>
              {Object.entries(SOURCE_MEANING).map(([k, v]) => (
                <span key={k}><b style={{ color: SOURCE_COLOR[k], fontFamily: "var(--mono)" }}>{k}</b> {v}</span>
              ))}
            </div>
          </section>
        </>
      )}
      <Disclosure title="Scanners on the CryptoScan server" sub="On-demand hardware, runtime, network, container, OT, cloud and source scanners that run on the platform host itself — separate from the agents above.">
        <ServerScanners embedded />
      </Disclosure>
    </>
  );
}
