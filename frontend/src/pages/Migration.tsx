/* PQC migration plan — which systems move, in what order, and what moves in each.
 *
 * The plan is read from the agents' estate graph. Systems that hold quantum-vulnerable,
 * broken or deprecated crypto are put into waves in dependency order: a provider moves before
 * the systems that call it, and systems that call each other move together. Each system lists
 * what it must replace and with what. The estate-wide workstreams (for example
 * RSA → ML-KEM-768 / ML-DSA-65) link to the Simulation, which shows the full impact, and to
 * Tasks, which opens the work.
 */
import React from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar } from "../components/ui";
import { IconSecurity, IconCrypto } from "../components/icons";
import {
  SEVERITIES, SEV_TONE, EstateLoadStates, PageHeader, kicker, observedLine, tile, useEstateRead,
} from "../components/remediationUi";
import { apiEstateMigrationWaves } from "../lib/api.js";
import type { EstateMigrationWaves, MigrationWaveSystem } from "../lib/api.js";

const read = () => apiEstateMigrationWaves();
const ok = (d: EstateMigrationWaves) => Array.isArray(d.waves);

const CLASS_LABEL: Record<string, string> = {
  broken: "broken", deprecated: "deprecated", quantum_vulnerable: "quantum-vulnerable", symmetric_short: "short symmetric key",
};
const CLASS_TONE: Record<string, string> = { broken: "red", deprecated: "orange", quantum_vulnerable: "amber", symmetric_short: "slate" };
const simulateHref = (from: string, to: string) => `/simulation?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
const tasksHref = (from: string, to: string) => `/remediation?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;

function SystemCard({ s }: { s: MigrationWaveSystem }) {
  const open = SEVERITIES.filter((x) => s.open_findings[x]);
  return (
    <div aria-label={`System ${s.name}`} style={{ ...tile, padding: 12, display: "grid", gap: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        <span style={{ fontSize: 13.5, fontWeight: 800 }}>{s.name}</span>
        <span style={{ fontSize: 11, color: "var(--faint)" }}>{[s.criticality, s.owner].filter(Boolean).join(" · ")}</span>
      </div>
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 3 }}>
          <span>quantum-safe today</span><span style={{ fontFamily: "var(--mono)" }}>{s.readiness_pct == null ? "—" : `${s.readiness_pct}%`}</span>
        </div>
        <Bar value={(s.readiness_pct ?? 0) / 100} tone={(s.readiness_pct ?? 0) >= 80 ? "green" : (s.readiness_pct ?? 0) >= 40 ? "amber" : "red"} />
      </div>
      {s.moves.length > 0 && (
        <ul aria-label={`What moves in ${s.name}`} style={{ margin: 0, paddingLeft: 0, listStyle: "none", display: "grid", gap: 4 }}>
          {s.moves.map((m) => (
            <li key={m.algorithm} style={{ fontSize: 11.5, display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <Badge tone={CLASS_TONE[m.class] || "slate"}>{CLASS_LABEL[m.class] || m.class}</Badge>
              <span style={{ fontFamily: "var(--mono)" }}>{m.algorithm}</span>
              <span style={{ color: "var(--faint)" }}>×{m.uses}</span>
              {m.replace_with && <span style={{ color: "var(--dim)" }}>→ {m.replace_with}</span>}
            </li>
          ))}
        </ul>
      )}
      {s.rationale && <div style={{ fontSize: 11.5, color: "var(--dim)", lineHeight: 1.45 }}><b style={{ color: "var(--text)" }}>Order: </b>{s.rationale}</div>}
      {(s.depends_on.length > 0 || s.called_by.length > 0) && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          {s.depends_on.length > 0 && <>calls {s.depends_on.join(", ")}</>}
          {s.depends_on.length > 0 && s.called_by.length > 0 && " · "}
          {s.called_by.length > 0 && <>called by {s.called_by.join(", ")}</>}
        </div>
      )}
      {open.length > 0 && (
        <div style={{ display: "flex", gap: 5, flexWrap: "wrap", alignItems: "center" }}>
          <span style={kicker}>OPEN FINDINGS</span>
          {open.map((x) => <Badge key={x} tone={SEV_TONE[x]}>{`${s.open_findings[x]} ${x.toLowerCase()}`}</Badge>)}
          <Link to="/priorities" style={{ fontSize: 11, color: "var(--amber)" }}>see them →</Link>
        </div>
      )}
    </div>
  );
}

export default function Migration() {
  const { data, state, error, load } = useEstateRead(read, ok);
  const uses = data?.totals.algorithm_uses ?? {};
  const weak = (uses.broken ?? 0) + (uses.deprecated ?? 0);

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <PageHeader kickerText="REMEDIATION · MIGRATION WAVES FROM THE ESTATE" title="PQC migration plan" icon={<IconCrypto size={18} />} color="var(--violet)">
        <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 800 }}>
          Which systems move, in what order, and what moves in each, read from the estate the agents report.
          A provider moves before the systems that call it, so no caller switches before its peer can answer.
        </p>
        <div style={{ display: "flex", gap: 12, marginTop: 10, fontSize: 11.5, color: "var(--dim)", flexWrap: "wrap", alignItems: "center" }}>
          <IconSecurity size={13} /> <span>A plan only — nothing is re-keyed or deployed from here.</span>
          {data && <span style={{ fontFamily: "var(--mono)", color: "var(--faint)" }}>{observedLine(data.run_id, data.observed_at)}</span>}
        </div>
      </PageHeader>

      <EstateLoadStates state={state} error={error} load={load} what="The migration plan" />

      {data && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 12 }}>
            <div aria-label="Systems to migrate" style={{ ...tile, borderTop: "3px solid var(--violet)" }}>
              <div style={kicker}>SYSTEMS TO MIGRATE</div>
              <div style={{ fontSize: 26, fontWeight: 800 }}>{data.totals.to_migrate}<span style={{ fontSize: 13, color: "var(--faint)" }}> / {data.totals.systems}</span></div>
              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>in {data.waves.length} wave{data.waves.length === 1 ? "" : "s"}</div>
            </div>
            <div style={{ ...tile, borderTop: `3px solid ${(data.totals.readiness_pct ?? 0) >= 80 ? "var(--green)" : "var(--amber)"}` }}>
              <div style={kicker}>QUANTUM-SAFE TODAY</div>
              <div style={{ fontSize: 26, fontWeight: 800 }}>{data.totals.readiness_pct == null ? "—" : `${data.totals.readiness_pct}%`}</div>
              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>of {Object.entries(uses).filter(([k]) => k !== "unknown").reduce((a, [, n]) => a + n, 0)} classified algorithm uses</div>
            </div>
            <div style={{ ...tile, borderTop: "3px solid var(--amber)" }}>
              <div style={kicker}>QUANTUM-VULNERABLE USES</div>
              <div style={{ fontSize: 26, fontWeight: 800, color: uses.quantum_vulnerable ? "var(--amber)" : undefined }}>{uses.quantum_vulnerable ?? 0}</div>
              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>RSA, ECDSA, ECDH, Ed25519… (Shor)</div>
            </div>
            <div style={{ ...tile, borderTop: `3px solid ${weak ? "var(--red)" : "var(--line)"}` }}>
              <div style={kicker}>BROKEN OR DEPRECATED</div>
              <div style={{ fontSize: 26, fontWeight: 800, color: weak ? "var(--red)" : undefined }}>{weak}</div>
              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>weak today, no quantum computer needed</div>
            </div>
          </div>

          <Panel title="Workstreams" sub="each family of weak crypto across the estate, worst first" style={{ marginTop: 14 }}>
            {data.workstreams.length === 0 ? (
              <div style={{ fontSize: 12.5, color: "var(--dim)" }}>No weak or quantum-vulnerable algorithm was observed.</div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table className="tbl" aria-label="Migration workstreams" style={{ width: "100%" }}>
                  <thead><tr><th>Move</th><th>Why</th><th>Uses</th><th>Systems</th><th /></tr></thead>
                  <tbody>
                    {data.workstreams.map((w) => (
                      <tr key={`${w.class}-${w.family}`}>
                        <td style={{ fontFamily: "var(--mono)", fontSize: 12 }}><b>{w.algorithms.join(", ")}</b>{w.targets.length > 0 && <span style={{ color: "var(--dim)" }}> → {w.targets.join(" / ")}</span>}</td>
                        <td><Badge tone={CLASS_TONE[w.class] || "slate"}>{CLASS_LABEL[w.class] || w.class}</Badge></td>
                        <td style={{ fontFamily: "var(--mono)" }}>{w.uses}</td>
                        <td style={{ fontSize: 11.5 }}>{w.systems.join(", ") || "—"}</td>
                        <td style={{ whiteSpace: "nowrap" }}>
                          {w.simulate && (
                            <>
                              <Link className="btn sm" to={simulateHref(w.simulate.from_algo, w.simulate.to_algo)} aria-label={`Simulate ${w.simulate.from_algo} to ${w.simulate.to_algo}`}>Simulate</Link>{" "}
                              <Link className="btn sm" to={tasksHref(w.simulate.from_algo, w.simulate.to_algo)} aria-label={`Plan tasks for ${w.simulate.from_algo} to ${w.simulate.to_algo}`}>Plan tasks</Link>
                            </>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <div aria-label="Migration waves" style={{ display: "grid", gap: 14, marginTop: 14 }}>
            {data.waves.map((w) => (
              <Panel key={w.wave} title={`Wave ${w.wave}`} sub={`${w.focus} · ${w.systems.length} system${w.systems.length === 1 ? "" : "s"}`}>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(290px, 1fr))", gap: 10 }}>
                  {w.systems.map((s) => <SystemCard key={s.system_id} s={s} />)}
                </div>
              </Panel>
            ))}
          </div>

          {data.no_migration_needed.length > 0 && (
            <Panel title="No migration needed" sub="no weak or quantum-vulnerable crypto observed — that is not proof nothing is there" style={{ marginTop: 14 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {data.no_migration_needed.map((s) => (
                  <span key={s.system_id} style={{ fontSize: 12, border: "1px solid var(--line)", borderRadius: 999, padding: "3px 10px" }}>
                    {s.name}{s.readiness_pct != null && <span style={{ color: "var(--faint)" }}> · {s.readiness_pct}% safe</span>}
                  </span>
                ))}
              </div>
            </Panel>
          )}

          <details style={{ ...tile, marginTop: 14 }}>
            <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 700 }}>How the order is decided ({data.unknowns.length} unknown{data.unknowns.length === 1 ? "" : "s"})</summary>
            <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--dim)", lineHeight: 1.6 }}>
              <li>{data.rule}.</li>
              {data.unknowns.map((u) => <li key={u}>{u}</li>)}
            </ul>
          </details>
        </>
      )}
    </div>
  );
}
