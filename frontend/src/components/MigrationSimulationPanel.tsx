/* Migration simulation — one crypto change, read against the Digital Twin.
 *
 * The estate scenarios above answer "which evidence would change". This panel answers the
 * questions a migration owner asks next, from what the Digital Twin holds about each system
 * the change touches: the hardware its keys live on, the software implementing the crypto,
 * the systems it is connected to and the vendors behind it. It reports
 *
 *   1. parallel or direct — and exactly why;
 *   2. how to migrate — ordered phases, providers before their callers;
 *   3. what can go wrong during the migration, with who acts and what to do;
 *   4. what it does to vendors and to connected systems;
 *   5. what the twin could not see.
 *
 * Read-only: it runs the `algorithm_migration` twin scenario, which mutates nothing. Unknown
 * capability is shown as unknown — never as a pass.
 */
import React, { useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge } from "./ui";
import { apiMigrationSimulation } from "../lib/api.js";
import type {
  MigrationSimulation, MigrationStrategy, MigrationSeverity, MigrationSystemReport, MigrationPlanStep,
} from "../lib/api.js";

const STRATEGY_TONE: Record<MigrationStrategy, string> = {
  BLOCKED: "red", PARALLEL: "amber", DIRECT: "green", NOT_DETERMINED: "slate",
};
const STRATEGY_LABEL: Record<MigrationStrategy, string> = {
  BLOCKED: "BLOCKED — CLEAR PREREQUISITES FIRST",
  PARALLEL: "PARALLEL MIGRATION",
  DIRECT: "DIRECT (NORMAL) MIGRATION",
  NOT_DETERMINED: "NOT DETERMINED",
};
const SEVERITY_TONE: Record<MigrationSeverity, string> = {
  BLOCKER: "red", HIGH: "orange", MEDIUM: "amber", INFO: "slate",
};
const SUPPORT_TONE: Record<string, string> = {
  SUPPORTED: "green", SUPPORTED_DECLARED: "green", READY: "green",
  NOT_SUPPORTED: "red", NOT_READY: "red",
  UNKNOWN: "slate", NOT_RECORDED_FOR_TARGET: "slate",
};
const PHASE_LABEL: Record<MigrationPlanStep["phase"], string> = {
  PREREQUISITES: "PREREQUISITES", KEYS_AND_TRUST: "KEYS & TRUST", ENABLE_ALONGSIDE: "RUN SIDE BY SIDE",
  CUT_OVER: "CUT-OVER", VERIFY: "VERIFY", DECOMMISSION: "RETIRE OLD",
};
const PRESETS: { from: string; to: string; why: string }[] = [
  { from: "RSA", to: "ML-KEM-768", why: "key exchange → post-quantum" },
  { from: "RSA", to: "ML-DSA-65", why: "signatures → post-quantum" },
  { from: "ECDSA", to: "ML-DSA-65", why: "ECC signatures → post-quantum" },
  { from: "3DES", to: "AES-256-GCM", why: "retire a legacy cipher" },
];

const inputStyle: React.CSSProperties = {
  padding: "7px 9px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)",
  color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12.5,
};
const labelStyle: React.CSSProperties = { display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--faint)" };
const boxStyle: React.CSSProperties = {
  padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)",
};

export default function MigrationSimulationPanel({ algorithms, suggested }: {
  /** algorithm values the estate's evidence actually holds — offered as quick picks */
  algorithms?: string[];
  /** the from/to currently typed into the estate scenario form, if any */
  suggested?: { from?: string; to?: string };
}) {
  const [from, setFrom] = useState("RSA");
  const [to, setTo] = useState("ML-KEM-768");
  const [systems, setSystems] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<MigrationSimulation | null>(null);

  const simulate = async () => {
    if (!from.trim() || !to.trim()) return;
    setBusy(true);
    setError(null);
    const response = await apiMigrationSimulation({
      from_algo: from.trim(), to_algo: to.trim(), ...(systems.trim() ? { systems: systems.trim() } : {}),
    });
    setBusy(false);
    if (response.data?.migration) {
      setResult(response.data.migration);
    } else {
      setResult(null);
      setError(response.detail || response.error ||
        "The Digital Twin returned no migration answer — the backend may predate this feature.");
    }
  };

  const canUseSuggested = Boolean(suggested?.from && suggested?.to &&
    (suggested.from !== from || suggested.to !== to));

  return (
    <Panel
      title="Migration simulation — checked against the Digital Twin"
      sub="hardware, software, connected systems and vendors → how to migrate, what can go wrong, who else is affected, and parallel or direct"
    >
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
        <label style={labelStyle}>
          Current algorithm
          <input aria-label="Current algorithm" value={from} onChange={(e) => setFrom(e.target.value)} style={{ ...inputStyle, width: 150 }} />
        </label>
        <span style={{ paddingBottom: 8, color: "var(--faint)" }}>→</span>
        <label style={labelStyle}>
          Target algorithm
          <input aria-label="Target algorithm" value={to} onChange={(e) => setTo(e.target.value)} style={{ ...inputStyle, width: 150 }} />
        </label>
        <label style={labelStyle}>
          Only these systems (optional, comma-separated)
          <input aria-label="Only these systems" value={systems} placeholder="all systems using it"
                 onChange={(e) => setSystems(e.target.value)} style={{ ...inputStyle, width: 240 }} />
        </label>
        <button type="button" className="btn primary" onClick={simulate} disabled={busy || !from.trim() || !to.trim()}>
          {busy ? "Reading the twin…" : "Simulate migration"}
        </button>
        {canUseSuggested && (
          <button type="button" className="btn" onClick={() => { setFrom(suggested!.from!); setTo(suggested!.to!); }}
                  title="copy the from/to of the scenario form above">
            Use {suggested!.from} → {suggested!.to}
          </button>
        )}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
        {PRESETS.map((p) => (
          <button key={`${p.from}>${p.to}`} type="button" title={p.why}
                  aria-pressed={from === p.from && to === p.to}
                  onClick={() => { setFrom(p.from); setTo(p.to); }}
                  style={{
                    padding: "4px 9px", borderRadius: 999, fontSize: 11, cursor: "pointer", fontFamily: "var(--mono)",
                    background: from === p.from && to === p.to ? "color-mix(in srgb, var(--violet) 16%, transparent)" : "var(--panel-2)",
                    border: `1px solid ${from === p.from && to === p.to ? "var(--violet)" : "var(--line)"}`, color: "var(--text)",
                  }}>
            {p.from} → {p.to}
          </button>
        ))}
        {(algorithms ?? []).filter((a) => !PRESETS.some((p) => p.from === a)).slice(0, 6).map((a) => (
          <button key={`estate:${a}`} type="button" title="an algorithm this estate's evidence holds"
                  onClick={() => setFrom(a)}
                  style={{ padding: "4px 9px", borderRadius: 999, fontSize: 11, cursor: "pointer", fontFamily: "var(--mono)",
                           background: "transparent", border: "1px dashed var(--line)", color: "var(--dim)" }}>
            from {a}
          </button>
        ))}
      </div>
      <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 6 }}>
        Read-only — runs the Digital Twin's <span style={{ fontFamily: "var(--mono)" }}>algorithm_migration</span> scenario
        on a snapshot and changes nothing. Capability that was never recorded is reported as unknown, not as supported.
        The full twin is on the <Link to="/digital-twin">Digital Twin</Link> page.
      </div>

      {error && (
        <div role="alert" style={{ ...boxStyle, marginTop: 10, borderColor: "var(--red)", fontSize: 12, color: "var(--dim)" }}>
          {error}
        </div>
      )}
      {result && <MigrationResult result={result} />}
    </Panel>
  );
}

export function MigrationResult({ result }: { result: MigrationSimulation }) {
  const strategy = result.strategy.recommended;
  const ctx = result.twin_context;
  return (
    <div aria-label="Migration simulation result" style={{ marginTop: 14, display: "grid", gap: 12 }}>
      {/* 1 — the verdict */}
      <div style={{
        ...boxStyle, borderColor: `var(--${STRATEGY_TONE[strategy] === "slate" ? "line" : STRATEGY_TONE[strategy]})`,
        background: `color-mix(in srgb, var(--${STRATEGY_TONE[strategy] === "slate" ? "faint" : STRATEGY_TONE[strategy]}) 7%, var(--panel-2))`,
      }}>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div className="kicker" style={{ fontSize: 9.5 }}>RECOMMENDED STRATEGY</div>
          <Badge tone={STRATEGY_TONE[strategy]}>{STRATEGY_LABEL[strategy]}</Badge>
          <span style={{ fontSize: 11.5, color: "var(--dim)" }}>{result.strategy.meaning}</span>
        </div>
        <div style={{ fontSize: 13.5, fontWeight: 700, marginTop: 8 }}>{result.headline}</div>
        {strategy !== "NOT_DETERMINED" && (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8 }}>
            {(["BLOCKED", "PARALLEL", "DIRECT"] as const).map((s) => (
              <span key={s} style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--dim)" }}>
                <Badge tone={STRATEGY_TONE[s]}>{s}</Badge> {result.strategy.systems[s]} system(s)
              </span>
            ))}
          </div>
        )}
        {Object.keys(result.strategy.reasons).length > 0 && (
          <div style={{ marginTop: 10 }}>
            <div className="kicker" style={{ fontSize: 9.5, marginBottom: 4 }}>WHY</div>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {Object.entries(result.strategy.reasons).map(([code, n]) => (
                <span key={code} style={{ fontSize: 10.5, fontFamily: "var(--mono)", padding: "2px 8px", borderRadius: 999,
                                          border: "1px solid var(--line)", color: "var(--dim)" }}>
                  {code.replace(/_/g, " ").toLowerCase()} · {n}
                </span>
              ))}
            </div>
          </div>
        )}
        {result.strategy.parallel_mechanisms.length > 0 && (
          <div style={{ marginTop: 10 }}>
            <div className="kicker" style={{ fontSize: 9.5, marginBottom: 4 }}>HOW TO RUN OLD AND NEW SIDE BY SIDE</div>
            <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.6 }}>
              {result.strategy.parallel_mechanisms.map((m) => (
                <li key={m.mechanism}><b style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{m.mechanism}</b> — {m.how}</li>
              ))}
            </ul>
          </div>
        )}
        <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 8 }}>
          A direct migration is recommended only when {result.strategy.direct_is_safe_when}.
        </div>
      </div>

      {/* 2 — what the twin was checked for */}
      <div>
        <div className="kicker" style={{ fontSize: 9.5, marginBottom: 6 }}>WHAT THE TWIN WAS CHECKED FOR</div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(110px, 1fr))", gap: 8 }}>
          {([
            ["Systems in change", ctx.systems_in_change], ["Hardware / HSM", ctx.hardware],
            ["Software libraries", ctx.software_libraries], ["Connected systems", ctx.connected_systems],
            ["Network endpoints", ctx.network_endpoints], ["Vendors", ctx.vendors], ["Certificates", ctx.certificates],
          ] as [string, number][]).map(([k, v]) => (
            <div key={k} style={boxStyle}>
              <div style={{ fontSize: 10, color: "var(--faint)" }}>{k}</div>
              <div style={{ fontSize: 18, fontWeight: 800, fontFamily: "var(--mono)" }}>{v}</div>
            </div>
          ))}
        </div>
      </div>

      {/* 3 — the plan */}
      {result.plan.length > 0 && (
        <div>
          <div className="kicker" style={{ fontSize: 9.5, marginBottom: 6 }}>HOW TO MIGRATE — {result.plan.length} STEPS</div>
          <ol aria-label="Migration plan" style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 8 }}>
            {result.plan.map((step) => (
              <li key={step.order} style={{ ...boxStyle, display: "grid", gridTemplateColumns: "28px 1fr", gap: 10 }}>
                <span style={{ width: 26, height: 26, borderRadius: 99, display: "grid", placeItems: "center",
                               background: "var(--violet)", color: "#fff", fontWeight: 800, fontSize: 12 }}>{step.order}</span>
                <div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                    <Badge tone={step.phase === "PREREQUISITES" ? "red" : step.phase === "ENABLE_ALONGSIDE" ? "amber" : "cyan"}>
                      {PHASE_LABEL[step.phase]}
                    </Badge>
                    <b style={{ fontSize: 12.5 }}>{step.title}</b>
                  </div>
                  <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 3 }}>{step.systems.join(", ")}</div>
                  <ul style={{ margin: "6px 0 0", paddingLeft: 18, fontSize: 11.5, color: "var(--dim)", lineHeight: 1.55 }}>
                    {step.actions.map((a, i) => <li key={i}>{a}</li>)}
                  </ul>
                  <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 6 }}>
                    <b>Done when:</b> {step.exit_criteria} · <b>Rollback:</b> {step.rollback}
                    {step.providers_first ? ` · ${step.providers_first}` : ""}
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* 4 — problems during migration */}
      {result.problems.length > 0 && (
        <div>
          <div className="kicker" style={{ fontSize: 9.5, marginBottom: 6 }}>
            PROBLEMS THAT CAN ARISE DURING THE MIGRATION —{" "}
            {(["BLOCKER", "HIGH", "MEDIUM", "INFO"] as const).filter((s) => result.problem_counts[s])
              .map((s) => `${result.problem_counts[s]} ${s.toLowerCase()}`).join(" · ")}
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" aria-label="Migration problems">
              <thead><tr><th>Severity</th><th>Problem</th><th>System</th><th>What to do</th><th>Who acts</th><th>If ignored</th></tr></thead>
              <tbody>
                {result.problems.map((p, i) => (
                  <tr key={`${p.code}:${p.system}:${p.subject}:${i}`}>
                    <td><Badge tone={SEVERITY_TONE[p.severity]}>{p.severity}</Badge></td>
                    <td>
                      <div style={{ fontWeight: 700, fontSize: 12 }}>{p.title}</div>
                      <div style={{ fontSize: 11, color: "var(--faint)" }}>{p.detail}</div>
                    </td>
                    <td style={{ fontSize: 11.5 }}>{p.system ?? "all"}</td>
                    <td style={{ fontSize: 11.5 }}>{p.mitigation}</td>
                    <td style={{ fontSize: 11 }}>{p.who_acts}</td>
                    <td style={{ fontSize: 11, color: "var(--dim)" }}>{p.if_ignored}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 5 — impact on vendors and connected systems */}
      {(result.vendor_impact.length > 0 || result.connected_impact.length > 0) && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 }}>
          <div>
            <div className="kicker" style={{ fontSize: 9.5, marginBottom: 6 }}>IMPACT ON VENDORS</div>
            {result.vendor_impact.length === 0
              ? <div style={{ fontSize: 11.5, color: "var(--faint)" }}>No vendor is linked to the systems in this change.</div>
              : (
                <table className="tbl" aria-label="Vendor impact">
                  <thead><tr><th>Vendor</th><th>Target support</th><th>Systems</th><th>Needs to</th></tr></thead>
                  <tbody>
                    {result.vendor_impact.map((v) => (
                      <tr key={v.vendor_id}>
                        <td style={{ fontWeight: 700, fontSize: 12 }}>{v.name}
                          {v.sub_tier.length > 0 && <div style={{ fontSize: 10, color: "var(--faint)", fontWeight: 400 }}>sub-tier: {v.sub_tier.join(", ")}</div>}
                        </td>
                        <td><Badge tone={SUPPORT_TONE[v.readiness] ?? "slate"}>{v.readiness.replace(/_/g, " ")}</Badge></td>
                        <td style={{ fontSize: 11 }}>{v.systems.join(", ")}</td>
                        <td style={{ fontSize: 11 }}>{v.needs_to}<div style={{ fontSize: 10, color: "var(--faint)" }}>{v.if_it_does_not}</div></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </div>
          <div>
            <div className="kicker" style={{ fontSize: 9.5, marginBottom: 6 }}>IMPACT ON CONNECTED SYSTEMS</div>
            {result.connected_impact.length === 0
              ? <div style={{ fontSize: 11.5, color: "var(--faint)" }}>No system dependency is recorded for the systems in this change.</div>
              : (
                <table className="tbl" aria-label="Connected system impact">
                  <thead><tr><th>System</th><th>Connection</th><th>Effect</th><th>Action</th></tr></thead>
                  <tbody>
                    {result.connected_impact.map((c) => (
                      <tr key={c.system_id}>
                        <td style={{ fontWeight: 700, fontSize: 12 }}>{c.name}
                          <div style={{ marginTop: 2 }}>
                            <Badge tone={c.in_change ? "cyan" : c.uses_target ? "amber" : "orange"}>
                              {c.in_change ? "IN THIS CHANGE" : c.uses_target ? "HAS TARGET ELSEWHERE" : "OUTSIDE CHANGE"}
                            </Badge>
                          </div>
                        </td>
                        <td style={{ fontSize: 11 }}>{c.links.map((l) => `${l.direction === "CALLS" ? "calls" : "called by"} ${l.with}`).join("; ")}</td>
                        <td style={{ fontSize: 11 }}>{c.effect}</td>
                        <td style={{ fontSize: 11 }}>{c.action}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </div>
        </div>
      )}

      {/* 6 — per system: what the twin holds */}
      {result.systems.length > 0 && (
        <div>
          <div className="kicker" style={{ fontSize: 9.5, marginBottom: 6 }}>PER SYSTEM — WHAT THE TWIN HOLDS</div>
          <div style={{ display: "grid", gap: 8 }}>
            {result.systems.map((s) => <SystemCard key={s.system_id} report={s} />)}
          </div>
        </div>
      )}

      {/* 7 — limits */}
      <div style={boxStyle}>
        <div className="kicker" style={{ fontSize: 9.5, marginBottom: 4 }}>WHAT THE TWIN COULD NOT SEE</div>
        <ul style={{ margin: 0, paddingLeft: 18, fontSize: 11, color: "var(--dim)", lineHeight: 1.6 }}>
          {result.unknowns.map((u) => <li key={u}>{u}</li>)}
        </ul>
      </div>
    </div>
  );
}

function SystemCard({ report }: { report: MigrationSystemReport }) {
  const t = report.twin;
  return (
    <details style={boxStyle}>
      <summary style={{ cursor: "pointer", display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <b style={{ fontSize: 12.5 }}>{report.name}</b>
        <Badge tone={STRATEGY_TONE[report.strategy]}>{report.strategy}</Badge>
        {report.criticality && <span style={{ fontSize: 10.5, color: "var(--faint)" }}>criticality {report.criticality}</span>}
        <span style={{ fontSize: 10.5, color: "var(--faint)", fontFamily: "var(--mono)" }}>
          {t.hardware.length} hw · {t.software.libraries.length} lib · {t.connections.length} links · {t.vendors.length} vendors · {t.network_endpoints.length} endpoints · {t.certificates.length} certs
        </span>
      </summary>
      <div style={{ display: "grid", gap: 8, marginTop: 8, fontSize: 11.5, color: "var(--dim)" }}>
        {[...report.blocked_by, ...report.parallel_because, ...report.considerations].length > 0 && (
          <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.55 }}>
            {report.blocked_by.map((r, i) => <li key={`b${i}`}><Badge tone="red">BLOCKS</Badge> {r.text}</li>)}
            {report.parallel_because.map((r, i) => <li key={`p${i}`}><Badge tone="amber">PARALLEL</Badge> {r.text}</li>)}
            {report.considerations.map((r, i) => <li key={`c${i}`}><Badge tone="slate">NOTE</Badge> {r.text}</li>)}
          </ul>
        )}
        <Row label="Why it is in the change">{report.why_in_change.join("; ")}</Row>
        <Row label="Hardware">
          {t.hardware.length === 0 ? "no crypto↔hardware link recorded" : t.hardware.map((h) => (
            <span key={h.asset_id} style={{ marginRight: 10 }}>
              {h.kind} {h.asset_id}{h.manufacturer ? ` (${[h.manufacturer, h.model].filter(Boolean).join(" ")})` : ""}{" "}
              <Badge tone={SUPPORT_TONE[h.target_support] ?? "slate"}>{h.target_support.replace(/_/g, " ")}</Badge>
              <span style={{ fontSize: 10, color: "var(--faint)" }}> {h.basis}</span>
            </span>
          ))}
        </Row>
        <Row label="Software">
          {t.software.libraries.length === 0 ? "no library recorded" : t.software.libraries.map((l) => (
            <span key={l.name} style={{ marginRight: 10 }}>
              {l.name}{l.version ? ` ${l.version}` : ""} <Badge tone={SUPPORT_TONE[l.target_support] ?? "slate"}>{l.target_support.replace(/_/g, " ")}</Badge>
              {l.deprecated && <> <Badge tone="orange">DEPRECATED</Badge></>}
            </span>
          ))}
          {t.software.deployments.length > 0 && <span style={{ color: "var(--faint)" }}> · {t.software.deployments.length} deployment(s)</span>}
        </Row>
        <Row label="Connected systems">
          {t.connections.length === 0 ? "none recorded" : t.connections.map((c) => (
            <span key={`${c.system_id}:${c.direction}`} style={{ marginRight: 10 }}>
              {c.direction === "CALLS" ? "→" : "←"} {c.name}{c.in_change ? " (in change)" : ""}
            </span>
          ))}
        </Row>
        <Row label="Vendors">
          {t.vendors.length === 0 ? "none linked" : t.vendors.map((v) => (
            <span key={v.vendor_id} style={{ marginRight: 10 }}>
              {v.name}{v.dependency_type ? ` (${v.dependency_type})` : ""} <Badge tone={SUPPORT_TONE[v.readiness] ?? "slate"}>{v.readiness.replace(/_/g, " ")}</Badge>
            </span>
          ))}
        </Row>
        {t.network_endpoints.length > 0 && (
          <Row label="Network endpoints">
            {t.network_endpoints.map((e) => (
              <span key={e.endpoint} style={{ marginRight: 10, fontFamily: "var(--mono)", fontSize: 10.5 }}>
                {e.endpoint} {e.tls_version ?? (e.observed ? "" : "(not observed)")}
              </span>
            ))}
          </Row>
        )}
        {t.certificates.length > 0 && (
          <Row label="Certificates">
            {t.certificates.map((c) => (
              <span key={c.fingerprint_sha256} style={{ marginRight: 10 }}>
                {c.subject ?? c.fingerprint_sha256.slice(0, 12)}{c.days_until_expiry != null ? ` · ${c.days_until_expiry}d left` : ""}
              </span>
            ))}
          </Row>
        )}
        {t.business_processes.length > 0 && (
          <Row label="Business processes">{t.business_processes.map((p) => p.name).filter(Boolean).join(", ")}</Row>
        )}
      </div>
    </details>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "150px 1fr", gap: 8 }}>
      <span style={{ fontSize: 10.5, color: "var(--faint)", textTransform: "uppercase", letterSpacing: ".05em" }}>{label}</span>
      <span>{children}</span>
    </div>
  );
}
