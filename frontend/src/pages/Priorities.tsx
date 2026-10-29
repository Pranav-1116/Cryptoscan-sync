import React, { useMemo, useState } from "react";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconTarget, IconClock, IconSecurity, IconComponent, IconInfo } from "../components/icons";
import { usePollingApi } from "../lib/apiUi.jsx";
import { apiPriority, apiPriorityCreateTasks, PriorityResponse, PriorityTaskActionResult, RankedItem } from "../lib/api.js";

const SEV_TONE: Record<string, string> = { CRITICAL: "red", HIGH: "amber", ALERT: "amber", MEDIUM: "slate", LOW: "green" };
const SEV_COLOR = (s: string) => ({ CRITICAL: "var(--red)", HIGH: "var(--amber)", ALERT: "var(--amber)", MEDIUM: "var(--slate)", LOW: "var(--green)" }[s] ?? "var(--faint)");

function TaskAction({ item }: { item: RankedItem }) {
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PriorityTaskActionResult | null>(null);
  const open = async () => { if (!item.ref_id) return; setBusy(true); setResult(null); setResult(await apiPriorityCreateTasks(item.ref_id, owner.trim() || undefined)); setBusy(false); };
  if (!item.ref_id) return <p style={{ fontSize: 11, color: "var(--faint)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>No backing record id — cannot open a task.</p>;
  return (
    <div style={{ marginTop: 12, padding: 12, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <strong style={{ fontSize: 12 }}>Act:</strong>
        <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="owner (optional)" style={{ fontSize: 12, padding: "5px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
        <button onClick={() => void open()} disabled={busy} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--amber)", color: "#fff", border: "1px solid var(--amber)", fontWeight: 700, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}>{busy ? "Opening…" : "Open remediation task(s)"}</button>
        {item.source === "runtime" && <span style={{ fontSize: 11, color: "var(--dim)" }}>runtime findings have no evidence record — expect an honest refusal</span>}
      </div>
      {result && (result.ok ? <p style={{ fontSize: 12, marginTop: 8 }}><Badge tone={result.data.created > 0 ? "green" : "amber"}>{result.data.created} task(s)</Badge> {result.data.message}{result.data.task_ids.length > 0 && <span style={{ fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)" }}> {result.data.task_ids.join(", ")}</span>}</p> : <p style={{ fontSize: 12, marginTop: 8, color: result.status === 422 ? "var(--amber)" : "var(--red)" }}>{result.status === 422 ? "Refused (honest): " : `Failed (HTTP ${result.status || "network"}): `}{result.detail}</p>)}
    </div>
  );
}

function Detail({ item, onClose }: { item: RankedItem; onClose: () => void }) {
  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <button onClick={onClose} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", cursor: "pointer", marginBottom: 12 }}>← Back to queue</button>
      <Panel title={`#${item.rank} — ${item.kind}`} sub={`${item.severity_in} · priority ${item.priority.toFixed(1)} · effort ${item.effort.toFixed(1)}`} style={{ borderTop: `2px solid ${SEV_COLOR(item.severity_in)}` } as any}>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: 10, marginBottom: 12 }}>
          <div style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", textAlign: "center" }}><div style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)" }}>PRIORITY</div><div style={{ fontSize: 20, fontWeight: 800, color: "var(--amber)" }}>{item.priority.toFixed(1)}</div><Bar value={Math.min(1, item.priority / 25)} tone="amber" /><div style={{ fontSize: 10, color: "var(--faint)" }}>revenue × severity × agility · max 25</div></div>
          <div style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", textAlign: "center" }}><div style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)" }}>EFFORT</div><div style={{ fontSize: 20, fontWeight: 800 }}>{item.effort.toFixed(1)}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>assets × complexity × (2 − agility) · no ceiling</div></div>
          <div style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", textAlign: "center" }}><div style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)" }}>SEVERITY</div><div style={{ fontSize: 14, fontWeight: 800, color: SEV_COLOR(item.severity_in) }}>{item.severity_in}</div><Badge tone={SEV_TONE[item.severity_in] ?? "slate"}>{item.source}</Badge></div>
          <div style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", textAlign: "center" }}><div style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--faint)" }}>SOURCE</div><div style={{ fontSize: 13, fontWeight: 700 }}>{item.source}</div><div style={{ fontSize: 11, color: "var(--faint)" }}>rank {item.rank}</div></div>
        </div>
        <p style={{ fontSize: 13, background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px" }}>{item.explanation}</p>
        {item.replacement && <p style={{ fontSize: 12 }}><strong>Replacement:</strong> <code style={{ background: "var(--panel-2)", padding: "2px 6px", borderRadius: "var(--r)", fontFamily: "var(--mono)" }}>{item.replacement.replacement}</code>{item.replacement.reason ? ` — ${item.replacement.reason}` : ""}</p>}
        {item.correlated.length > 0 && <p style={{ fontSize: 12, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}><strong>Blast radius:</strong>{item.correlated.map((c) => <Badge key={c} tone="amber">{c}</Badge>)}</p>}
        {item.plan && <><strong style={{ fontSize: 12 }}>Migration plan ({item.plan.profile})</strong><ol style={{ fontSize: 12, paddingLeft: 18 }}>{(item.plan.phases ?? []).map((ph: any, i: number) => <li key={i} style={{ margin: "4px 0" }}>{ph.phase ?? JSON.stringify(ph)}</li>)}</ol></>}
        <TaskAction item={item} />
      </Panel>
    </div>
  );
}

export default function Priorities() {
  const state = usePollingApi<PriorityResponse>(() => apiPriority(100), 15000);
  const [selected, setSelected] = useState<number>(-1);
  const data = state.data;
  const ranked = useMemo(() => data?.ranked ?? [], [data]);
  const counts = data?.counts_by_severity ?? {};
  const cov = data?.coverage;
  const total = ranked.length;
  const critical = counts.CRITICAL ?? 0;
  const high = (counts.HIGH ?? 0) + (counts.ALERT ?? 0);
  const topPriority = ranked[0]?.priority ?? 0;

  if (selected >= 0 && selected < ranked.length) return <Detail item={ranked[selected]} onClose={() => setSelected(-1)} />;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--red) 12%, transparent)", border: "1px solid var(--red)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--red)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--red)" }} /> GOVERNANCE · PRIORITIES · REVENUE × SEVERITY × AGILITY
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--red)", color: "#fff" }}><IconTarget size={18} /></span>
            Remediation Priorities
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            Deterministic work queue — <b style={{ color: "var(--text)" }}>priority = revenue × severity × agility, effort = assets × complexity × (2 − agility)</b>. Replacement from fixed rule table, blast radius from dependency graph.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>CORRELATION ENGINE · BLAST RADIUS · FIXED REPLACEMENT TABLE</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={total ? Math.min(1, critical / Math.max(1, total)) : 0} label={String(critical)} sub="critical" tone={critical ? "red" : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>QUEUE HEALTH</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 135, lineHeight: 1.4 }}>{total} open · {critical} critical · {high} high/alert</div>
              <div style={{ marginTop: 6 }}><Bar value={total ? critical / total : 0} tone={critical ? "red" : "slate"} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{ cov ? `profile ${cov.profile ?? "—"}` : "loading coverage…"}</span>
            <span style={{ fontSize: 11, color: "var(--dim)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "6px 10px", textAlign: "center" }}>Top P {ranked.length ? topPriority.toFixed(1) : "—"} · Effort {ranked[0]?.effort.toFixed(1) ?? "—"}</span>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--slate)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>OPEN ITEMS</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{total}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>drift + runtime findings</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--slate) 14%, transparent)", border: "1px solid var(--slate)", color: "var(--slate)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><div style={{ fontSize: 10, color: "var(--faint)" }}>{cov ? `drift ${cov.open_drift_events} · runtime ${cov.runtime_findings}` : "counting inputs…"}</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${critical ? "var(--red)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>CRITICAL</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: critical ? "var(--red)" : "var(--dim)" }}>{critical}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>immediate triage</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: critical ? "color-mix(in srgb, var(--red) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${critical ? "var(--red)" : "var(--line)"}`, color: critical ? "var(--red)" : "var(--faint)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={total ? critical / Math.max(1, total) : 0} tone={critical ? "red" : "slate"} /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${high ? "var(--amber)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>HIGH / ALERT</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: high ? "var(--amber)" : "var(--dim)" }}>{high}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>elevated urgency</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: high ? "color-mix(in srgb, var(--amber) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${high ? "var(--amber)" : "var(--line)"}`, color: high ? "var(--amber)" : "var(--faint)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={total ? high / Math.max(1, total) : 0} tone={high ? "amber" : "slate"} /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>MEDIUM</div><div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{counts.MEDIUM ?? 0}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>planned queue</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--faint)" }}><IconInfo size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={total ? (counts.MEDIUM ?? 0) / Math.max(1, total) : 0} tone="cyan" /></div>
        </div>
      </div>

      <Panel title="Ranked remediation queue" sub="Click a row to open detail + create remediation task" style={{ padding: 0, overflow: "hidden" } as any}>
        <div style={{ padding: "10px 14px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>{total} ranked — revenue × severity × agility · blast radius from graph · replacement from rule table</span>
          <Badge tone="slate">click row → detail</Badge>
        </div>
        {ranked.length === 0 ? <p style={{ fontSize: 12, color: "var(--dim)", padding: 16, textAlign: "center", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", margin: 14 }}>Nothing to rank yet — items appear when OPEN drift events or runtime findings exist. Rank combines business-process revenue, system agility and finding severity.</p> : (
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Priority</th><th>Effort</th><th>Replacement</th><th>Blast radius</th></tr></thead>
              <tbody>
                {ranked.map((r, i) => (
                  <tr key={i} onClick={() => setSelected(i)} style={{ cursor: "pointer" }}>
                    <td style={{ fontFamily: "var(--mono)", fontWeight: 700 }}>{r.rank}</td>
                    <td><Badge tone={SEV_TONE[r.severity_in] ?? "slate"}>{r.severity_in}</Badge></td>
                    <td style={{ fontSize: 12, maxWidth: 360 }}><span style={{ color: "var(--faint)" }}>{r.kind}:</span> {r.explanation.slice(0, 80)}{r.explanation.length > 80 ? "…" : ""}</td>
                    <td style={{ fontWeight: 800, fontFamily: "var(--mono)", color: SEV_COLOR(r.severity_in) }}>{r.priority.toFixed(1)}</td>
                    <td style={{ minWidth: 100, fontFamily: "var(--mono)" }}><span style={{ fontSize: 12 }}>{r.effort.toFixed(1)}</span><span style={{ fontSize: 10, color: "var(--faint)", display: "block" }}>unbounded</span></td>
                    <td><code style={{ fontSize: 11, background: "var(--panel-2)", padding: "2px 6px", borderRadius: "var(--r)", fontFamily: "var(--mono)" }}>{r.replacement ? r.replacement.replacement.slice(0, 28) : "—"}</code></td>
                    <td>{r.correlated.length > 0 ? <Badge tone="amber">+{r.correlated.length}</Badge> : <span style={{ color: "var(--faint)" }}>—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {cov && (
        <Panel title="Ranking inputs — honest coverage" sub="what fed the ranker; neutral defaults where unmapped" style={{ marginTop: 14 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
            {[
              { k: "drift events", v: cov.open_drift_events },
              { k: "runtime findings", v: cov.runtime_findings },
              { k: "systems with agility", v: cov.systems_with_agility },
              { k: "with revenue mapping", v: cov.systems_with_revenue_mapping },
              { k: "graph edges", v: cov.graph_edges },
            ].map(x => (
              <div key={x.k} style={{ padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 11, color: "var(--faint)" }}>{x.k}</span><span style={{ fontFamily: "var(--mono)", fontWeight: 800, fontSize: 13 }}>{String(x.v)}</span>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 11, color: "var(--faint)", margin: "8px 0 0", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>profile {cov.profile ?? "—"} · Unmapped systems use neutral defaults (revenue 3, agility 0.5) — never invented numbers.</p>
        </Panel>
      )}
    </div>
  );
}
