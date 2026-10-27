import React, { useEffect, useRef, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconCaretDown, IconCaretRight, IconClock, IconTarget, IconHardware, IconComponent } from "../components/icons";
import { ICON_SM } from "../components/icons";
import { apiRemediationAccept, apiRemediationComplete, apiRemediationTasks, apiRemediationVerify, RemediationTask } from "../lib/api.js";

const STATUS_TONE: Record<string, string> = { PROPOSED: "slate", ACCEPTED: "cyan", COMPLETED: "amber", VERIFIED: "green", PARTIAL: "amber", FAILED: "red", REGRESSION: "red" };
const STATUS_MEANING: Record<string, string> = { PROPOSED: "opened, not yet owned", ACCEPTED: "owned, work in progress", COMPLETED: "work declared done — awaiting/failed verification, NOT closure", VERIFIED: "machine-verified from rescan evidence", PARTIAL: "rescan still shows some of the original problem", FAILED: "rescan still shows the problem", REGRESSION: "rescan shows a worse violation than the original" };

function VerificationBlock({ v }: { v: RemediationTask["latest_verification"] }) {
  if (!v) return <span className="dim" style={{ fontSize: 11 }}>No verification yet — completion is a declaration, not proof.</span>;
  return (
    <div style={{ display: "grid", gap: 4 }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Badge tone={v.result === "VERIFIED" ? "green" : v.result === "PARTIAL" ? "amber" : "red"}>{v.result}</Badge>
        <span className="dim" style={{ fontSize: 11 }}>by {v.verified_by}{v.verified_at ? ` · ${new Date(v.verified_at).toLocaleString()}` : ""}</span>
      </div>
      {v.reason && <div style={{ fontSize: 11, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "6px 8px" }}>{v.reason}</div>}
      {v.rescan_id && <div style={{ fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)" }}>rescan {v.rescan_id}</div>}
    </div>
  );
}

function TaskActions({ task, onChanged }: { task: RemediationTask; onChanged: () => void }) {
  const [rescan, setRescan] = useState(task.latest_verification?.rescan_id || "");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true); const inFlight = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const run = async (kind: "accept" | "complete" | "verify") => {
    if (!mounted.current || inFlight.current) return;
    inFlight.current = true; setBusy(kind); setError(null);
    try {
      const res = kind === "accept" ? await apiRemediationAccept(task.id) : kind === "complete" ? await apiRemediationComplete(task.id, rescan.trim(), notes.trim() || undefined) : await apiRemediationVerify(task.id, rescan.trim() || undefined);
      if (!mounted.current) return;
      if (res.source === "live") { onChanged(); setNotes(""); } else setError(`Action outcome not confirmed. Inspect retained task history before retrying. ${res.error || "Request refused or interrupted."}`);
    } catch { if (mounted.current) setError("Action outcome not confirmed. Inspect retained task history before retrying."); }
    finally { inFlight.current = false; if (mounted.current) setBusy(null); }
  };
  return (
    <div style={{ display: "grid", gap: 8, padding: "6px 0" }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {task.status === "PROPOSED" && <button className="btn sm" disabled={busy !== null} onClick={() => void run("accept")} style={{ background: "var(--cyan)", color: "#fff", border: "1px solid var(--cyan)", borderRadius: "var(--r)", padding: "6px 12px", fontWeight: 700, fontSize: 12, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}>{busy === "accept" ? "Accepting…" : "Accept (take ownership)"}</button>}
        {task.status === "ACCEPTED" && <button className="btn sm" disabled={busy !== null} onClick={() => void run("complete")} style={{ background: "var(--amber)", color: "#fff", border: "1px solid var(--amber)", borderRadius: "var(--r)", padding: "6px 12px", fontWeight: 700, fontSize: 12, cursor: busy ? "not-allowed" : "pointer", opacity: busy ? 0.6 : 1 }}>{busy === "complete" ? "Completing…" : "Mark complete + verify"}</button>}
        {["COMPLETED", "VERIFIED", "PARTIAL", "FAILED", "REGRESSION"].includes(task.status) && <button className="btn sm outline" disabled={busy !== null} onClick={() => void run("verify")} style={{ border: "1px solid var(--line-strong)", borderRadius: "var(--r)", padding: "6px 12px", fontSize: 12 }}>{busy === "verify" ? "Verifying…" : "Re-verify against rescan"}</button>}
        <input value={rescan} onChange={(e) => setRescan(e.target.value)} placeholder="rescan id (optional — latest of same target is used)" aria-label={`Rescan id for task ${task.id}`} style={{ fontSize: 12, padding: "5px 8px", minWidth: 260, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />
        {task.status === "ACCEPTED" && <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="completion notes (optional)" aria-label={`Completion notes for task ${task.id}`} style={{ fontSize: 12, padding: "5px 8px", minWidth: 200, borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)" }} />}
      </div>
      {error && <div role="alert" style={{ fontSize: 11, color: "var(--red)", background: "color-mix(in srgb, var(--red) 8%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", padding: "8px 10px" }}>{error}</div>}
    </div>
  );
}

export default function Remediation() {
  const [scopeVersion, setScopeVersion] = useState(0);
  useEffect(() => {
    const reset = () => setScopeVersion(version => version + 1);
    const onStorage = (event: StorageEvent) => { if (event.key === "cryptoscan_tenant" || event.key === "zelinx_token" || event.key === null) reset(); };
    window.addEventListener("zelinx:tenant", reset); window.addEventListener("zelinx:auth", reset); window.addEventListener("storage", onStorage);
    return () => { window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); window.removeEventListener("storage", onStorage); };
  }, []);
  return <RemediationView key={scopeVersion} />;
}

function RemediationView() {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [loaded, setLoaded] = useState(false);
  const [offline, setOffline] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const mounted = useRef(true); const latestRead = useRef(0);
  const load = async (status: string) => {
    if (!mounted.current) return;
    const request = ++latestRead.current; setTasks([]); setTotal(0); setOpenId(null); setLoaded(false); setOffline(false);
    const res = await apiRemediationTasks(status ? { status } : { page_size: 100 });
    if (!mounted.current || request !== latestRead.current) return;
    if (res.source === "live" && res.data) { setTasks(res.data.tasks || []); setTotal(res.data.total ?? 0); setLoaded(true); setOffline(false); } else { setOffline(true); setLoaded(true); }
  };
  useEffect(() => { mounted.current = true; void load(statusFilter); return () => { mounted.current = false; ++latestRead.current; }; }, [statusFilter]);
  const byStatus = tasks.reduce<Record<string, number>>((acc, t) => { acc[t.status] = (acc[t.status] || 0) + 1; return acc; }, {});
  const totalTasks = total || tasks.length;
  const verifiedCount = tasks.filter(t => t.status === "VERIFIED").length;
  const proposedCount = tasks.filter(t => t.status === "PROPOSED").length;
  const failedCount = tasks.filter(t => ["FAILED", "REGRESSION"].includes(t.status)).length;
  const verifiedPct = totalTasks ? verifiedCount / totalTasks : 0;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Hero */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 520px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--amber) 12%, transparent)", border: "1px solid var(--amber)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--amber)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--amber)" }} /> GOVERNANCE · REMEDIATION LIFECYCLE · VERIFIED FIX
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--amber)", color: "#fff" }}><IconComponent size={18} /></span>
            Remediation Tasks
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            Owned tasks bound to evidence — <b style={{ color: "var(--text)" }}>accept, complete, verify against rescan evidence</b>. <span style={{ color: "var(--amber)" }}>COMPLETED is a declaration, not closure</span> — machine verdicts decide.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>PROPOSED → ACCEPTED → COMPLETED → VERIFIED/PARTIAL/FAILED</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <Link to="/operator-decisions" style={{ fontSize: 11, color: "var(--amber)" }}>Operator decisions →</Link>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={verifiedPct} label={verifiedCount ? `${Math.round(verifiedPct*100)}%` : totalTasks ? "0%" : "—"} sub="verified" tone={verifiedCount ? "green" : "amber"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>FIX CONFIDENCE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 135, lineHeight: 1.4 }}>{totalTasks ? `${verifiedCount}/${totalTasks} verified · ${failedCount} failed` : "No tasks yet"}</div>
              <div style={{ marginTop: 6 }}><Bar value={verifiedPct} tone={verifiedCount ? "green" : "amber"} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Link to="/priorities" className="btn sm" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", background: "var(--amber)", color: "#fff", border: "1px solid var(--amber)", fontWeight: 700 }}>Ranked priorities →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{totalTasks ? `${proposedCount} proposed · ${verifiedCount} verified` : "create from Priorities"}</span>
          </div>
        </div>
      </div>

      <p style={{ fontSize: 11, color: "var(--faint)", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 12px", margin: "0 0 14px" }}>
        <b style={{ color: "var(--amber)" }}>COMPLETED ≠ closure.</b> The task says the work is done; verification says whether the estate agrees. Legacy comparison alone cannot establish a verified fix.
      </p>

      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${proposedCount ? "var(--slate)" : "var(--amber)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>PROPOSED — AWAITING OWNER</div><div style={{ fontSize: 28, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{proposedCount}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>opened, not yet owned</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: proposedCount ? "color-mix(in srgb, var(--slate) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${proposedCount ? "var(--slate)" : "var(--line)"}`, color: proposedCount ? "var(--slate)" : "var(--faint)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={totalTasks ? proposedCount / totalTasks : 0} tone="slate" /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Take ownership to start work</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${tasks.some(t => t.status === "ACCEPTED") ? "var(--cyan)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>ACCEPTED — IN PROGRESS</div><div style={{ fontSize: 28, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{byStatus["ACCEPTED"] ?? 0}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>owned, work in progress</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: (byStatus["ACCEPTED"] ?? 0) ? "color-mix(in srgb, var(--cyan) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${(byStatus["ACCEPTED"] ?? 0) ? "var(--cyan)" : "var(--line)"}`, color: (byStatus["ACCEPTED"] ?? 0) ? "var(--cyan)" : "var(--faint)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={totalTasks ? (byStatus["ACCEPTED"] ?? 0) / totalTasks : 0} tone="cyan" /></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${verifiedCount ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>VERIFIED — MACHINE PROOF</div><div style={{ fontSize: 28, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: verifiedCount ? "var(--green)" : "var(--dim)" }}>{verifiedCount}</div><div style={{ fontSize: 11, color: verifiedCount ? "var(--green)" : "var(--dim)" }}>rescan evidence confirms fix</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: verifiedCount ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${verifiedCount ? "var(--green)" : "var(--line)"}`, color: verifiedCount ? "var(--green)" : "var(--faint)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={verifiedPct} tone={verifiedCount ? "green" : "slate"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{verifiedCount ? "Estate agrees — not just declaration" : "No verified fixes yet"}</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${failedCount ? "var(--red)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div><div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>FAILED / REGRESSION</div><div style={{ fontSize: 28, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: failedCount ? "var(--red)" : "var(--dim)" }}>{failedCount}</div><div style={{ fontSize: 11, color: failedCount ? "var(--red)" : "var(--dim)" }}>{failedCount ? "rescan still shows problem" : "no regressions"}</div></div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: failedCount ? "color-mix(in srgb, var(--red) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${failedCount ? "var(--red)" : "var(--line)"}`, color: failedCount ? "var(--red)" : "var(--faint)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={totalTasks ? failedCount / totalTasks : 0} tone={failedCount ? "red" : "slate"} /></div>
        </div>
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 14, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 12px" }}>
        {["", "PROPOSED", "ACCEPTED", "COMPLETED", "VERIFIED", "PARTIAL", "FAILED", "REGRESSION"].map((s) => (
          <button key={s || "all"} onClick={() => setStatusFilter(s)} style={{ padding: "5px 12px", borderRadius: 999, fontSize: 11, fontWeight: statusFilter === s ? 700 : 500, cursor: "pointer", background: statusFilter === s ? "var(--amber)" : "var(--panel)", color: statusFilter === s ? "#fff" : "var(--text)", border: `1px solid ${statusFilter === s ? "var(--amber)" : "var(--line)"}` }}>
            {s || "All statuses"}{s && byStatus[s] ? ` · ${byStatus[s]}` : ""}
          </button>
        ))}
        <Link to="/priorities" className="btn sm outline" style={{ fontSize: 11, textDecoration: "none", marginLeft: "auto", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "6px 12px" }}>Ranked priorities →</Link>
      </div>

      {!loaded && <div className="panel" style={{ padding: 16, textAlign: "center", color: "var(--dim)" }} role="status">Loading remediation tasks for the current scope…</div>}
      {offline && <Panel title="Tasks unavailable" sub="The remediation service did not answer; nothing is shown or invented."><button onClick={() => void load(statusFilter)} style={{ fontSize: 12, padding: "6px 12px", borderRadius: "var(--r)", background: "var(--amber)", color: "#fff", border: "none", cursor: "pointer" }}>Retry</button></Panel>}
      {loaded && !offline && tasks.length === 0 && <Panel title="No remediation tasks" sub={statusFilter ? `No tasks in status ${statusFilter}.` : "Tasks appear when drift is acknowledged or a priority item is turned into a task."}><Link to="/priorities" className="btn sm" style={{ textDecoration: "none", background: "var(--amber)", color: "#fff", padding: "6px 12px", borderRadius: "var(--r)" }}>Open Priorities to create tasks</Link></Panel>}
      {loaded && !offline && tasks.length > 0 && (
        <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
            <div><h3 style={{ margin: 0, fontSize: 14, fontWeight: 800, display: "flex", alignItems: "center", gap: 8 }}><IconComponent size={14} style={{ color: "var(--amber)" }} /> Tasks ({tasks.length}{total > tasks.length ? ` of ${total}` : ""})</h3><p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>COMPLETED is a declaration — VERIFIED is a machine verdict from rescan evidence. Never conflated.</p></div>
            <Badge tone={statusFilter ? "amber" : "slate"}>{statusFilter || "all"}</Badge>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th></th><th>Rule</th><th>Finding</th><th>Status</th><th>Owner</th><th>Source</th><th>Latest verification</th></tr></thead>
              <tbody>
                {tasks.map((t) => (
                  <React.Fragment key={t.id}>
                    <tr>
                      <td style={{ width: 28 }}><button className="btn sm ghost" aria-label={openId === t.id ? `Collapse task ${t.id}` : `Expand task ${t.id}`} aria-expanded={openId === t.id} onClick={() => setOpenId(openId === t.id ? null : t.id)} style={{ padding: "2px 6px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", cursor: "pointer" }}>{openId === t.id ? <IconCaretDown size={ICON_SM} /> : <IconCaretRight size={ICON_SM} />}</button></td>
                      <td><code style={{ fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>{t.rule_id}</code>{t.priority && <><span style={{ marginLeft: 6 }} /><Badge tone={t.priority === "P1" ? "red" : t.priority === "P2" ? "amber" : "slate"}>{t.priority}</Badge></>}</td>
                      <td><div style={{ fontSize: 11 }}>{String(t.original_finding?.algorithm || "?")}<span className="dim" style={{ fontFamily: "var(--mono)", fontSize: 10 }}> {String(t.original_finding?.file_path ?? "")}{t.original_finding?.line_number ? `:${t.original_finding.line_number}` : ""}</span></div></td>
                      <td><div style={{ display: "grid", gap: 2 }}><Badge tone={STATUS_TONE[t.status] || "slate"}>{t.status}</Badge><span className="dim" style={{ fontSize: 9 }}>{STATUS_MEANING[t.status] || ""}</span></div></td>
                      <td style={{ fontSize: 11 }}>{t.owner || <span className="dim">unassigned</span>}</td>
                      <td style={{ fontSize: 11 }}>{t.source}{t.source === "drift" && t.source_ref ? <div className="dim" style={{ fontSize: 9 }}>event <code style={{ fontFamily: "var(--mono)" }}>{String(t.source_ref).slice(0, 10)}…</code></div> : null}</td>
                      <td><VerificationBlock v={t.latest_verification} /></td>
                    </tr>
                    {openId === t.id && (
                      <tr><td colSpan={7} style={{ background: "var(--bg-2)" }}>
                        <div style={{ padding: "10px 12px", display: "grid", gap: 10 }}>
                          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10, fontSize: 11 }}>
                            <div><div className="dim" style={{ fontSize: 9, letterSpacing: ".06em" }}>BOUND EVIDENCE</div><div><code style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{t.evidence_id}</code></div><div className="dim" style={{ fontSize: 10 }}>from scan <code style={{ fontFamily: "var(--mono)" }}>{t.scan_id}</code></div></div>
                            <div><div className="dim" style={{ fontSize: 9, letterSpacing: ".06em" }}>TARGET</div><div style={{ overflowWrap: "anywhere" }}>{t.target_location || "—"}</div></div>
                            <div><div className="dim" style={{ fontSize: 9, letterSpacing: ".06em" }}>REPLACEMENT</div><div>{t.replace_with || "—"}</div></div>
                            <div><div className="dim" style={{ fontSize: 9, letterSpacing: ".06em" }}>COMPLETED</div><div>{t.completed_at ? `${new Date(t.completed_at).toLocaleString()} by ${t.completed_by}` : "—"}</div></div>
                          </div>
                          {t.notes && <div style={{ fontSize: 11 }}><div className="dim" style={{ fontSize: 9, letterSpacing: ".06em" }}>NOTES</div><div style={{ whiteSpace: "pre-wrap", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "8px 10px" }}>{t.notes}</div></div>}
                          <div><div className="dim" style={{ fontSize: 9, letterSpacing: ".06em", marginBottom: 6 }}>LIFECYCLE ACTIONS</div><TaskActions task={t} onChanged={() => void load(statusFilter)} /></div>
                        </div>
                      </td></tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
            <Link to="/operator-decisions" style={{ color: "var(--amber)" }}>Operator decisions: retained before/after →</Link><span>·</span><span>Completed ≠ closed — verification decides</span><span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>Rank lives on Priorities</span>
          </div>
        </div>
      )}
    </div>
  );
}
