import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { ICON_SM, IconCaretDown, IconCaretRight } from "../components/icons";
import {
  apiRemediationAccept,
  apiRemediationComplete,
  apiRemediationTasks,
  apiRemediationVerify,
  RemediationTask,
} from "../lib/api.js";

/* Remediation Tasks (§5, round 63) — the task LIFECYCLE view the ranker
   (Priorities) deliberately is not. Every row is a real task bound to
   evidence, with owner, status, rescan and verification.

   The honest distinction this page exists to keep visible:
     PROPOSED → ACCEPTED → COMPLETED  = declared workflow states (people
                                        said things)
     VERIFIED / PARTIAL / FAILED /
     REGRESSION                        = machine verdicts computed from
                                        RESCAN EVIDENCE (_run_verification),
                                        shown with their reason verbatim.

   COMPLETED is not closure: the task says the work is done, the
   verification says whether the estate agrees. Empty until real tasks
   exist — nothing is invented. */

const STATUS_TONE: Record<string, string> = {
  PROPOSED: "slate", ACCEPTED: "cyan", COMPLETED: "amber",
  VERIFIED: "green", PARTIAL: "amber", FAILED: "red", REGRESSION: "red",
};

const STATUS_MEANING: Record<string, string> = {
  PROPOSED: "opened, not yet owned",
  ACCEPTED: "owned, work in progress",
  COMPLETED: "work declared done — awaiting/failed verification, NOT closure",
  VERIFIED: "machine-verified from rescan evidence",
  PARTIAL: "rescan still shows some of the original problem",
  FAILED: "rescan still shows the problem",
  REGRESSION: "rescan shows a worse violation than the original",
};

function VerificationBlock({ v }: { v: RemediationTask["latest_verification"] }) {
  if (!v) {
    return <span className="dim" style={{ fontSize: 12 }}>No verification yet — completion is a declaration, not proof.</span>;
  }
  return (
    <div style={{ display: "grid", gap: 4 }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Badge tone={v.result === "VERIFIED" ? "green" : v.result === "PARTIAL" ? "amber" : "red"}>
          {v.result}
        </Badge>
        <span className="dim" style={{ fontSize: 11.5 }}>
          verified by {v.verified_by}{v.verified_at ? ` · ${new Date(v.verified_at).toLocaleString()}` : ""}
        </span>
      </div>
      {v.reason && <div style={{ fontSize: 12 }}>{v.reason}</div>}
      {v.rescan_id && (
        <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
          against rescan <code style={{ fontFamily: "var(--mono)" }}>{v.rescan_id}</code>
        </div>
      )}
    </div>
  );
}

function TaskActions({ task, onChanged }: { task: RemediationTask; onChanged: () => void }) {
  const [rescan, setRescan] = useState(task.latest_verification?.rescan_id || "");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (kind: "accept" | "complete" | "verify") => {
    setBusy(kind);
    setError(null);
    const res =
      kind === "accept" ? await apiRemediationAccept(task.id)
      : kind === "complete" ? await apiRemediationComplete(task.id, rescan.trim(), notes.trim() || undefined)
      : await apiRemediationVerify(task.id, rescan.trim() || undefined);
    setBusy(null);
    if (res.source === "live") {
      onChanged();
      setNotes("");
    } else {
      // refusals (409 wrong status, 404 gone) are shown verbatim
      setError(res.error || "The action was refused.");
    }
  };

  return (
    <div style={{ display: "grid", gap: 8, padding: "6px 0" }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {task.status === "PROPOSED" && (
          <button className="btn sm" disabled={busy !== null} onClick={() => void run("accept")}>
            {busy === "accept" ? "Accepting…" : "Accept (take ownership)"}
          </button>
        )}
        {(task.status === "ACCEPTED" || task.status === "PROPOSED") && (
          <button className="btn sm" disabled={busy !== null} onClick={() => void run("complete")}>
            {busy === "complete" ? "Completing… (verifies against rescan)" : "Mark complete + verify"}
          </button>
        )}
        {["COMPLETED", "VERIFIED", "PARTIAL", "FAILED", "REGRESSION"].includes(task.status) && (
          <button className="btn sm outline" disabled={busy !== null} onClick={() => void run("verify")}>
            {busy === "verify" ? "Verifying…" : "Re-verify against rescan"}
          </button>
        )}
        <input
          value={rescan}
          onChange={(e) => setRescan(e.target.value)}
          placeholder="rescan id (optional — latest of the same target is used)"
          aria-label={`Rescan id for task ${task.id}`}
          style={{ fontSize: 12, padding: "4px 8px", minWidth: 260 }}
        />
        {(task.status === "ACCEPTED" || task.status === "PROPOSED") && (
          <input
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="completion notes (optional)"
            aria-label={`Completion notes for task ${task.id}`}
            style={{ fontSize: 12, padding: "4px 8px", minWidth: 200 }}
          />
        )}
      </div>
      {error && <div style={{ fontSize: 12, color: "var(--red)" }}>Refused: {error}</div>}
    </div>
  );
}

export default function Remediation() {
  const [tasks, setTasks] = useState<RemediationTask[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [loaded, setLoaded] = useState(false);
  const [offline, setOffline] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);

  const load = async (status: string) => {
    const res = await apiRemediationTasks(status ? { status } : { page_size: 100 });
    if (res.source === "live" && res.data) {
      setTasks(res.data.tasks || []);
      setTotal(res.data.total ?? 0);
      setLoaded(true);
      setOffline(false);
    } else {
      setOffline(true);
      setLoaded(true);
    }
  };

  useEffect(() => {
    void load(statusFilter);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [statusFilter]);

  const byStatus = tasks.reduce<Record<string, number>>((acc, t) => {
    acc[t.status] = (acc[t.status] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <PageHead
        crumb="Remediation"
        title="Remediation Tasks"
        sub="Owned tasks bound to evidence — accept, complete, verify against rescan evidence. Ranked signals live on Priorities."
      />

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", marginBottom: 14 }}>
        {["", "PROPOSED", "ACCEPTED", "COMPLETED", "VERIFIED", "PARTIAL", "FAILED", "REGRESSION"].map((s) => (
          <button
            key={s || "all"}
            className={`btn sm ${statusFilter === s ? "" : "outline"}`}
            onClick={() => setStatusFilter(s)}
            style={{ fontSize: 12 }}
          >
            {s || "All statuses"}{s && byStatus[s] ? ` · ${byStatus[s]}` : ""}
          </button>
        ))}
        <Link to="/priorities" className="btn sm outline" style={{ fontSize: 12, textDecoration: "none" }}>
          Ranked priorities →
        </Link>
      </div>

      {offline && (
        <Panel title="Tasks unavailable" sub="The remediation service did not answer; nothing is shown or invented.">
          <button className="btn sm" onClick={() => void load(statusFilter)}>Retry</button>
        </Panel>
      )}

      {loaded && !offline && tasks.length === 0 && (
        <Panel title="No remediation tasks" sub={statusFilter ? `No tasks in status ${statusFilter}.` : "Tasks appear when drift is acknowledged or a priority item is turned into a task."}>
          <Link to="/priorities" className="btn sm" style={{ textDecoration: "none" }}>Open Priorities to create tasks</Link>
        </Panel>
      )}

      {loaded && !offline && tasks.length > 0 && (
        <Panel
          title={`Tasks (${tasks.length}${total > tasks.length ? ` of ${total}` : ""})`}
          sub="COMPLETED is a declaration — VERIFIED is a machine verdict from rescan evidence. The two are never conflated."
        >
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th></th>
                  <th>Rule</th>
                  <th>Finding</th>
                  <th>Status</th>
                  <th>Owner</th>
                  <th>Source</th>
                  <th>Latest verification</th>
                </tr>
              </thead>
              <tbody>
                {tasks.map((t) => (
                  <React.Fragment key={t.id}>
                    <tr>
                      <td style={{ width: 28 }}>
                        <button
                          className="btn sm ghost"
                          aria-label={openId === t.id ? `Collapse task ${t.id}` : `Expand task ${t.id}`}
                          aria-expanded={openId === t.id}
                          onClick={() => setOpenId(openId === t.id ? null : t.id)}
                          style={{ padding: "2px 6px" }}
                        >
                          {openId === t.id ? <IconCaretDown size={ICON_SM} /> : <IconCaretRight size={ICON_SM} />}
                        </button>
                      </td>
                      <td>
                        <code style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{t.rule_id}</code>
                        {t.priority && <Badge tone={t.priority === "P1" ? "red" : t.priority === "P2" ? "amber" : "slate"}>{t.priority}</Badge>}
                      </td>
                      <td>
                        <div style={{ fontSize: 12 }}>
                          {String(t.original_finding?.algorithm || "?")}
                          {t.original_finding?.file_path ? (
                            <span className="dim" style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                              {" "}{String(t.original_finding.file_path)}
                              {t.original_finding.line_number ? `:${t.original_finding.line_number}` : ""}
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: "grid", gap: 2 }}>
                          <Badge tone={STATUS_TONE[t.status] || "slate"}>{t.status}</Badge>
                          <span className="dim" style={{ fontSize: 10.5 }}>{STATUS_MEANING[t.status] || ""}</span>
                        </div>
                      </td>
                      <td style={{ fontSize: 12 }}>{t.owner || <span className="dim">unassigned</span>}</td>
                      <td style={{ fontSize: 12 }}>
                        {t.source}
                        {t.source === "drift" && t.source_ref ? (
                          <div className="dim" style={{ fontSize: 10.5 }}>
                            event <code style={{ fontFamily: "var(--mono)" }}>{String(t.source_ref).slice(0, 10)}…</code>
                          </div>
                        ) : null}
                      </td>
                      <td><VerificationBlock v={t.latest_verification} /></td>
                    </tr>
                    {openId === t.id && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-2)" }}>
                          <div style={{ padding: "10px 6px", display: "grid", gap: 10 }}>
                            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 10, fontSize: 12 }}>
                              <div>
                                <div className="dim" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Bound evidence</div>
                                <div><code style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{t.evidence_id}</code></div>
                                <div className="dim" style={{ fontSize: 10.5 }}>from scan <code style={{ fontFamily: "var(--mono)" }}>{t.scan_id}</code></div>
                              </div>
                              <div>
                                <div className="dim" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Target</div>
                                <div style={{ overflowWrap: "anywhere" }}>{t.target_location || "—"}</div>
                              </div>
                              <div>
                                <div className="dim" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Replacement</div>
                                <div>{t.replace_with || "—"}</div>
                              </div>
                              <div>
                                <div className="dim" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Completed</div>
                                <div>{t.completed_at ? `${new Date(t.completed_at).toLocaleString()} by ${t.completed_by}` : "—"}</div>
                              </div>
                            </div>
                            {t.notes && (
                              <div style={{ fontSize: 12 }}>
                                <div className="dim" style={{ fontSize: 10.5, textTransform: "uppercase" }}>Notes</div>
                                <div style={{ whiteSpace: "pre-wrap" }}>{t.notes}</div>
                              </div>
                            )}
                            <div>
                              <div className="dim" style={{ fontSize: 10.5, textTransform: "uppercase", marginBottom: 4 }}>Lifecycle actions</div>
                              <TaskActions task={t} onChanged={() => void load(statusFilter)} />
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
