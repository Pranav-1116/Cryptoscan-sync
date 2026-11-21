/* Create remediation tasks from the agents' estate. There are two sources:
 *
 *  1. Estate weaknesses: the ranked findings from the Priorities page. The urgent ones
 *     (critical and high) can be opened in one click.
 *  2. A migration: type a change (for example RSA → ML-KEM-768), see every issue the simulation
 *     raises for it, and open them as tasks.
 *
 * The server re-reads the estate for every request and skips findings that already have an
 * open task, so a double click cannot create duplicates. ?from=&to= in the URL pre-fills the
 * migration and shows its work; the Migration page links here that way. */
import React, { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Badge } from "./ui";
import { SEVERITIES, SEV_TONE, TASK_TONE, inputStyle, kicker, tile } from "./remediationUi";
import { apiEstateRemediationFindings, apiMigrationTaskCandidates, apiOpenEstateTasks } from "../lib/api.js";
import type { EstateRemediationFindings, MigrationTaskCandidates } from "../lib/api.js";

const isOpen = (t?: { status: string } | null) => !!t && t.status !== "VERIFIED";

export default function CreateRemediationTasks({ onCreated }: { onCreated: () => void }) {
  const [params] = useSearchParams();
  const linked = useRef({ from: params.get("from") || "", to: params.get("to") || "", done: false });
  const [findings, setFindings] = useState<EstateRemediationFindings | null>(null);
  const [estateState, setEstateState] = useState<"loading" | "ready" | "none" | "error">("loading");
  const [from, setFrom] = useState(linked.current.from || "RSA");
  const [to, setTo] = useState(linked.current.to || "ML-KEM-768");
  const [work, setWork] = useState<MigrationTaskCandidates | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);
  const mounted = useRef(true);

  const loadFindings = async () => {
    const response = await apiEstateRemediationFindings();
    if (!mounted.current) return;
    if (response.data && Array.isArray(response.data.findings)) { setFindings(response.data); setEstateState("ready"); }
    else setEstateState(String(response.error || "").includes("404") ? "none" : "error");
  };
  const preview = async (change?: { from: string; to: string }, keepNotice = false) => {
    const f = (change?.from ?? from).trim();
    const t = (change?.to ?? to).trim();
    if (!f || !t) return;
    setBusy("preview");
    if (!keepNotice) setNotice(null);
    const response = await apiMigrationTaskCandidates(f, t);
    if (!mounted.current) return;
    setBusy(null);
    if (response.data && Array.isArray(response.data.candidates)) setWork(response.data);
    else { setWork(null); setNotice({ ok: false, text: response.detail || response.error || "the migration could not be simulated" }); }
  };
  useEffect(() => {
    mounted.current = true;
    void loadFindings();
    if (linked.current.from && linked.current.to && !linked.current.done) {
      linked.current.done = true;
      void preview({ from: linked.current.from, to: linked.current.to });
    }
    return () => { mounted.current = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const open = async (key: string, body: Parameters<typeof apiOpenEstateTasks>[0]) => {
    if (!body.ids.length) return;
    setBusy(key);
    setNotice(null);
    const response = await apiOpenEstateTasks(body);
    if (!mounted.current) return;
    setBusy(null);
    if (response.data) {
      setNotice({ ok: true, text: response.data.message });
      onCreated();
      void loadFindings();
      if (body.source === "migration" && work) void preview({ from: work.change.from_algo, to: work.change.to_algo }, true);
    } else {
      setNotice({ ok: false, text: response.detail || response.error || "the tasks could not be opened" });
    }
  };

  const urgent = (findings?.findings ?? []).filter((f) => (f.severity === "CRITICAL" || f.severity === "HIGH") && !isOpen(f.task));
  const without = (findings?.findings ?? []).filter((f) => !isOpen(f.task)).length;
  const fresh = (work?.candidates ?? []).filter((c) => !isOpen(c.task));

  return (
    <section aria-label="Create tasks" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: 12, marginBottom: 16 }}>
      <div aria-label="Tasks from estate weaknesses" style={{ ...tile, borderTop: "3px solid var(--amber)" }}>
        <div style={kicker}>FROM ESTATE WEAKNESSES</div>
        {estateState === "loading" && <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 6 }}>Reading what the agents observed…</div>}
        {estateState === "none" && <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 6 }}>No estate has been discovered yet, so there is nothing to rank.</div>}
        {estateState === "error" && <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 6 }}>The estate could not be read. <button className="btn sm" onClick={() => void loadFindings()}>Retry</button></div>}
        {findings && (
          <>
            <div style={{ fontSize: 13, margin: "6px 0 8px" }}>
              <b>{findings.total}</b> weakness{findings.total === 1 ? "" : "es"} observed · <b>{without}</b> without a task
            </div>
            <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginBottom: 10 }}>
              {SEVERITIES.map((s) => <Badge key={s} tone={SEV_TONE[s]}>{`${findings.counts_by_severity[s] ?? 0} ${s.toLowerCase()}`}</Badge>)}
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <button className="btn primary" disabled={busy !== null || urgent.length === 0}
                onClick={() => void open("urgent", { source: "estate", ids: urgent.map((f) => f.id) })}>
                {busy === "urgent" ? "Opening…" : `Open tasks for ${urgent.length} critical & high`}
              </button>
              <Link to="/priorities" style={{ fontSize: 12, color: "var(--amber)" }}>Choose on Priorities →</Link>
            </div>
          </>
        )}
      </div>

      <div aria-label="Tasks from a migration" style={{ ...tile, borderTop: "3px solid var(--violet)" }}>
        <div style={kicker}>FROM A MIGRATION</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", margin: "8px 0" }}>
          <input aria-label="Task migration from" value={from} onChange={(e) => { setFrom(e.target.value); setWork(null); }} style={{ ...inputStyle, width: 130, fontFamily: "var(--mono)" }} />
          <span style={{ color: "var(--faint)" }}>→</span>
          <input aria-label="Task migration to" value={to} onChange={(e) => { setTo(e.target.value); setWork(null); }} style={{ ...inputStyle, width: 130, fontFamily: "var(--mono)" }} />
          <button className="btn" disabled={busy !== null || !from.trim() || !to.trim()} onClick={() => void preview()}>
            {busy === "preview" ? "Simulating…" : "Show the work"}
          </button>
        </div>
        {!work && <div style={{ fontSize: 11.5, color: "var(--dim)" }}>Simulates the change on the estate and lists every issue as a task you can open.</div>}
        {work && (
          <>
            <div style={{ fontSize: 12.5, marginBottom: 6 }}>
              <b>{work.total}</b> issue{work.total === 1 ? "" : "s"} for {work.change.from_algo} → {work.change.to_algo}
              {work.strategy && <span style={{ color: "var(--faint)" }}> · {work.strategy.toLowerCase().replace("_", " ")}</span>}
            </div>
            {work.total > 0 && (
              <ul aria-label="Migration work" style={{ listStyle: "none", margin: "0 0 8px", padding: 0, display: "grid", gap: 4, maxHeight: 220, overflowY: "auto" }}>
                {work.candidates.map((c) => (
                  <li key={c.id} style={{ fontSize: 11.5, display: "flex", gap: 6, alignItems: "baseline" }}>
                    <Badge tone={SEV_TONE[c.severity]}>{c.severity}</Badge>
                    <span style={{ flex: 1 }}>{c.title}{c.systems.length > 0 && <span style={{ color: "var(--faint)" }}> · {c.systems.join(", ")}</span>}</span>
                    {isOpen(c.task) && <Badge tone={TASK_TONE[c.task!.status] || "slate"}>{c.task!.status}</Badge>}
                  </li>
                ))}
              </ul>
            )}
            <button className="btn primary" disabled={busy !== null || fresh.length === 0}
              onClick={() => void open("migration", { source: "migration", ids: fresh.map((c) => c.id), from_algo: work.change.from_algo, to_algo: work.change.to_algo })}>
              {busy === "migration" ? "Opening…" : `Open ${fresh.length} migration task${fresh.length === 1 ? "" : "s"}`}
            </button>
          </>
        )}
      </div>
      {notice && <div role={notice.ok ? "status" : "alert"} style={{ gridColumn: "1 / -1", fontSize: 12, color: notice.ok ? "var(--green)" : "var(--red)" }}>{notice.text}</div>}
    </section>
  );
}
