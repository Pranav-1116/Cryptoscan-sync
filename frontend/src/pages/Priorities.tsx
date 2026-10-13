import React, { useMemo, useState } from "react";
import { Badge, Bar, Kpi, PageHead, Panel, Table } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiPriority,
  apiPriorityCreateTasks,
  PriorityResponse,
  PriorityTaskActionResult,
  RankedItem,
} from "../lib/api.js";

/* Priorities — the deterministic remediation work queue (GET /api/v1/priority).
   Every row is a real OPEN drift event or runtime finding folded through the
   correlation engine: priority = revenue x severity x agility, effort =
   assets x complexity x (2 - agility), replacement from the fixed rule table,
   blast radius from the system dependency graph. Empty until real findings
   exist. No invented numbers. */

const SEV_TONE: Record<string, string> = {
  CRITICAL: "bad", HIGH: "warn", ALERT: "warn", MEDIUM: "warn", LOW: "ok",
};

/* §4.7: turn a ranked item into an owned remediation task. Drift items open
   tasks against their FAIL/WARN evidence (a task always points at evidence,
   never at a rank); runtime items are refused honestly by the API — the
   refusal text is shown verbatim, never papered over. */
function TaskAction({ item }: { item: RankedItem }) {
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PriorityTaskActionResult | null>(null);

  const open = async () => {
    if (!item.ref_id) return;
    setBusy(true);
    setResult(null);
    setResult(await apiPriorityCreateTasks(item.ref_id, owner.trim() || undefined));
    setBusy(false);
  };

  if (!item.ref_id) {
    return <p className="sub" style={{ fontSize: 12 }}>No backing record id — cannot open a task.</p>;
  }
  return (
    <div style={{ margin: "12px 0 4px", padding: 12, border: "1px solid var(--border, #233)" }}>
      <div className="row" style={{ gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <strong style={{ fontSize: 13 }}>Act on this: </strong>
        <input
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="owner (optional)"
          style={{ fontSize: 13, padding: "4px 8px" }}
        />
        <button className="btn sm" onClick={() => void open()} disabled={busy}>
          {busy ? "Opening…" : "Open remediation task(s)"}
        </button>
        {item.source === "runtime" && (
          <span className="dim" style={{ fontSize: 12 }}>
            runtime findings have no evidence record — expect an honest refusal
          </span>
        )}
      </div>
      {result && (result.ok ? (
        <p style={{ fontSize: 13, marginTop: 8 }}>
          <Badge tone={result.data.created > 0 ? "ok" : "warn"}>{result.data.created} task(s)</Badge>{" "}
          {result.data.message}
          {result.data.task_ids.length > 0 && (
            <span className="mono dim" style={{ fontSize: 11 }}> {result.data.task_ids.join(", ")}</span>
          )}
        </p>
      ) : (
        <p style={{ fontSize: 13, marginTop: 8, color: result.status === 422 ? "var(--amber)" : "var(--red)" }}>
          {result.status === 422 ? "Refused (honest): " : `Failed (HTTP ${result.status || "network"}): `}
          {result.detail}
        </p>
      ))}
    </div>
  );
}

function Detail({ item, onClose }: { item: RankedItem; onClose: () => void }) {
  return (
    <Panel title={`#${item.rank} — ${item.kind}`}>
      <div className="row" style={{ gap: 12, flexWrap: "wrap", margin: "8px 0" }}>
        <button className="btn" onClick={onClose} style={{ position: "absolute", right: 12, top: 12 }}>close</button>
        <Kpi k="Priority" v={item.priority.toFixed(1)} tone="var(--amber)" />
        <Kpi k="Effort" v={item.effort.toFixed(1)} />
        <Kpi k="Severity" v={item.severity_in} tone={SEV_TONE[item.severity_in] ? `var(--${SEV_TONE[item.severity_in]})` : undefined} />
        <Kpi k="Source" v={item.source} />
      </div>
      <p style={{ fontSize: 13 }}>{item.explanation}</p>
      {item.replacement && (
        <p style={{ fontSize: 13 }}>
          <strong>Replacement: </strong>
          <code>{item.replacement.replacement}</code>
          {item.replacement.reason ? ` — ${item.replacement.reason}` : ""}
        </p>
      )}
      {item.correlated.length > 0 && (
        <p style={{ fontSize: 13 }}>
          <strong>Blast radius: </strong>
          {item.correlated.map((c) => <Badge key={c} tone="warn">{c}</Badge>)}
        </p>
      )}
      {item.plan && (
        <>
          <strong style={{ fontSize: 13 }}>Migration plan ({item.plan.profile})</strong>
          <ol style={{ fontSize: 13, paddingLeft: 18 }}>
            {(item.plan.phases ?? []).map((ph, i) => (
              <li key={i} style={{ margin: "4px 0" }}>{ph.phase ?? JSON.stringify(ph)}</li>
            ))}
          </ol>
        </>
      )}
      <TaskAction item={item} />
    </Panel>
  );
}

export default function Priorities() {
  const state = usePollingApi<PriorityResponse>(() => apiPriority(100), 15000);
  const [selected, setSelected] = useState<number>(-1);
  const data = state.data;
  const ranked = useMemo(() => data?.ranked ?? [], [data]);
  const counts = data?.counts_by_severity ?? {};
  const cov = data?.coverage;

  if (selected >= 0 && selected < ranked.length) {
    return (
      <>
        <PageHead crumb="Platform / Priorities" title="Remediation priority" sub="ranked by revenue x severity x agility" />
        <Detail item={ranked[selected]} onClose={() => setSelected(-1)} />
      </>
    );
  }

  return (
    <>
      <PageHead
        crumb="Platform / Priorities"
        title="Remediation priority"
        sub="Deterministic work queue: revenue x severity x agility, blast radius, replacement table."
      />
      <div className="row" style={{ gap: 12, margin: "12px 0", flexWrap: "wrap" }}>
        <Kpi k="Open items" v={ranked.length} />
        <Kpi k="Critical" v={counts.CRITICAL ?? 0} tone="var(--red)" />
        <Kpi k="High/Alert" v={(counts.HIGH ?? 0) + (counts.ALERT ?? 0)} tone="var(--amber)" />
        <Kpi k="Medium" v={counts.MEDIUM ?? 0} />
      </div>
      <Panel title="Ranked remediation queue">
        {ranked.length === 0 ? (
          <p className="sub">
            Nothing to rank yet — items appear when OPEN drift events or runtime
            findings exist. Rank combines business-process revenue, system
            agility and finding severity.
          </p>
        ) : (
          <Table
            clickable
            selected={selected}
            onSelect={(i: number) => setSelected(i)}
            head={["#", "Severity", "Finding", "Priority", "Effort", "Replacement", "Blast radius"]}
            rows={ranked.map((r, i) => [
              r.rank,
              <Badge key={`s${i}`} tone={SEV_TONE[r.severity_in] ?? ""}>{r.severity_in}</Badge>,
              <span key={`f${i}`} style={{ fontSize: 12 }}>{r.kind}: {r.explanation.slice(0, 80)}{r.explanation.length > 80 ? "…" : ""}</span>,
              <span key={`p${i}`} style={{ fontWeight: 600 }}>{r.priority.toFixed(1)}</span>,
              <div key={`e${i}`} style={{ minWidth: 80 }}><Bar value={Math.min(1, r.effort / 50)} tone={r.effort > 25 ? "warn" : ""} /></div>,
              r.replacement ? <code key={`r${i}`} style={{ fontSize: 11 }}>{r.replacement.replacement.slice(0, 28)}</code> : "—",
              r.correlated.length > 0 ? `+${r.correlated.length}` : "—",
            ])}
          />
        )}
      </Panel>
      {cov && (
        <Panel title="Ranking inputs (honest coverage)">
          <p className="sub" style={{ fontSize: 12 }}>
            drift events: {cov.open_drift_events} · runtime findings: {cov.runtime_findings} ·
            systems with agility scores: {cov.systems_with_agility} ·
            with revenue mapping: {cov.systems_with_revenue_mapping} ·
            graph edges: {cov.graph_edges} · plan profile: {cov.profile}.
            Unmapped systems use neutral defaults (revenue 3, agility 0.5) — never invented numbers.
          </p>
        </Panel>
      )}
    </>
  );
}
