import React, { useMemo, useState } from "react";
import type { ThreatClass, ThreatFinding } from "./types";
import { HBars } from "../components/viz";

const CLASSES: ThreatClass[] = [
  "CRYPTO_REGRESSION",
  "WEAK_ALGORITHM_EXPOSURE",
  "CERTIFICATE_RISK",
  "TRUST_PATH_MUTATION",
  "HSM_DEPENDENCY",
  "LIBRARY_RISK",
  "VENDOR_RISK",
  "COLLECTION_BLIND_SPOT",
  "PQC_REGRESSION",
];

/** Evidence-linked findings: every row answers the six mandated questions and
 *  carries an explicit "NOT PROVEN" column. A detection is a question, never a
 *  declared compromise — the header says so on every render.
 *
 *  Filtering here is report-internal and deliberate: this table renders a
 *  DERIVED findings report (source queries capped at CERT_CAP/LIVE_CAP in
 *  roadmap_intelligence), not the bank inventory — inventories paginate,
 *  filter and authorise at the server (see Assets). The class/search filters
 *  narrow within the loaded report and say "N of M shown". The ROWS are
 *  windowed (the virtual-scroll row): a report with thousands of findings
 *  never lands fully in the DOM. */
export default function FindingsTable({
  findings,
  onEvidence,
}: {
  findings: ThreatFinding[];
  onEvidence?: (evidenceId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [klass, setKlass] = useState<string>("ALL");
  /* Windowed rendering (the virtual-scroll row): a report can carry thousands
     of findings (source caps CERT_CAP=2000/LIVE_CAP=5000). Only the first
     window lands in the DOM; scrolling to the bottom extends it. */
  const WINDOW = 200;
  const [shown, setShown] = useState(WINDOW);

  const rows = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings.filter((f) => {
      if (klass !== "ALL" && f.class !== klass) return false;
      if (!needle) return true;
      return [f.asset, f.what_changed, f.why_it_matters, f.investigate]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [findings, query, klass]);

  return (
    <section aria-label="Evidence-linked findings">
      <h2>Findings — evidence-linked, detection is a question</h2>
      {findings.length > 0 && (
        <div style={{ margin: "8px 0 12px", maxWidth: 560 }}>
          <HBars
            rows={CLASSES.filter((c) => findings.some((f) => f.class === c)).map((c) => ({
              key: c,
              label: c,
              value: findings.filter((f) => f.class === c).length,
              tone: "accent",
            }))}
            unit=""
            emptyTitle="no classes"
            emptyNote="a detection is a question, never a declared compromise"
          />
        </div>
      )}
      <div className="filters">
        <input
          type="search"
          placeholder="search findings"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search findings"
        />
        <select
          value={klass}
          onChange={(e) => setKlass(e.target.value)}
          aria-label="Filter by threat class"
        >
          <option value="ALL">all classes</option>
          {CLASSES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <span className="muted">
          {rows.length} of {findings.length} shown
        </span>
      </div>
      <div
        style={{ maxHeight: rows.length > WINDOW ? "70vh" : undefined, overflowY: rows.length > WINDOW ? "auto" : undefined }}
        onScroll={rows.length > shown ? (e) => {
          const el = e.currentTarget;
          if (el.scrollTop + el.clientHeight >= el.scrollHeight - 80) setShown((s) => Math.min(s + WINDOW, rows.length));
        } : undefined}
      >
      <table aria-label="Findings" aria-rowcount={rows.length}>
        <thead>
          <tr>
            <th>class</th>
            <th>asset</th>
            <th>what changed</th>
            <th>why it matters</th>
            <th>evidence</th>
            <th>what is NOT proven</th>
            <th>what to investigate</th>
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, shown).map((f, i) => (
            <tr key={`${f.class}-${f.asset}-${i}`}>
              <td>
                <span className="chip">{f.class}</span>
              </td>
              <td>{f.asset}</td>
              <td>{f.what_changed}</td>
              <td>{f.why_it_matters}</td>
              <td>
                {f.evidence_ids.map((id) => (
                  <span
                    key={id}
                    className="evidence"
                    onClick={() => onEvidence?.(id)}
                    role="link"
                    tabIndex={0}
                  >
                    {id}
                  </span>
                ))}
              </td>
              <td className="not-proven">{f.not_proven}</td>
              <td>{f.investigate}</td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={7} className="muted">
                no findings match this filter — which is an empty result, not a
                clean estate
              </td>
            </tr>
          )}
        </tbody>
      </table>
      {rows.length > shown && (
        <div className="dim" role="status" style={{ fontSize: 12, padding: "6px 2px" }}>
          Showing {shown.toLocaleString()} of {rows.length.toLocaleString()} findings — scroll to
          load more (windowed rendering; the rest is not in the DOM).
        </div>
      )}
      </div>
    </section>
  );
}
