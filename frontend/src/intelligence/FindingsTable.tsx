import React, { useMemo, useState } from "react";
import type { ThreatClass, ThreatFinding } from "./types";

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
 *  declared compromise — the header says so on every render. */
export default function FindingsTable({
  findings,
  onEvidence,
}: {
  findings: ThreatFinding[];
  onEvidence?: (evidenceId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [klass, setKlass] = useState<string>("ALL");

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
      <table aria-label="Findings">
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
          {rows.map((f, i) => (
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
    </section>
  );
}
