/* Remediation priorities — every crypto weakness the agents observed, ranked.
 *
 * The list is read from the estate graph, the same source the Digital Twin, the Simulation and
 * the Migration what-if pages use, so on the sandbox it shows the Meridian bank's weaknesses.
 * Examples: an RSA-1024 certificate, TLS 1.0 on the legacy branch, a 3DES key slot in the
 * payment HSM, an OpenSSL without ML-KEM, an expiring certificate, a vendor with no
 * post-quantum release. The rank is severity × the criticality of the system that carries the
 * weakness. Any finding can be turned into a tracked task, and the task is verified against
 * the agents' next report.
 */
import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge } from "../components/ui";
import { IconTarget, IconSecurity } from "../components/icons";
import {
  SEVERITIES, SEV_COLOR, SEV_TONE, TASK_TONE, EstateLoadStates, PageHeader, chip, inputStyle, kicker, observedLine, tile,
  useEstateRead,
} from "../components/remediationUi";
import { apiEstateRemediationFindings, apiOpenEstateTasks } from "../lib/api.js";
import type { EstateRemediationFinding, EstateRemediationFindings, RemediationSeverity } from "../lib/api.js";

const BOMS = ["CBOM", "NBOM", "SBOM", "HBOM", "VBOM"];
const BOM_LABEL: Record<string, string> = {
  CBOM: "crypto", NBOM: "network", SBOM: "software", HBOM: "hardware", VBOM: "vendors",
};

const read = () => apiEstateRemediationFindings();
const ok = (d: EstateRemediationFindings) => Array.isArray(d.findings);

function Detail({ f }: { f: EstateRemediationFinding }) {
  const cell = (label: string, value: React.ReactNode) => (
    <div><div style={kicker}>{label}</div><div style={{ fontSize: 12, marginTop: 2, lineHeight: 1.5 }}>{value || "—"}</div></div>
  );
  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, padding: "10px 4px" }}>
      {cell("WHY IT MATTERS", f.cause)}
      {cell("WHAT TO DO", f.action)}
      {cell("WHO ACTS", f.who_acts)}
      {cell("REPLACE WITH", f.replace_with)}
      {cell("CLOSED WHEN", f.verify_by)}
      {cell("WHY THIS RANK", `${f.rank_reason} · score ${f.score}`)}
      {cell("ASSET", <>{f.asset_name}{f.asset_type && <span style={{ color: "var(--faint)" }}> · {f.asset_type.toLowerCase()}</span>}</>)}
      {cell("EVIDENCE", f.basis.replace(/_/g, " ").toLowerCase())}
    </div>
  );
}

export default function Priorities() {
  const { data, state, error, load } = useEstateRead(read, ok);
  const [sev, setSev] = useState<RemediationSeverity | "">("");
  const [bom, setBom] = useState("");
  const [system, setSystem] = useState("");
  const [query, setQuery] = useState("");
  const [onlyOpen, setOnlyOpen] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [owner, setOwner] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ ok: boolean; text: string } | null>(null);

  const findings = data?.findings ?? [];
  const systems = useMemo(() => Array.from(new Set(findings.flatMap((f) => f.systems))).sort(), [findings]);
  const shown = useMemo(() => findings.filter((f) =>
    (!sev || f.severity === sev) && (!bom || f.bom === bom) && (!system || f.systems.includes(system))
    && (!onlyOpen || !f.task) && (!query.trim() || `${f.title} ${f.asset_name ?? ""} ${f.algorithm ?? ""}`.toLowerCase().includes(query.trim().toLowerCase()))),
  [findings, sev, bom, system, query, onlyOpen]);
  const untasked = shown.filter((f) => !f.task || ["VERIFIED"].includes(f.task.status));

  const open = async (ids: string[], key: string) => {
    if (!ids.length) return;
    setBusy(key);
    setNotice(null);
    const response = await apiOpenEstateTasks({ source: "estate", ids, owner: owner.trim() || undefined });
    setBusy(null);
    if (response.data) {
      setNotice({ ok: true, text: response.data.message });
      void load();
    } else {
      setNotice({ ok: false, text: response.detail || response.error || "the tasks could not be opened" });
    }
  };

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <PageHeader kickerText="REMEDIATION · RANKED FROM THE ESTATE" title="Remediation priorities" icon={<IconTarget size={18} />}>
        <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 780 }}>
          Every crypto weakness the agents observed, most urgent first: severity × how critical the system is.
          Turn any of them into a tracked task. The task is checked against the agents' next report.
        </p>
        <div style={{ display: "flex", gap: 12, marginTop: 10, fontSize: 11.5, color: "var(--dim)", flexWrap: "wrap", alignItems: "center" }}>
          <IconSecurity size={13} /> <span>Read-only until you open a task — nothing in the estate is changed.</span>
          {data && <span style={{ fontFamily: "var(--mono)", color: "var(--faint)" }}>{observedLine(data.run_id, data.observed_at)}</span>}
          <Link to="/remediation" style={{ color: "var(--amber)" }}>Tasks →</Link>
          <Link to="/migration" style={{ color: "var(--amber)" }}>Migration waves →</Link>
        </div>
      </PageHeader>

      <EstateLoadStates state={state} error={error} load={load} what="The priority list" />

      {data && (
        <>
          <div aria-label="Findings by severity" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))", gap: 12 }}>
            {SEVERITIES.map((s) => (
              <button key={s} type="button" aria-pressed={sev === s} aria-label={`Show ${s}`} onClick={() => setSev(sev === s ? "" : s)}
                style={{ ...tile, textAlign: "left", cursor: "pointer", borderTop: `3px solid ${SEV_COLOR[s]}`, outline: sev === s ? `2px solid ${SEV_COLOR[s]}` : "none" }}>
                <div style={kicker}>{s}</div>
                <div style={{ fontSize: 26, fontWeight: 800, fontFamily: "var(--mono)", color: data.counts_by_severity[s] ? SEV_COLOR[s] : "var(--dim)" }}>
                  {data.counts_by_severity[s] ?? 0}
                </div>
              </button>
            ))}
            <div style={{ ...tile, borderTop: "3px solid var(--violet)" }}>
              <div style={kicker}>WITHOUT A TASK</div>
              <div style={{ fontSize: 26, fontWeight: 800, fontFamily: "var(--mono)" }}>{findings.filter((f) => !f.task).length}</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>of {data.total} findings</div>
            </div>
          </div>

          <Panel title="Findings" sub={`${shown.length} of ${data.total} shown`} style={{ marginTop: 14 }}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
              <input aria-label="Search findings" placeholder="Search asset, algorithm…" value={query} onChange={(e) => setQuery(e.target.value)} style={{ ...inputStyle, minWidth: 220 }} />
              <select aria-label="System" value={system} onChange={(e) => setSystem(e.target.value)} style={inputStyle}>
                <option value="">All systems</option>
                {systems.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
              {BOMS.filter((b) => data.counts_by_bom[b]).map((b) => (
                <button key={b} type="button" aria-pressed={bom === b} aria-label={`Only ${b}`} style={chip(bom === b)} onClick={() => setBom(bom === b ? "" : b)}>
                  {b} <span style={{ color: "var(--faint)" }}>· {BOM_LABEL[b]} · {data.counts_by_bom[b]}</span>
                </button>
              ))}
              <label style={{ fontSize: 11.5, color: "var(--dim)", display: "flex", gap: 5, alignItems: "center" }}>
                <input type="checkbox" checked={onlyOpen} onChange={(e) => setOnlyOpen(e.target.checked)} /> without a task
              </label>
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 12, padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
              <input aria-label="Task owner" placeholder="owner (optional)" value={owner} onChange={(e) => setOwner(e.target.value)} style={{ ...inputStyle, minWidth: 180 }} />
              <button className="btn primary" disabled={busy !== null || untasked.length === 0} onClick={() => void open(untasked.map((f) => f.id), "bulk")}>
                {busy === "bulk" ? "Opening…" : `Open tasks for ${untasked.length} shown finding${untasked.length === 1 ? "" : "s"}`}
              </button>
              {notice && <span role={notice.ok ? "status" : "alert"} style={{ fontSize: 12, color: notice.ok ? "var(--green)" : "var(--red)" }}>{notice.text}</span>}
            </div>

            {shown.length === 0 ? (
              <div style={{ fontSize: 12.5, color: "var(--dim)" }}>
                {data.total === 0 ? "The agents observed no weakness this ranking checks for. See below for what it could not see." : "No finding matches these filters."}
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table className="tbl" aria-label="Ranked findings" style={{ width: "100%" }}>
                  <thead><tr><th>#</th><th>Severity</th><th>Finding</th><th>Systems</th><th>BOM</th><th>Task</th></tr></thead>
                  <tbody>
                    {shown.map((f, i) => (
                      <React.Fragment key={f.id}>
                        <tr>
                          <td style={{ fontFamily: "var(--mono)", color: "var(--faint)", width: 34 }}>{i + 1}</td>
                          <td><Badge tone={SEV_TONE[f.severity]}>{f.severity}</Badge></td>
                          <td>
                            <button type="button" aria-expanded={openId === f.id} aria-label={`Details of ${f.title}`} onClick={() => setOpenId(openId === f.id ? null : f.id)}
                              style={{ background: "none", border: "none", padding: 0, color: "var(--text)", textAlign: "left", cursor: "pointer", fontSize: 12.5, fontWeight: 600 }}>
                              {f.title}
                            </button>
                            <div style={{ fontSize: 11, color: "var(--dim)", marginTop: 2 }}>{f.action}</div>
                          </td>
                          <td style={{ fontSize: 11.5 }}>{f.systems.length ? f.systems.join(", ") : <span style={{ color: "var(--faint)" }}>no system claims it</span>}</td>
                          <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{f.bom}</span></td>
                          <td>
                            {f.task && f.task.status !== "VERIFIED" ? (
                              <Link to="/remediation" style={{ textDecoration: "none" }}><Badge tone={TASK_TONE[f.task.status] || "slate"}>{f.task.status}</Badge></Link>
                            ) : (
                              <button className="btn sm" disabled={busy !== null} aria-label={`Open task for ${f.title}`} onClick={() => void open([f.id], f.id)}>
                                {busy === f.id ? "Opening…" : "Open task"}
                              </button>
                            )}
                          </td>
                        </tr>
                        {openId === f.id && <tr><td colSpan={6} style={{ background: "var(--bg-2)" }}><Detail f={f} /></td></tr>}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {Object.keys(data.counts_by_system).length > 0 && (
            <Panel title="By system" sub="open findings per business system" style={{ marginTop: 14 }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: 10 }}>
                {Object.entries(data.counts_by_system).map(([name, counts]) => (
                  <button key={name} type="button" aria-label={`Only ${name}`} onClick={() => setSystem(system === name ? "" : name)}
                    style={{ ...tile, padding: 12, textAlign: "left", cursor: "pointer", outline: system === name ? "2px solid var(--violet)" : "none" }}>
                    <div style={{ fontSize: 12.5, fontWeight: 700, marginBottom: 6 }}>{name}</div>
                    <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
                      {SEVERITIES.filter((s) => counts[s]).map((s) => <Badge key={s} tone={SEV_TONE[s]}>{`${counts[s]} ${s.toLowerCase()}`}</Badge>)}
                    </div>
                  </button>
                ))}
              </div>
            </Panel>
          )}

          <details style={{ ...tile, marginTop: 14 }}>
            <summary style={{ cursor: "pointer", fontSize: 12.5, fontWeight: 700 }}>What this ranking cannot see ({data.unknowns.length})</summary>
            <ul style={{ margin: "8px 0 0", paddingLeft: 18, fontSize: 12, color: "var(--dim)", lineHeight: 1.6 }}>
              {data.unknowns.map((u) => <li key={u}>{u}</li>)}
              <li>How the rank is computed: {data.ranking}.</li>
            </ul>
          </details>
        </>
      )}
    </div>
  );
}
