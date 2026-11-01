import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Table, PageHead, Kpi, Code, Drawer, Bar, Ring, Stat } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { ChannelLiveBadge, useChannelRefresh } from "../lib/realtime.js";
import { RequireRole } from "../lib/auth.js";
import { ICON_MD, ICON_SM, IconClose, IconRunning, StatusMark, IconSearch, IconCertificate, IconTrendUp, IconTrendDown } from "../components/icons";
import {
  apiFindings,
  apiFindingDetail,
  apiFindingVerify,
  apiRemediationTasks,
  apiTriggerScan,
  apiRuntimeFindings,
  Finding,
  FindingVerifyVerdict,
  RemediationTask,
  RuntimeFindingsResponse,
  RuntimeFindingRow,
} from "../lib/api.js";

/* Visualized Findings — evidence chain with distribution, health, and scan CTA */

const STATUS_TONE: Record<string, string> = {
  CRITICAL: "red", HIGH: "red", MEDIUM: "amber", LOW: "amber",
  NON_COMPLIANT: "red", FAIL: "red", PARTIAL: "amber", WARN: "amber",
  COMPLIANT: "green", PASS: "green", UNKNOWN: "",
};
function tone(status?: string | null): string {
  return status ? STATUS_TONE[String(status).toUpperCase()] ?? "" : "";
}
function statusBadge(status?: string | null) {
  const s = (status || "—").toUpperCase();
  return <Badge tone={tone(status)}>{s}</Badge>;
}
function confidenceBadge(c: string) {
  const up = (c || "").toUpperCase();
  const t = up === "HIGH" ? "green" : up === "MEDIUM" ? "amber" : up === "LOW" ? "red" : "";
  return <Badge tone={t}>{up || "—"}</Badge>;
}

// Findings are produced by scans and retractions: the page refreshes when either of those
// surfaces actually changes, instead of re-reading the same list every 8 seconds.
const FINDINGS_CHANNELS = ["findings", "crypto", "estate"];

export default function Findings() {
  const [algorithm, setAlgorithm] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<number>(-1);
  const [detail, setDetail] = useState<Finding | null>(null);
  const [detailLive, setDetailLive] = useState(false);
  const [detailErr, setDetailErr] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"table" | "cards">("table");

  const list = usePollingApi(
    () => apiFindings({ page, page_size: 50, algorithm: algorithm || undefined, compliance_status: status || undefined }),
    15000,
    [page, algorithm, status],
    { channels: FINDINGS_CHANNELS },
  );
  const runtime = usePollingApi(() => apiRuntimeFindings(50), 8000, [], { channels: FINDINGS_CHANNELS });
  useChannelRefresh(FINDINGS_CHANNELS, [list.run, runtime.run]);

  const [repoUrl, setRepoUrl] = useState("");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanMsg, setScanMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const runScan = async () => {
    if (!repoUrl.trim()) { setScanMsg({ ok: false, text: "Enter a repository URL to scan" }); return; }
    setScanBusy(true);
    setScanMsg(null);
    const r = await apiTriggerScan({ repo_url: repoUrl.trim() });
    setScanBusy(false);
    if (r.ok) {
      setScanMsg({ ok: true, text: `Scan queued (${r.status}) · job ${r.job_id} — findings appear as evidence lands` });
      setTimeout(() => { void list.run(); void runtime.run(); }, 6000);
    } else {
      setScanMsg({ ok: false, text: r.error || "scan failed to start" });
    }
  };

  const select = (i: number) => {
    setSelected(i);
    const f = list.data?.findings?.[i];
    if (!f) return;
    setDetail(null);
    setDetailErr(null);
    void apiFindingDetail(f.evidence_id).then((r) => {
      setDetail(r.data);
      setDetailLive(r.source === "live");
      if (!r.ok) setDetailErr(r.error || "failed to load finding");
    });
  };

  const findings = list.data?.findings ?? [];
  const total = list.data?.total_count ?? 0;
  const live = list.source === "live";

  const statusOptions = useMemo(() => {
    const seen = new Set<string>();
    for (const f of findings) if (f.compliance_status) seen.add(f.compliance_status);
    return Array.from(seen).sort();
  }, [findings]);

  const algos = useMemo(() => {
    const seen = new Set<string>();
    for (const f of findings) if (f.algorithm) seen.add(f.algorithm);
    return Array.from(seen).sort();
  }, [findings]);

  const hardcoded = findings.filter((f) => f.is_hardcoded_key).length;
  const nonCompliant = findings.filter((f) =>
    ["NON_COMPLIANT", "FAIL", "HIGH", "CRITICAL"].includes(String(f.compliance_status || "").toUpperCase())).length;
  const compliant = findings.filter((f) =>
    ["COMPLIANT", "PASS"].includes(String(f.compliance_status || "").toUpperCase())).length;

  // Visual aggregates
  const algoAgg = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set(f.algorithm || "Unknown", (m.get(f.algorithm || "Unknown") || 0) + 1);
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [findings]);
  const confidenceAgg = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set((f.confidence || "unknown").toUpperCase(), (m.get((f.confidence || "unknown").toUpperCase()) || 0) + 1);
    return Array.from(m.entries());
  }, [findings]);
  const statusAgg = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) m.set((f.compliance_status || "UNKNOWN").toUpperCase(), (m.get((f.compliance_status || "UNKNOWN").toUpperCase()) || 0) + 1);
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]);
  }, [findings]);
  const shareCompliant = total ? compliant / Math.max(1, total) : 0;
  const shareNonCompliant = total ? nonCompliant / Math.max(1, total) : 0;

  useEffect(() => { setSelected(-1); setDetail(null); setPage(1); }, [algorithm, status]);

  return (
    <>
      <PageHead
        crumb="intelligence / findings"
        title="Findings"
        sub="Deterministic evidence-chain — every row is a content-hash + chain-hash observation"
        right={
          <>
            <LiveBadge source={live ? "live" : "offline"} label={live ? "EVIDENCE CHAIN" : "BACKEND OFFLINE"} />
            <ChannelLiveBadge channels={FINDINGS_CHANNELS} label="findings" />
            <Badge tone={live ? "cyan" : ""}><span className="dot" /> {total.toLocaleString()} FINDINGS</Badge>
          </>
        }
      />

      {/* ── Hero KPIs — visual ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginBottom: 12 }}>
        <div className="panel" style={{ padding: "14px 16px", borderTop: "2px solid var(--cyan)", display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <div>
            <div style={{ fontSize: 10, letterSpacing: ".1em", color: "var(--faint)" }}>TOTAL FINDINGS</div>
            <div style={{ fontSize: 26, fontWeight: 800, fontFamily: "var(--mono)", margin: "2px 0" }}>{total.toLocaleString()}</div>
            <div style={{ fontSize: 11, color: "var(--dim)" }}>{findings.length} in view · page {page}</div>
            <div style={{ marginTop: 8, width: 96 }}><Bar value={Math.min(1, total / 200)} tone="cyan" /></div>
          </div>
          <div style={{ width: 74, height: 74, position: "relative" }}>
            <svg width={74} height={74} viewBox="0 0 74 74">
              <circle cx={37} cy={37} r={28} fill="none" stroke="var(--line-strong)" strokeWidth={6} />
              <circle cx={37} cy={37} r={28} fill="none" stroke="var(--cyan)" strokeWidth={6} strokeDasharray={`${Math.min(1, total / 200) * 176} 176`} strokeLinecap="round" transform="rotate(-90 37 37)" />
            </svg>
            <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", fontSize: 11, fontWeight: 700, color: "var(--cyan)" }}>{live ? "LIVE" : "—"}</div>
          </div>
        </div>
        <div className="panel" style={{ padding: "14px 16px", borderTop: "2px solid var(--line-strong)" }}>
          <div style={{ fontSize: 10, letterSpacing: ".1em", color: "var(--faint)" }}>IN THIS VIEW</div>
          <div style={{ fontSize: 26, fontWeight: 800, fontFamily: "var(--mono)" }}>{findings.length.toLocaleString()}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>{algorithm || status ? `filtered` : "no filter"} · {status || "any status"}</div>
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            <span style={{ flex: 1, height: 6, borderRadius: 99, background: "var(--cyan)", opacity: .9 }} />
            <span style={{ flex: 0.5, height: 6, borderRadius: 99, background: "var(--line-strong)" }} />
          </div>
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{algorithm ? `algo: ${algorithm}` : "all algorithms"}</div>
        </div>
        <div className="panel" style={{ padding: "14px 16px", borderTop: `2px solid ${nonCompliant ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ fontSize: 10, letterSpacing: ".1em", color: "var(--faint)" }}>NON-COMPLIANT</div>
          <div style={{ fontSize: 26, fontWeight: 800, color: nonCompliant ? "var(--red)" : "var(--green)" }}>{nonCompliant}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>{compliant} compliant · {shareNonCompliant ? `${Math.round(shareNonCompliant * 100)}%` : "0%"} risk exposure</div>
          <div style={{ marginTop: 8 }}><Bar value={shareNonCompliant} tone={nonCompliant ? "red" : "green"} /></div>
        </div>
        <div className="panel" style={{ padding: "14px 16px", borderTop: `2px solid ${hardcoded ? "var(--amber)" : "var(--green)"}` }}>
          <div style={{ fontSize: 10, letterSpacing: ".1em", color: "var(--faint)" }}>HARDCODED KEYS</div>
          <div style={{ fontSize: 26, fontWeight: 800, color: hardcoded ? "var(--amber)" : "var(--text)" }}>{hardcoded}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>{hardcoded ? "requires rotation" : "none detected in view"}</div>
          <div style={{ marginTop: 8 }}><Bar value={findings.length ? hardcoded / findings.length : 0} tone={hardcoded ? "amber" : "green"} /></div>
          {hardcoded > 0 && <div style={{ fontSize: 10, color: "var(--amber)", marginTop: 4 }}>● hardcoded = plaintext secret in source</div>}
        </div>
      </div>

      {/* ── Distribution visuals ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 0.9fr", gap: 12, marginBottom: 12 }}>
        <Panel title="Algorithm distribution" sub={algoAgg.length ? `top ${algoAgg.length} in view — click chip to filter` : "no algorithms in view"} style={{ padding: "12px 14px" }}>
          {algoAgg.length ? (
            <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 8 }}>
              {algoAgg.map(([name, cnt]) => {
                const pct = findings.length ? cnt / findings.length : 0;
                const active = algorithm === name;
                return (
                  <button key={name} onClick={() => setAlgorithm(active ? "" : name)} style={{ display: "grid", gridTemplateColumns: "110px 1fr 52px", gap: 10, alignItems: "center", padding: "7px 10px", borderRadius: "var(--r)", border: `1px solid ${active ? "var(--cyan)" : "var(--line)"}`, background: active ? "color-mix(in srgb, var(--cyan) 10%, var(--panel))" : "var(--panel-2)", textAlign: "left", cursor: "pointer" }}>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 700, color: active ? "var(--cyan)" : "var(--text)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{name}</span>
                    <span style={{ height: 8, background: "var(--bg)", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
                      <span style={{ display: "block", height: "100%", width: `${pct * 100}%`, background: active ? "var(--cyan)" : "var(--violet)", transition: "width .3s" }} />
                    </span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)", textAlign: "right" }}>{cnt} · {Math.round(pct * 100)}%</span>
                  </button>
                );
              })}
            </div>
          ) : <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>Run a scan to populate.</div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8 }}>Evidence-backed — each bar is a distinct algorithm observation.</div>
        </Panel>

        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <Panel title="Compliance split" sub="policy verdicts in view" style={{ padding: "12px 14px" }}>
            {statusAgg.length ? (
              <>
                <div style={{ display: "flex", height: 10, borderRadius: 99, overflow: "hidden", background: "var(--bg-2)", border: "1px solid var(--line)", marginTop: 8 }}>
                  {statusAgg.map(([s, cnt]) => {
                    const pct = findings.length ? cnt / findings.length : 0;
                    const col = tone(s) === "red" ? "var(--red)" : tone(s) === "amber" ? "var(--amber)" : tone(s) === "green" ? "var(--green)" : "var(--slate)";
                    return <span key={s} title={`${s}: ${cnt}`} style={{ width: `${pct * 100}%`, background: col }} />;
                  })}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
                  {statusAgg.map(([s, cnt]) => (
                    <span key={s} style={{ display: "inline-flex", alignItems: "center", gap: 6, padding: "4px 8px", borderRadius: 99, border: "1px solid var(--line)", background: "var(--panel-2)", fontSize: 11 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 99, background: tone(s) === "red" ? "var(--red)" : tone(s) === "amber" ? "var(--amber)" : tone(s) === "green" ? "var(--green)" : "var(--slate)" }} />{s} <b style={{ fontFamily: "var(--mono)" }}>{cnt}</b>
                    </span>
                  ))}
                </div>
              </>
            ) : <div className="dim" style={{ fontSize: 12 }}>No verdicts yet.</div>}
          </Panel>

          <Panel title="Confidence" sub="signal strength" style={{ padding: "12px 14px" }}>
            {confidenceAgg.length ? (
              <div style={{ display: "flex", gap: 8, alignItems: "end", marginTop: 8, height: 56 }}>
                {confidenceAgg.map(([c, cnt]) => {
                  const h = findings.length ? (cnt / findings.length) * 52 + 8 : 8;
                  const col = c === "HIGH" ? "var(--green)" : c === "MEDIUM" ? "var(--amber)" : c === "LOW" ? "var(--red)" : "var(--slate)";
                  return (
                    <div key={c} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                      <div style={{ width: "100%", height: h, background: col, borderRadius: "var(--r)", opacity: .95, border: "1px solid var(--line)" }} />
                      <span style={{ fontSize: 10, letterSpacing: ".06em", color: "var(--dim)" }}>{c}</span>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700 }}>{cnt}</span>
                    </div>
                  );
                })}
              </div>
            ) : <div className="dim" style={{ fontSize: 12 }}>—</div>}
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>HIGH = near-certain · LOW = heuristic</div>
          </Panel>
        </div>
      </div>

      {/* ── Filter — visual chips ── */}
      <Panel title="Filter" sub="refine the evidence view — filters are live, paginated server-side" className="mt" style={{ padding: "12px 14px" }}>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "end" }}>
          <label style={{ flex: "1 1 260px" }}>
            <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>ALGORITHM</div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <IconSearch size={14} style={{ color: "var(--faint)" }} />
              <input
                value={algorithm}
                onChange={(e) => setAlgorithm(e.target.value)}
                placeholder="e.g. RSA, AES, MD5, ECDSA"
                className="inp"
                style={{ flex: 1 }}
              />
              {algorithm && <button className="btn sm" onClick={() => setAlgorithm("")}>✕</button>}
            </div>
          </label>
          <label style={{ flex: "1 1 200px" }}>
            <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>STATUS</div>
            <select value={status} onChange={(e) => setStatus(e.target.value)} className="inp">
              <option value="">All — {total} total</option>
              {statusOptions.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>Quick:</span>
            {(algos.length ? algos.slice(0, 6) : ["RSA", "AES", "DES", "MD5"]).map((a) => (
              <button key={a} onClick={() => setAlgorithm(algorithm === a ? "" : a)} className="btn sm" style={{ background: algorithm === a ? "var(--accent)" : "var(--panel-2)", color: algorithm === a ? "var(--on-accent)" : "var(--text)", borderColor: algorithm === a ? "var(--accent)" : "var(--line)", fontWeight: algorithm === a ? 700 : 500 }}>{a}</button>
            ))}
            {(statusOptions.slice(0, 3)).map((s) => (
              <button key={s} onClick={() => setStatus(status === s ? "" : s)} className="btn sm" style={{ background: status === s ? "var(--accent)" : "transparent", color: status === s ? "var(--on-accent)" : "var(--dim)", borderColor: status === s ? "var(--accent)" : "var(--line)" }}>{s}</button>
            ))}
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
            <span className="dim" style={{ fontSize: 11 }}>{findings.length} rows · {hardcoded} hardcoded</span>
            <button className="btn sm" onClick={() => { setAlgorithm(""); setStatus(""); }}>Reset</button>
          </div>
        </div>
      </Panel>

      {/* ── Run scan — visual CTA ── */}
      <Panel title="" sub="" className="mt" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.3fr .9fr", gap: 0 }}>
          <div style={{ padding: "16px 18px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 6 }}>
              <span style={{ width: 28, height: 28, borderRadius: 8, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)", fontWeight: 800, fontSize: 14 }}>↗</span>
              <div>
                <div style={{ fontWeight: 800, fontSize: 14 }}>Run a universal source scan</div>
                <div style={{ fontSize: 12, color: "var(--dim)" }}>Collect findings backed by the evidence chain — worker → WORM</div>
              </div>
              <Badge tone="cyan">UNIVERSAL</Badge>
            </div>
            <label style={{ display: "block", marginTop: 10 }}>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>REPOSITORY URL (GIT / HTTPS / LOCAL PATH)</div>
              <div style={{ display: "flex", gap: 8 }}>
                <input value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://github.com/your-org/app or /path/to/repo" className="inp" style={{ flex: 1 }} />
                <RequireRole anyOf={["superadmin", "ciso", "security_analyst", "developer", "scanner"]} fallback={<span className="dim" style={{ fontSize: 12, alignSelf: "center" }}>read-only</span>}>
                  <button className="btn primary" onClick={() => void runScan()} disabled={scanBusy || !repoUrl.trim()} style={{ whiteSpace: "nowrap" }}>
                    {scanBusy ? "Queuing…" : <><IconRunning size={ICON_SM} /> Run scan</>}
                  </button>
                </RequireRole>
              </div>
            </label>
            {scanMsg && (
              <div className={`auth-alert ${scanMsg.ok ? "ok" : "err"}`} style={{ marginTop: 10 }}>
                <StatusMark ok={scanMsg.ok} muted />{scanMsg.text}
              </div>
            )}
            <div className="dim" style={{ fontSize: 11.5, marginTop: 8, lineHeight: 1.6 }}>
              Permission-gated via <code>scan.trigger</code> matrix. List refreshes automatically as evidence lands — ~6s after queue.
            </div>
          </div>
          <div style={{ background: "var(--bg-2)", borderLeft: "1px solid var(--line)", padding: "14px 16px", display: "flex", flexDirection: "column", gap: 10 }}>
            <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>PIPELINE</div>
            {[["Queued", "job admitted"], ["Scanning", "detectors run"], ["Evidence", "hash + chain"], ["Findings", "appear here"]].map(([t, d], i) => (
              <div key={t} style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{ width: 22, height: 22, borderRadius: 99, display: "grid", placeItems: "center", background: "var(--panel)", border: "1px solid var(--line-strong)", fontSize: 11, fontWeight: 700, color: "var(--cyan)" }}>{i + 1}</span>
                <div style={{ flex: 1 }}><div style={{ fontSize: 12, fontWeight: 700 }}>{t}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{d}</div></div>
                {i < 3 && <span style={{ color: "var(--line-strong)" }}>→</span>}
              </div>
            ))}
            <div style={{ marginTop: 4, padding: "8px 10px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11, color: "var(--dim)" }}>
              Tip: scan a local path for fastest feedback. Remote clones respect proxy + credential policy.
            </div>
          </div>
        </div>
      </Panel>

      {/* ── Evidence findings — visualized table ── */}
      <Panel title="Evidence findings" sub={live ? `deterministic — page ${page} · click row for drawer` : "backend offline"} className="mt" style={{ padding: "12px 14px" }}>
        <div style={{ display: "flex", gap: 8, alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", marginBottom: 8 }}>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Badge tone="cyan">{findings.length} rows</Badge>
            <Badge tone={nonCompliant ? "red" : "green"}>{nonCompliant} non-compliant</Badge>
            {live ? <span style={{ fontSize: 11, color: "var(--green)" }}>● live</span> : <span style={{ fontSize: 11, color: "var(--amber)" }}>● offline</span>}
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>View</span>
            <button onClick={() => setViewMode("table")} className="btn sm" style={{ background: viewMode === "table" ? "var(--accent)" : "var(--panel-2)", color: viewMode === "table" ? "var(--on-accent)" : "var(--text)", borderColor: viewMode === "table" ? "var(--accent)" : "var(--line)" }}>Table</button>
            <button onClick={() => setViewMode("cards")} className="btn sm" style={{ background: viewMode === "cards" ? "var(--accent)" : "var(--panel-2)", color: viewMode === "cards" ? "var(--on-accent)" : "var(--text)", borderColor: viewMode === "cards" ? "var(--accent)" : "var(--line)" }}>Cards</button>
          </div>
        </div>

        {viewMode === "table" ? (
          <>
            <Table
              clickable
              selected={selected}
              onSelect={select}
              head={["finding", "algorithm", "key", "status", "confidence", "location"]}
              rows={findings.map((f) => [
                <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: tone(f.compliance_status) === "red" ? "var(--red)" : tone(f.compliance_status) === "amber" ? "var(--amber)" : "var(--green)", display: "inline-block" }} /><span className="mono" style={{ fontWeight: 700 }}>{f.evidence_id.slice(0, 10)}…</span>{f.is_hardcoded_key && <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 99, background: "var(--amber)", color: "#000", fontWeight: 700 }}>HARDCODED</span>}</span>,
                <Badge tone="violet">{f.algorithm}</Badge>,
                <span className="num">{f.key_size ?? "—"}{f.mode ? ` · ${f.mode}` : ""}{f.key_size && f.key_size < 2048 ? <span style={{ color: "var(--red)", marginLeft: 6 }}>● weak</span> : null}</span>,
                statusBadge(f.compliance_status),
                confidenceBadge(f.confidence),
                <span className="dim" style={{ fontSize: 12, maxWidth: 260, display: "inline-block", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {f.file_path || "—"}{f.line_number ? `:${f.line_number}` : ""}{f.class_name ? ` · ${f.class_name}` : ""}
                </span>,
              ])}
            />
            {!findings.length && (
              <div style={{ textAlign: "center", padding: "22px 16px", border: "1px dashed var(--line-strong)", borderRadius: "var(--r)", marginTop: 8, background: "var(--bg-2)" }}>
                <div style={{ fontSize: 18 }}>⬡</div>
                <div style={{ fontWeight: 700, marginTop: 6 }}>{live ? "No findings match this filter." : "Backend offline — no findings yet."}</div>
                <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>Try clearing algorithm/status or run a new scan above.</div>
              </div>
            )}
          </>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))", gap: 10, marginTop: 8 }}>
            {findings.map((f, i) => (
              <button key={f.evidence_id} onClick={() => select(i)} style={{ textAlign: "left", padding: "12px 14px", borderRadius: "var(--r)", border: `1px solid ${selected === i ? "var(--cyan)" : "var(--line)"}`, background: selected === i ? "color-mix(in srgb, var(--cyan) 8%, var(--panel))" : "var(--panel-2)", cursor: "pointer" }}>
                <div style={{ display: "flex", gap: 8, alignItems: "center", justifyContent: "space-between" }}>
                  <span className="mono" style={{ fontWeight: 800, fontSize: 12 }}>{f.evidence_id.slice(0, 12)}</span>
                  {statusBadge(f.compliance_status)}
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}><Badge tone="violet">{f.algorithm}</Badge><Badge tone={f.is_hardcoded_key ? "amber" : "slate"}>{f.key_size ?? "—"} {f.mode || ""}</Badge>{confidenceBadge(f.confidence)}</div>
                <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 8, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{f.file_path || "—"}{f.line_number ? `:${f.line_number}` : ""}</div>
                <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>{f.class_name || ""} {f.method_name ? `· ${f.method_name}` : ""}</div>
              </button>
            ))}
            {!findings.length && <div className="dim" style={{ fontSize: 13, padding: 12, border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>No findings in card view.</div>}
          </div>
        )}

        <div className="row" style={{ gap: 8, marginTop: 14, justifyContent: "space-between" }}>
          <span className="dim" style={{ fontSize: 12 }}>
            page {page} · {list.data?.page_size ?? 50} per page · {total.toLocaleString()} total
          </span>
          <div className="row" style={{ gap: 8 }}>
            <button className="btn sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>← prev</button>
            <button className="btn sm" disabled={page * 50 >= total} onClick={() => setPage((p) => p + 1)}>next →</button>
          </div>
        </div>
      </Panel>

      <Panel
        title="Live runtime findings"
        sub={(runtime.data as RuntimeFindingsResponse | null)?.summary
          ? "continuous — weak TLS & risky libs"
          : "always-on scanners"}
        className="mt"
        style={{ padding: "12px 14px" }}
      >
        <RuntimeFeed data={runtime.data as RuntimeFindingsResponse | null} live={runtime.source === "live"} />
      </Panel>

      {selected >= 0 && (
        <Drawer
          title={`Finding ${detail?.evidence_id ?? findings[selected]?.evidence_id ?? ""}`}
          sub={detailLive ? "Live evidence record" : detail ? "evidence record" : "loading…"}
          onClose={() => { setSelected(-1); setDetail(null); }}
        >
          {detailErr && <div className="auth-alert err"><IconClose size={ICON_MD} /> {detailErr}</div>}
          {!detail && !detailErr && <div className="dim">Loading evidence record…</div>}
          {detail && (
            <FindingDetail f={detail} />
          )}
        </Drawer>
      )}
    </>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  const asset = [f.file_path, f.class_name, f.method_name].filter(Boolean).join(" · ") || "—";
  const [verdict, setVerdict] = useState<FindingVerifyVerdict | null>(null);
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyErr, setVerifyErr] = useState<string | null>(null);
  const [tasks, setTasks] = useState<RemediationTask[] | null>(null);

  useEffect(() => {
    let alive = true;
    setVerdict(null);
    setVerifyErr(null);
    setTasks(null);
    void apiRemediationTasks({ evidence_id: f.evidence_id, page_size: 20 }).then((r) => {
      if (!alive) return;
      setTasks(r.source === "live" && r.data ? (r.data.tasks ?? []) : null);
    });
    return () => { alive = false; };
  }, [f.evidence_id]);

  async function runVerify() {
    setVerifyBusy(true);
    setVerifyErr(null);
    const r = await apiFindingVerify(f.evidence_id);
    setVerifyBusy(false);
    if (r.source === "live" && r.data) {
      setVerdict(r.data);
    } else {
      setVerdict(null);
      setVerifyErr(
        r.error === "HTTP 403"
          ? "Requires auditor role — per-record verification is an audit action."
          : r.error || "verification failed");
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="kpi-strip" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(120px,1fr))" }}>
        <Mini label="Algorithm" v={f.algorithm} badge="violet" />
        <Mini label="Key / mode" v={`${f.key_size ?? "—"}${f.mode ? ` ${f.mode}` : ""}`} />
        <Mini label="Status" v={f.compliance_status || "—"} badge={tone(f.compliance_status)} />
        <Mini label="Confidence" v={f.confidence || "—"} />
      </div>

      <div className="grid cols-2">
        <Panel title="Why it matters" sub="what this observation is">
          <div className="mono-list">
            <Row k="finding id" v={<span className="mono">{f.evidence_id}</span>} />
            <Row k="scan" v={<span className="mono">{f.scan_id}</span>} />
            <Row k="asset / location" v={asset} />
            <Row k="purpose" v={f.purpose || "—"} />
            <Row k="padding" v={f.padding || "—"} />
            <Row k="hardcoded key" v={f.is_hardcoded_key ? <Badge tone="red">hardcoded</Badge> : <Badge tone="green">not hardcoded</Badge>} />
            <Row k="first seen" v={fmtTs(f.created_at)} />
            <Row k="last seen" v={fmtTs(f.updated_at)} />
          </div>
        </Panel>
        <Panel title="Evidence chain" sub="tamper-evident hashes">
          <div className="mono-list">
            <Row k="content hash" v={<span className="mono" style={{ wordBreak: "break-all" }}>{f.content_hash}</span>} />
            <Row k="chain hash" v={<span className="mono" style={{ wordBreak: "break-all" }}>{f.chain_hash}</span>} />
            <Row k="confidence" v={confidenceBadge(f.confidence)} />
            <Row k="policy status" v={statusBadge(f.compliance_status)} />
          </div>
        </Panel>
      </div>

      {f.normalized_crypto && (
        <Panel title="Normalized crypto" sub="canonical CBOM fields">
          <Code>{JSON.stringify(f.normalized_crypto, null, 2)}</Code>
        </Panel>
      )}
      {f.policy_evaluation && (
        <Panel title="Policy evaluation" sub="deterministic rule verdict">
          <Code>{JSON.stringify(f.policy_evaluation, null, 2)}</Code>
        </Panel>
      )}
      {f.finding_data && (
        <Panel title="Source data" sub="raw detection payload">
          <Code>{JSON.stringify(f.finding_data, null, 2)}</Code>
        </Panel>
      )}

      <div className="grid cols-2">
        <Panel title="Record verification" sub="recompute hashes vs commitments">
          <button className="btn sm primary" disabled={verifyBusy} onClick={() => void runVerify()} style={{ fontSize: 12 }}>
            {verifyBusy ? "Verifying…" : "Verify this record"}
          </button>
          {verifyErr && (
            <div style={{ fontSize: 12.5, color: "var(--amber)", marginTop: 8 }}>{verifyErr}</div>
          )}
          {verdict && (
            <div className="mono-list" style={{ marginTop: 10 }}>
              <Row k="verdict" v={<Badge tone={verdict.result === "PASS" ? "green" : "red"}>{verdict.result}</Badge>} />
              <Row k="content intact" v={verdict.content_intact ? <Badge tone="green">yes</Badge> : <Badge tone="red">no</Badge>} />
              <Row k="chain intact" v={verdict.chain_intact ? <Badge tone="green">yes</Badge> : <Badge tone="red">no</Badge>} />
              <Row k="hash format" v={verdict.hash_format_valid ? <Badge tone="green">valid</Badge> : <Badge tone="red">invalid</Badge>} />
              {verdict.errors.length > 0 && (
                <Row k="errors" v={verdict.errors.map((e) => (
                  <div key={e} style={{ color: "var(--red)", fontSize: 12 }}>{e}</div>
                ))} />
              )}
              <Row k="verified by" v={<span className="mono">{verdict.verified_by}</span>} />
              <Row k="scan verify" v={<span className="mono">{verdict.scan_verify_path}</span>} />
              <div className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
                {verdict.notes?.[0] ||
                  "Verifies stored payload vs committed hashes — not a claim the observation was true."}
              </div>
            </div>
          )}
        </Panel>
        <Panel title="Remediation tasks" sub="tasks referencing this finding">
          {tasks === null && (
            <div className="dim" style={{ fontSize: 13 }}>Task lookup unavailable.</div>
          )}
          {tasks !== null && tasks.length === 0 && (
            <div className="dim" style={{ fontSize: 13, marginBottom: 8 }}>
              No tasks reference this — create from Priorities or scan.
            </div>
          )}
          {tasks !== null && tasks.length > 0 && (
            <div className="mono-list">
              {tasks.map((t) => (
                <Row key={t.id}
                  k={<span className="mono">{t.id.slice(0, 14)}…</span>}
                  v={
                    <span className="row" style={{ gap: 6 }}>
                      <Badge tone={tone(t.status)}>{String(t.status || "—").toUpperCase()}</Badge>
                      <span style={{ fontSize: 12 }}>{t.rule_id || "—"}</span>
                      {t.owner && <span style={{ fontSize: 12, color: "var(--dim)" }}>· {t.owner}</span>}
                    </span>
                  } />
              ))}
            </div>
          )}
          <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
            <Link to="/remediation" className="btn sm outline" style={{ textDecoration: "none", fontSize: 11.5, padding: "4px 10px" }}>
              Open task lifecycle →
            </Link>
            <span className="dim" style={{ fontSize: 11.5 }}>
              COMPLETED = declaration — VERIFIED = rescan verdict.
            </span>
          </div>
        </Panel>
      </div>
    </div>
  );
}

function Mini({ label, v, badge }: { label: string; v: React.ReactNode; badge?: string }) {
  return (
    <div className="kpi">
      <span className="k">{label}</span>
      <span className="v">{badge ? <Badge tone={badge}>{v}</Badge> : v}</span>
    </div>
  );
}
function Row({ k, v }: { k: React.ReactNode; v: React.ReactNode }) {
  return (
    <div className="spread" style={{ fontSize: 13, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="dim">{k}</span>
      <span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}
function fmtTs(ts?: string | null): React.ReactNode {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return <span className="mono">{ts}</span>;
  return <span className="mono">{d.toLocaleString()}</span>;
}
function RuntimeFeed({ data, live }: { data: RuntimeFindingsResponse | null; live: boolean }) {
  if (!data) {
    return <div className="dim" style={{ fontSize: 13 }}>{live ? "No runtime observations yet." : "Backend offline — runtime findings unavailable."}</div>;
  }
  const rows = data.findings ?? [];
  const summary = data.summary ?? {};
  const weak = rows.filter((r) => r.weak_tls).length;
  return (
    <>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px,1fr))", gap: 10, marginBottom: 10 }}>
        <div className="panel" style={{ padding: "10px 12px", borderTop: "2px solid var(--cyan)" }}><div style={{ fontSize: 10, color: "var(--faint)" }}>RUNTIME FINDINGS</div><div style={{ fontSize: 20, fontWeight: 800, fontFamily: "var(--mono)" }}>{data.total_count.toLocaleString()}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>continuous</div></div>
        <div className="panel" style={{ padding: "10px 12px", borderTop: `2px solid ${weak ? "var(--red)" : "var(--green)"}` }}><div style={{ fontSize: 10, color: "var(--faint)" }}>WEAK TLS</div><div style={{ fontSize: 20, fontWeight: 800, color: weak ? "var(--red)" : "var(--green)" }}>{weak}</div><div style={{ fontSize: 11, color: "var(--dim)" }}>{weak ? "needs attention" : "clean"}</div></div>
        <div className="panel" style={{ padding: "10px 12px", borderTop: "2px solid var(--line-strong)" }}><div style={{ fontSize: 10, color: "var(--faint)" }}>HOSTS</div><div style={{ fontSize: 20, fontWeight: 800 }}>{String(summary.hosts ?? "—")}</div></div>
        <div className="panel" style={{ padding: "10px 12px", borderTop: "2px solid var(--line-strong)" }}><div style={{ fontSize: 10, color: "var(--faint)" }}>SCANNERS</div><div style={{ fontSize: 20, fontWeight: 800 }}>{String(summary.scanner_ids ?? "—")}</div></div>
      </div>
      <Table
        head={["algorithm / suite", "host · process", "tls", "status", "quantum", "last seen"]}
        total={rows.length} rows={rows.slice(0, 20).map((r: RuntimeFindingRow) => [
          <span className="mono" style={{ fontWeight: 600 }}>{r.algorithm || r.cipher_suite || "—"}</span>,
          <span className="dim" style={{ fontSize: 12 }}>{r.hostname || "—"} · {r.process_name || "—"}</span>,
          <Badge tone={r.weak_tls ? "red" : ""}>{r.tls_version || "—"}</Badge>,
          <Badge tone={String(r.status || "").toLowerCase().includes("disallow") || String(r.status || "").toLowerCase().includes("deprecat") ? "red" : ""}>{r.status || "—"}</Badge>,
          <Badge tone={r.quantum_impact === "shor" ? "red" : r.quantum_impact ? "amber" : ""}>{r.quantum_impact || "—"}</Badge>,
          <span className="mono" style={{ fontSize: 11.5 }}>{fmtTs(r.last_seen_at)}</span>,
        ])}
      />
      {rows.length > 20 && (
        <div className="dim" style={{ fontSize: 12, marginTop: 8 }} role="status">
          Showing the first 20 of {rows.length.toLocaleString()} runtime findings — the table is
          capped so the page stays responsive; narrow the filters to see the rest.
        </div>
      )}
      {!rows.length && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>No runtime observations yet — run Realtime scanners in Operations.</div>}
    </>
  );
}
