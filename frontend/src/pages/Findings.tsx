import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table, PageHead, Kpi, Code, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { RequireRole } from "../lib/auth.js";
import {
  apiFindings,
  apiFindingDetail,
  apiTriggerScan,
  apiRuntimeFindings,
  Finding,
  RuntimeFindingsResponse,
  RuntimeFindingRow,
} from "../lib/api.js";

/* Every finding in the platform is an evidence-chain record: a deterministic
   observation (algorithm/key/mode/padding) locked to a source file/line, a
   content hash and a chain hash. Nothing is simulated — the list and the
   detail all come from GET /api/v1/findings (and /findings/{evidence_id}). */

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

export default function Findings() {
  const [algorithm, setAlgorithm] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<number>(-1);
  const [detail, setDetail] = useState<Finding | null>(null);
  const [detailLive, setDetailLive] = useState(false);
  const [detailErr, setDetailErr] = useState<string | null>(null);

  const list = usePollingApi(
    () => apiFindings({ page, page_size: 50, algorithm: algorithm || undefined, compliance_status: status || undefined }),
    15000,
    [page, algorithm, status],
  );
  // Live runtime observations from the 24/7 engine (separate from evidence
  // records — the always-on scanners that do not require a scan job).
  const runtime = usePollingApi(() => apiRuntimeFindings(50), 8000, []);
  useRealtimeRefresh(list.run, runtime.run);
  // Run-a-scan CTA: kick off a real universal source scan, then refresh.
  const [repoUrl, setRepoUrl] = useState("");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanMsg, setScanMsg] = useState<{ ok: boolean; text: string } | null>(null);

  // Kick off a real universal source scan (worker pipeline → evidence records).
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

  // Refresh the detail drawer when a new row is selected.
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

  // Distinct compliance_status values present so the filter is data-driven.
  const statusOptions = useMemo(() => {
    const seen = new Set<string>();
    for (const f of findings) if (f.compliance_status) seen.add(f.compliance_status);
    return Array.from(seen).sort();
  }, [findings]);

  // Distinct algorithms present for quick chips (data-driven, no hardcoding).
  const algos = useMemo(() => {
    const seen = new Set<string>();
    for (const f of findings) if (f.algorithm) seen.add(f.algorithm);
    return Array.from(seen).sort();
  }, [findings]);

  const hardcoded = findings.filter((f) => f.is_hardcoded_key).length;
  const nonCompliant = findings.filter((f) =>
    ["NON_COMPLIANT", "FAIL", "HIGH", "CRITICAL"].includes(String(f.compliance_status || "").toUpperCase())).length;
  const compl = findings.filter((f) =>
    ["COMPLIANT", "PASS"].includes(String(f.compliance_status || "").toUpperCase())).length;

  useEffect(() => { setSelected(-1); setDetail(null); setPage(1); }, [algorithm, status]);

  return (
    <>
      <PageHead
        crumb="intelligence / findings"
        title="Findings"
        sub="Deterministic evidence-chain observations — every finding carries source, confidence, content hash and chain hash"
        right={
          <>
            <LiveBadge source={live ? "live" : "offline"} label={live ? "EVIDENCE CHAIN" : "BACKEND OFFLINE"} />
            <Badge tone={live ? "cyan" : ""}><span className="dot" /> {total.toLocaleString()} FINDINGS</Badge>
          </>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Kpi k="total findings" v={total.toLocaleString()} tone="cyan" />
        <Kpi k="in this view" v={findings.length.toLocaleString()} />
        <Kpi k="non-compliant" v={nonCompliant} tone={nonCompliant ? "red" : "green"} />
        <Kpi k="hardcoded keys" v={hardcoded} tone={hardcoded ? "amber" : "green"} />
      </div>

      <Panel title="Filter" sub="findings are grouped by algorithm / policy status" className="mt">
        <div className="row" style={{ gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "1 1 220px" }}>
            <span className="dim" style={{ fontSize: 11.5 }}>Algorithm</span>
            <input
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
              placeholder="e.g. RSA, AES, MD5"
              style={{ width: "100%", padding: "8px 10px" }}
            />
          </label>
          <label className="field" style={{ flex: "1 1 180px" }}>
            <span className="dim" style={{ fontSize: 11.5 }}>Status</span>
            <select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: "100%", padding: "8px 10px" }}>
              <option value="">All</option>
              {statusOptions.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          {algos.length > 0 && (
            <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
              {algos.slice(0, 8).map((a) => (
                <button
                  key={a}
                  className={`btn sm ${algorithm === a ? "primary" : ""}`}
                  onClick={() => setAlgorithm(algorithm === a ? "" : a)}
                >{a}</button>
              ))}
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Run a universal source scan" sub="POST /api/v1/scans/trigger — evidence-chain findings populate from the scan" className="mt">
        <div className="row" style={{ gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <label className="field" style={{ flex: "1 1 320px" }}>
            <span className="dim" style={{ fontSize: 11.5 }}>Repository URL (git / https / local path)</span>
            <input
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/your-org/app or /path/to/repo"
              style={{ width: "100%", padding: "9px 11px" }}
            />
          </label>
          <RequireRole
            anyOf={["superadmin", "ciso", "security_analyst", "developer", "scanner"]}
            fallback={<span className="dim" style={{ fontSize: 12 }}>Your role is read-only for scan submission.</span>}
          >
            <button className="btn primary" onClick={() => void runScan()} disabled={scanBusy || !repoUrl.trim()}>
              {scanBusy ? "Queuing…" : "▶ Run scan"}
            </button>
          </RequireRole>
        </div>
        {scanMsg && (
          <div className={`auth-alert ${scanMsg.ok ? "ok" : "err"}`} style={{ marginTop: 10 }}>
            {scanMsg.ok ? "✓ " : "✕ "}{scanMsg.text}
          </div>
        )}
        <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          Scan submission follows the server-side scan.trigger permission matrix. Findings land as the worker pipeline persists evidence — the list refreshes automatically.
        </div>
      </Panel>

      <Panel title="Evidence findings" sub={live ? "GET /api/v1/findings — click a row for the full finding record" : "backend offline — run a scan to populate findings"} className="mt">
        <Table
          clickable
          selected={selected}
          onSelect={select}
          head={["finding id", "algorithm", "key", "status", "confidence", "location"]}
          rows={findings.map((f) => [
            <span className="mono" style={{ fontWeight: 600 }}>{f.evidence_id.slice(0, 10)}…</span>,
            <Badge tone="violet">{f.algorithm}</Badge>,
            <span className="num">{f.key_size ?? "—"}{f.mode ? ` · ${f.mode}` : ""}</span>,
            statusBadge(f.compliance_status),
            confidenceBadge(f.confidence),
            <span className="dim" style={{ fontSize: 12 }}>
              {f.file_path || "—"}{f.line_number ? `:${f.line_number}` : ""}
            </span>,
          ])}
        />
        {!findings.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live ? "No findings match this filter." : "Backend offline — no findings yet."}
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
          ? "GET /api/v1/scans/runtime-findings — the 24/7 engine (weak TLS / risky libraries)"
          : "GET /api/v1/scans/runtime-findings — always-on scanners"}
        className="mt"
      >
        <RuntimeFeed data={runtime.data as RuntimeFindingsResponse | null} live={runtime.source === "live"} />
      </Panel>

      {selected >= 0 && (
        <Drawer
          title={`Finding ${detail?.evidence_id ?? findings[selected]?.evidence_id ?? ""}`}
          sub={detailLive ? "GET /api/v1/findings/{evidence_id} — live evidence record" : detail ? "evidence record" : "loading…"}
          onClose={() => { setSelected(-1); setDetail(null); }}
        >
          {detailErr && <div className="auth-alert err">✕ {detailErr}</div>}
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
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="kpi-strip">
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
        <Panel title="Evidence chain" sub="tamper-evident hashes (you can verify these) ">
          <div className="mono-list">
            <Row k="content hash" v={<span className="mono">{f.content_hash}</span>} />
            <Row k="chain hash" v={<span className="mono">{f.chain_hash}</span>} />
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

      <Panel title="Recommendation & verification" sub="next actions after this finding">
        <div className="mono-list">
          <Row k="Recommended" v="Review the source location; confirm the algorithm/key against catalog policy" />
          <Row k="Verify" v="Cross-check content_hash / chain_hash in /api/v1/auth/audit/verify" />
          <Row k="Remediation" v="Rotate or re-key per the algorithm's policy verdict (see Policy evaluation)" />
        </div>
      </Panel>
    </div>
  );
}

/* Small local helpers so the drawer stays readable. */
function Mini({ label, v, badge }: { label: string; v: React.ReactNode; badge?: string }) {
  return (
    <div className="kpi">
      <span className="k">{label}</span>
      <span className="v">{badge ? <Badge tone={badge}>{v}</Badge> : v}</span>
    </div>
  );
}
function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="spread" style={{ fontSize: 13, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="dim">{k}</span>
      <span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}

/* Render an evidence-chain timestamp (ISO string from the API) or "—". */
function fmtTs(ts?: string | null): React.ReactNode {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return <span className="mono">{ts}</span>;
  return <span className="mono">{d.toLocaleString()}</span>;
}

/* Live runtime observations (24/7 engine) — summary + recent rows. */
function RuntimeFeed({ data, live }: { data: RuntimeFindingsResponse | null; live: boolean }) {
  if (!data) {
    return <div className="dim" style={{ fontSize: 13 }}>{live ? "No runtime observations yet." : "Backend offline — runtime findings unavailable."}</div>;
  }
  const rows = data.findings ?? [];
  const summary = data.summary ?? {};
  const weak = rows.filter((r) => r.weak_tls).length;
  return (
    <>
      <div className="grid cols-4" style={{ marginBottom: 14 }}>
        <Kpi k="runtime findings" v={data.total_count.toLocaleString()} tone="cyan" />
        <Kpi k="weak TLS" v={weak} tone={weak ? "red" : "green"} />
        <Kpi k="hosts" v={String(summary.hosts ?? "—")} />
        <Kpi k="scanners" v={String(summary.scanner_ids ?? "—")} />
      </div>
      <Table
        head={["algorithm / suite", "host · process", "tls", "status", "quantum", "last seen"]}
        rows={rows.slice(0, 20).map((r: RuntimeFindingRow) => [
          <span className="mono" style={{ fontWeight: 600 }}>{r.algorithm || r.cipher_suite || "—"}</span>,
          <span className="dim" style={{ fontSize: 12 }}>{r.hostname || "—"} · {r.process_name || "—"}</span>,
          <Badge tone={r.weak_tls ? "red" : ""}>{r.tls_version || "—"}</Badge>,
          <Badge tone={String(r.status || "").toLowerCase().includes("disallow") || String(r.status || "").toLowerCase().includes("deprecat") ? "red" : ""}>{r.status || "—"}</Badge>,
          <Badge tone={r.quantum_impact === "shor" ? "red" : r.quantum_impact ? "amber" : ""}>{r.quantum_impact || "—"}</Badge>,
          <span className="mono" style={{ fontSize: 11.5 }}>{fmtTs(r.last_seen_at)}</span>,
        ])}
      />
      {!rows.length && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>No runtime observations yet — run Realtime scanners in Operations.</div>}
    </>
  );
}


