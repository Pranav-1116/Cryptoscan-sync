import { useEffect, useRef, useState } from "react";
import { tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";
import { IconNetwork, IconHardware, IconHealth, IconCloud } from "./icons";

type Plan = { subject_id: string; revision: number; payload: { state: string; scope: { host_label: string } } };
type Summary = { capture_id: string; host_label: string; finished_at: string };
type Reading = { interface: string; status: string; rx_mbps: number | null; tx_mbps: number | null; delta: Record<string, number> | null };
type Disk = { path: string; status: string; total_bytes: number | null; used_bytes: number | null; available_bytes: number | null; used_percent: number | null; filesystem_device: string | null };
type Capture = { subject_id: string; payload: { capture: { finished_at: string; network_namespace_inode: number; mount_namespace_inode: number; authorization: { scope: { host_label: string } } }; report: { sample_seconds: number; network: Reading[]; storage: Disk[] } } };
const BASE = "/api/v1/resource-monitoring";
const number = (value: number | null | undefined, digits = 3) => typeof value === "number" && Number.isFinite(value) ? value.toFixed(digits) : "Unknown";
const gib = (value: number | null) => value === null ? "Unknown" : `${number(value / 2 ** 30, 2)} GiB`;

/** Imported, time-bounded observations. No background target access or enforcement. */
export default function ResourceMonitoring() {
  const epoch = useRef(0);
  const controllers = useRef(new Set<AbortController>());
  const [generation, setGeneration] = useState(0);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [plan, setPlan] = useState<Plan | null>(null);
  const [captures, setCaptures] = useState<Summary[]>([]);
  const [capture, setCapture] = useState<Capture | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [clock, setClock] = useState(Date.now());
  const [activeStep, setActiveStep] = useState<number>(0);
  useEffect(() => { const timer = window.setInterval(() => setClock(Date.now()), 15000); return () => window.clearInterval(timer); }, []);
  useEffect(() => {
    const invalidate = () => {
      epoch.current += 1;
      controllers.current.forEach((c) => c.abort()); controllers.current.clear();
      setPlans([]); setPlan(null); setCaptures([]); setCapture(null); setMessage(""); setBusy(false);
      setGeneration((n) => n + 1);
    };
    const unsubscribe = watchPrivateScope(invalidate);
    return () => { unsubscribe(); epoch.current += 1; controllers.current.forEach((c) => c.abort()); };
  }, []);

  async function run(action: (request: (path: string, init?: RequestInit) => Promise<any>) => Promise<void>) {
    const current = epoch.current;
    setBusy(true); setMessage("");
    const controller = new AbortController(); controllers.current.add(controller);
    const request = async (path: string, init: RequestInit = {}) => {
      if (current !== epoch.current) throw new Error("Private scope changed");
      const response = await tenantFetch(BASE + path, { ...init, signal: controller.signal, headers: { "Content-Type": "application/json" } });
      const body = await response.json();
      if (current !== epoch.current) throw new Error("Private scope changed");
      if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `Request refused (${response.status})`);
      return body;
    };
    try { await action(request); }
    catch (error) { if (current === epoch.current) { setCapture(null); setMessage(error instanceof Error ? error.message : "Request failed"); } }
    finally { controllers.current.delete(controller); if (current === epoch.current) setBusy(false); }
  }
  const payload = capture?.payload;
  const measuredAt = payload ? Date.parse(payload.capture.finished_at) : NaN;
  const stale = !Number.isFinite(measuredAt) || clock - measuredAt > 300000 || measuredAt > clock + 1000;

  // visual helpers
  const maxRx = Math.max(1, ...((payload?.report.network ?? []).map(n => n.rx_mbps ?? 0)));
  const maxTx = Math.max(1, ...((payload?.report.network ?? []).map(n => n.tx_mbps ?? 0)));
  const hasCapture = !!payload;

  return <section className="panel" aria-label="Traffic and storage monitoring" style={{ margin: "16px 0", padding: 0, overflow: "hidden" }}>
    {/* ── header: visual, not theory dump ── */}
    <div style={{ padding: "18px 20px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
      <div style={{ display: "flex", gap: 14, alignItems: "center", minWidth: 0 }}>
        <span className="brandmark" style={{ width: 38, height: 38, display: "grid", placeItems: "center" }}><IconNetwork size={18} /></span>
        <div style={{ minWidth: 0 }}>
          <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, letterSpacing: "-0.01em" }}>Traffic & storage</h2>
          <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 2, lineHeight: 1.4, maxWidth: 640 }}>Imported Linux interface counters & filesystem capacity — read-only samples, not continuous live monitoring.</div>
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>Read-only Linux interface totals and path-filesystem capacity. Imported samples, not continuous live monitoring. No packet contents, per-app attribution or traffic enforcement.</div>
        </div>
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexShrink: 0 }}>
        <span className="badge" style={{ background: "var(--panel)", borderColor: "var(--line)" }}><span className="dot" style={{ background: hasCapture ? "var(--green)" : "var(--slate)" }} /> {hasCapture ? "SAMPLE LOADED" : "NO SAMPLE"}</span>
        <button className="btn sm" type="button" disabled={busy} onClick={() => void run(async (request) => {
          const p = await request("/plans"); const c = await request("/captures"); setPlans(p.items); setCaptures(c.items);
          setCapture(null); setMessage("Loaded retained scopes and samples. Lists show the first 10 IDs; use API cursors for older records.");
        })}>Refresh scopes and samples</button>
      </div>
    </div>

    {/* ── KPI strip — visual at a glance ── */}
    <div style={{ padding: "14px 16px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, borderBottom: "1px solid var(--line)" }}>
      <div className="kpi" style={{ background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}>Scopes</span>
        <b style={{ fontFamily: "var(--mono)", fontSize: 16 }}>{plans.length}</b>
      </div>
      <div className="kpi" style={{ background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}>Samples</span>
        <b style={{ fontFamily: "var(--mono)", fontSize: 16 }}>{captures.length}</b>
      </div>
      <div className="kpi" style={{ background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}>Interfaces</span>
        <b style={{ fontFamily: "var(--mono)", fontSize: 16 }}>{payload ? payload.report.network.length : "—"}</b>
      </div>
      <div className="kpi" style={{ background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "10px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 10, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)" }}>Filesystems</span>
        <b style={{ fontFamily: "var(--mono)", fontSize: 16 }}>{payload ? payload.report.storage.length : "—"}</b>
      </div>
    </div>

    {/* ── visual 3-step workflow ── */}
    <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--line)" }}>
      <div className="stepper" style={{ margin: 0 }}>
        {[
          { n: 1, t: "Register scope", d: "Interfaces + paths", icon: IconCloud },
          { n: 2, t: "Approve & authorize", d: "Reviewer approval", icon: IconHardware },
          { n: 3, t: "Import capture", d: "CLI → verify", icon: IconNetwork },
        ].map((s) => {
          const state = activeStep === s.n - 1 ? "state-active" : activeStep > s.n - 1 ? "state-done" : "";
          const Ico = s.icon;
          return <div key={s.n} className={`step ${state}`} style={{ cursor: "pointer" }} onClick={() => setActiveStep(s.n - 1)} role="button" tabIndex={0} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setActiveStep(s.n - 1)} aria-label={`Step ${s.n}: ${s.t}`}>
            <div className="node">{s.n}</div>
            <div className="stitle">{s.t}</div>
            <div className="ssub">{s.d}</div>
          </div>;
        })}
      </div>
    </div>

    {/* ── step content — professional card forms ── */}
    <div key={generation} style={{ padding: 16 }}>
      {activeStep === 0 && <div className="panel" style={{ background: "var(--panel-2)", border: "1px solid var(--line)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <b style={{ fontSize: 13 }}>1. Register an explicit collection scope</b>
          <span className="badge slate">30-min window · no collection yet</span>
        </div>
        <form onSubmit={(event) => {
          event.preventDefault(); const f = new FormData(event.currentTarget);
          void run(async (request) => {
            const now = Date.now();
            const row = await request("/plans", { method: "POST", body: JSON.stringify({ system_id: f.get("system"), environment: f.get("environment"), host_label: f.get("host"),
              interfaces: String(f.get("interfaces")).split(",").map((s) => s.trim()).filter(Boolean),
              mount_paths: String(f.get("paths")).split("\n").map((s) => s.trim()).filter(Boolean), interval_seconds: Number(f.get("interval")),
              not_before: new Date(now - 1000).toISOString(), expires_at: new Date(now + 1800000).toISOString() }) });
            setPlan(row); setPlans((old) => [row, ...old.filter((p) => p.subject_id !== row.subject_id)]); setMessage("Draft scope registered. Approval required; no collection has run.");
          });
        }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Existing system ID <input className="inp" name="system" required maxLength={120} placeholder="sys-..." /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Environment <input className="inp" name="environment" required maxLength={120} placeholder="prod / staging" /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Operator host label <input className="inp" name="host" required maxLength={120} placeholder="host-01" /></label>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 10, marginTop: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Exact interfaces, comma-separated <input className="inp" name="interfaces" required placeholder="eth0,lo" /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Sample interval (seconds) <input className="inp" name="interval" type="number" min={1} max={30} defaultValue={5} required style={{ width: 120 }} /></label>
          </div>
          <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5, marginTop: 10 }}>Absolute directory paths, one per line <textarea className="inp" name="paths" defaultValue={"/"} required rows={3} style={{ fontFamily: "var(--mono)", fontSize: 12 }} /></label>
          <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
            <button className="btn primary" disabled={busy}>Register scope (30-minute window)</button>
            <button type="button" className="btn" onClick={() => setActiveStep(1)}>Next → Approve</button>
          </div>
        </form>
      </div>}

      {activeStep === 1 && <div className="panel" style={{ background: "var(--panel-2)", border: "1px solid var(--line)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <b style={{ fontSize: 13 }}>2. Approve scope and download operator authorization</b>
          <span className="badge amber">Requires reviewer</span>
        </div>
        <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5, marginBottom: 10 }}>Scope <select className="inp" value={plan?.subject_id ?? ""} onChange={(event) => setPlan(plans.find((p) => p.subject_id === event.target.value) ?? null)}>
          <option value="">Select scope</option>{plans.map((p) => <option key={p.subject_id} value={p.subject_id}>{p.payload.scope.host_label} — {p.payload.state} — {p.subject_id}</option>)}
        </select></label>
        {plan && <><div style={{ padding: "8px 10px", background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12, fontFamily: "var(--mono)", marginBottom: 10 }}>Scope ID: <code>{plan.subject_id}</code> · {plan.payload.state}</div>
          <form onSubmit={(event) => {
            event.preventDefault(); const f = new FormData(event.currentTarget); const selected = plan;
            void run(async (request) => {
              const row = await request(`/plans/${encodeURIComponent(selected.subject_id)}/approve`, { method: "POST", body: JSON.stringify({ expected_revision: selected.revision, evidence_ref: f.get("reference"), reason: f.get("reason") }) });
              setPlan(row); setPlans((old) => old.map((p) => p.subject_id === row.subject_id ? row : p)); setMessage("Scope approved. Download it and run the CLI on the intended Linux host as an ordinary user.");
            });
          }}>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 10 }}>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Change reference <input className="inp" name="reference" required maxLength={120} /></label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Approval reason <input className="inp" name="reason" required minLength={20} maxLength={500} placeholder="At least 20 characters" /></label>
            </div>
            <button className="btn primary" style={{ marginTop: 10 }} disabled={busy || plan.payload.state !== "DRAFT"}>Approve scope (reviewer permission required)</button>
          </form>
          <button style={{ marginTop: 10 }} className="btn" type="button" disabled={busy || plan.payload.state !== "APPROVED"} onClick={() => void run(async (request) => {
            const value = await request(`/plans/${encodeURIComponent(plan.subject_id)}/authorization`);
            const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
            try { const a = document.createElement("a"); a.href = url; a.download = `resource-scope-${plan.subject_id}.json`; a.click(); }
            finally { URL.revokeObjectURL(url); }
            setMessage(`Authorization downloaded. Approved record SHA256: ${value.plan_record_sha256}`);
          })}>Download approved scope</button>
        </>}
        <div style={{ marginTop: 12, fontSize: 11, color: "var(--faint)", padding: "8px 10px", background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>On that host: <code>python scripts/collect_resources.py collect --authorization /absolute/scope.json --approved-record-sha256 HASH --output /absolute/capture.json</code> · No sudo.</div>
        <div style={{ marginTop: 8, display: "flex", gap: 8 }}>
          <button className="btn" onClick={() => setActiveStep(0)}>← Back</button>
          <button className="btn" onClick={() => setActiveStep(2)}>Next → Import</button>
        </div>
      </div>}

      {activeStep === 2 && <div className="panel" style={{ background: "var(--panel-2)", border: "1px solid var(--line)" }}>
        <b style={{ fontSize: 13, display: "block", marginBottom: 10 }}>3. Import the operator capture</b>
        <form onSubmit={(event) => {
          event.preventDefault(); const f = new FormData(event.currentTarget); const file = f.get("file") as File;
          void run(async (request) => {
            if (!file?.size || file.size > 131072) throw new Error("Select a capture JSON file no larger than 128 KiB");
            const text = await file.text(); JSON.parse(text);
            const body = `{"capture":${text},"expected_capture_sha256":${JSON.stringify(f.get("sha"))}}`;
            const row = await request("/captures", { method: "POST", body }); setCapture(row); setMessage("Capture retained. Rates are reconstructed from counter pairs; no configuration changed.");
          });
        }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Capture JSON <input className="inp" name="file" type="file" accept="application/json,.json" required /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Capture SHA256 from CLI <input className="inp" name="sha" required pattern="[0-9a-f]{64}" maxLength={64} placeholder="64-hex" style={{ fontFamily: "var(--mono)" }} /></label>
          </div>
          <button className="btn primary" style={{ marginTop: 10 }} disabled={busy}>Import capture</button>
        </form>
        <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
          <button className="btn" onClick={() => setActiveStep(1)}>← Back</button>
        </div>
      </div>}

      {/* ── retained sample selector — visual ── */}
      <div style={{ marginTop: 14, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5, flex: 1, minWidth: 240 }}>Retained sample <select className="inp" value={capture?.subject_id ?? ""} disabled={busy} onChange={(event) => {
          const id = event.target.value; setCapture(null);
          if (id) void run(async (request) => setCapture(await request(`/captures/${encodeURIComponent(id)}`)));
        }}><option value="">Select a retained sample</option>{captures.map((s) => <option key={s.capture_id} value={s.capture_id}>{s.host_label} — {s.finished_at}</option>)}</select></label>
        {payload && <span className="badge green"><span className="dot" /> INSPECTING · {payload.report.network.length} ifaces</span>}
      </div>

      {payload && <div style={{ marginTop: 16 }}>
        {/* ── capture header — visual card ── */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, padding: "12px 14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 14 }}>
          <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
            <IconHealth size={18} style={{ color: stale ? "var(--amber)" : "var(--green)" }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: 14 }}>{payload.capture.authorization.scope.host_label}</div>
              <div style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{payload.capture.finished_at} · {number(payload.report.sample_seconds)}s window · ns {payload.capture.network_namespace_inode} / {payload.capture.mount_namespace_inode}</div>
            </div>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <span className={`badge ${stale ? "amber" : "green"}`}>{stale ? "STALE" : "FRESH"}</span>
            <span className="badge slate">IMPORTED · source authenticity unverified</span>
          </div>
        </div>
        {stale && <div style={{ padding: "8px 12px", background: "color-mix(in srgb, var(--amber) 10%, var(--panel))", border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 12, marginBottom: 12 }}><strong>Stale or invalid capture time: not a current reading.</strong></div>}
        <div style={{ fontSize: 11, color: "var(--faint)", marginBottom: 14, padding: "8px 10px", background: "var(--bg)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>Network namespace {payload.capture.network_namespace_inode}; mount namespace {payload.capture.mount_namespace_inode}. These are not whole-host/whole-network totals.</div>

        {/* ── network visual ── */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12, marginBottom: 14 }}>
          <div className="panel" style={{ background: "var(--panel-2)", padding: 14 }}>
            <div style={{ fontSize: 11, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)", marginBottom: 10, display: "flex", justifyContent: "space-between" }}><span>Interface throughput</span><span style={{ color: "var(--dim)", textTransform: "none", letterSpacing: 0 }}>decimal Mbps · avg in window</span></div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {payload.report.network.map((n) => (
                <div key={n.interface} style={{ display: "grid", gridTemplateColumns: "72px 1fr 64px", gap: 10, alignItems: "center" }}>
                  <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600 }}>{n.interface}</span>
                  <div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 11 }}>
                      <span style={{ color: "var(--cyan)", minWidth: 22 }}>↓</span><div className="bar" style={{ flex: 1, height: 6 }}><i style={{ width: `${Math.min(100, (n.rx_mbps ?? 0) / maxRx * 100)}%`, background: "var(--cyan)" }} /></div><span style={{ fontFamily: "var(--mono)", fontSize: 11, minWidth: 48, textAlign: "right" }}>{number(n.rx_mbps)}</span>
                    </div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 11, marginTop: 4 }}>
                      <span style={{ color: "var(--violet)", minWidth: 22 }}>↑</span><div className="bar" style={{ flex: 1, height: 6 }}><i style={{ width: `${Math.min(100, (n.tx_mbps ?? 0) / maxTx * 100)}%`, background: "var(--violet)" }} /></div><span style={{ fontFamily: "var(--mono)", fontSize: 11, minWidth: 48, textAlign: "right" }}>{number(n.tx_mbps)}</span>
                    </div>
                  </div>
                  <span className={`badge ${n.status === "MEASURED" ? "green" : "amber"}`} style={{ justifySelf: "end" }}>{n.status}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="panel" style={{ background: "var(--panel-2)", padding: 14 }}>
            <div style={{ fontSize: 11, letterSpacing: ".08em", textTransform: "uppercase", color: "var(--faint)", fontFamily: "var(--mono)", marginBottom: 10 }}>Filesystem capacity</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {payload.report.storage.map((s) => (
                <div key={s.path} style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 8, alignItems: "center" }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontFamily: "var(--mono)", fontSize: 12, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.path}</span>
                      <span style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{s.filesystem_device ?? "Unknown"}</span>
                    </div>
                    <div className="bar thick" style={{ marginTop: 6 }}><i style={{ width: `${s.used_percent ?? 0}%`, background: (s.used_percent ?? 0) > 80 ? "var(--red)" : (s.used_percent ?? 0) > 60 ? "var(--amber)" : "var(--green)" }} /></div>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--faint)", marginTop: 4 }}>
                      <span>{gib(s.used_bytes)} used of {gib(s.total_bytes)}</span><span>{s.used_percent !== null ? `${number(s.used_percent, 1)}%` : "Unknown"} · {s.status}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── detailed tables (kept for audit, now secondary) ── */}
        <details style={{ marginBottom: 10 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--dim)", fontFamily: "var(--mono)" }}>Detailed interface table</summary>
          <div style={{ overflowX: "auto", marginTop: 8 }}><table className="tbl"><thead><tr><th>Interface</th><th>Status</th><th>Receive Mbps</th><th>Transmit Mbps</th><th>RX/TX packets in window</th><th>RX/TX drops in window</th><th>RX/TX errors in window</th></tr></thead>
            <tbody>{payload.report.network.map((n) => <tr key={n.interface}><td>{n.interface}</td><td>{n.status}</td><td>{number(n.rx_mbps)}</td><td>{number(n.tx_mbps)}</td><td>{n.delta ? `${n.delta.rx_packets} / ${n.delta.tx_packets}` : "Unknown"}</td><td>{n.delta ? `${n.delta.rx_dropped} / ${n.delta.tx_dropped}` : "Unknown"}</td><td>{n.delta ? `${n.delta.rx_errors} / ${n.delta.tx_errors}` : "Unknown"}</td></tr>)}</tbody></table></div>
        </details>
        <details style={{ marginBottom: 10 }}>
          <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--dim)", fontFamily: "var(--mono)" }}>Detailed filesystem table</summary>
          <div style={{ overflowX: "auto", marginTop: 8 }}><table className="tbl"><thead><tr><th>Path</th><th>Status</th><th>Total</th><th>Used</th><th>Available to collector</th><th>Used %</th><th>Filesystem device</th></tr></thead>
            <tbody>{payload.report.storage.map((s) => <tr key={s.path}><td>{s.path}</td><td>{s.status}</td><td>{gib(s.total_bytes)}</td><td>{gib(s.used_bytes)}</td><td>{gib(s.available_bytes)}</td><td>{number(s.used_percent, 1)}</td><td>{s.filesystem_device ?? "Unknown"}</td></tr>)}</tbody></table></div>
        </details>
        <div style={{ fontSize: 11, color: "var(--faint)", padding: "8px 10px", background: "color-mix(in srgb, var(--amber) 6%, var(--panel))", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 12 }}>Do not add these rows: multiple paths can refer to the same filesystem. Free space is not all available to this user; physical disks, RAID/SAN and quotas are not discovered. Counter errors/drops do not prove end-to-end packet loss.</div>

        {/* ── draft limit — visual card ── */}
        <div className="panel" style={{ background: "var(--panel-2)", borderTop: "2px solid var(--amber)", padding: 14 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
            <b style={{ fontSize: 13 }}>Draft a traffic limit — not enforcement</b>
            <span className="badge amber">DRAFT ONLY</span>
          </div>
          <div style={{ fontSize: 11, color: "var(--dim)", marginBottom: 10 }}>Proposes a value for review. No enforcement adapter is called from this console.</div>
          <form onSubmit={(event) => {
            event.preventDefault(); const f = new FormData(event.currentTarget);
            void run(async (request) => {
              const row = await request("/traffic-proposals", { method: "POST", body: JSON.stringify({ capture_id: capture!.subject_id, interface: f.get("interface"), egress_limit_mbps: Number(f.get("limit")), reason: f.get("reason") }) });
              setMessage(`Draft ${row.subject_id}: ${row.payload.state}. NOT APPLIED; no enforcement adapter, management-path safety or rollback verification.`);
            });
          }}>
            <div style={{ display: "grid", gridTemplateColumns: "160px 140px 1fr", gap: 10 }}>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Interface <select className="inp" name="interface" required>{payload.report.network.filter((n) => n.status === "MEASURED").map((n) => <option key={n.interface}>{n.interface}</option>)}</select></label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Egress limit (Mbps) <input className="inp" name="limit" type="number" min={1} max={100000} required /></label>
              <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Change reason <input className="inp" name="reason" minLength={20} maxLength={500} required placeholder="At least 20 characters" /></label>
            </div>
            <button style={{ marginTop: 10 }} className="btn primary" disabled={busy || stale || !payload.report.network.some((n) => n.status === "MEASURED")}>Save draft limit (not apply)</button>
          </form>
        </div>
      </div>}
    </div>
    {message && <div style={{ padding: "10px 16px", fontSize: 12, background: "color-mix(in srgb, var(--cyan) 8%, var(--panel))", borderTop: "1px solid var(--line)", color: "var(--dim)" }} role="status">{message}</div>}
  </section>;
}
