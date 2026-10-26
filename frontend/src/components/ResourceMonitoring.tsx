import { useEffect, useRef, useState } from "react";
import { tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";

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

  return <section className="panel" aria-label="Traffic and storage monitoring" style={{ margin: "16px 0", padding: 20 }}>
    <h2>Traffic &amp; storage</h2>
    <p>Read-only Linux interface totals and path-filesystem capacity. Imported samples, not continuous live monitoring. No packet contents, per-app attribution or traffic enforcement.</p>
    <button type="button" disabled={busy} onClick={() => void run(async (request) => {
      const p = await request("/plans"); const c = await request("/captures"); setPlans(p.items); setCaptures(c.items);
      setCapture(null); setMessage("Loaded retained scopes and samples. Lists show the first 10 IDs; use API cursors for older records.");
    })}>Refresh scopes and samples</button>
    <div key={generation}>
      <details><summary>1. Register an explicit collection scope</summary>
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
          <label>Existing system ID <input name="system" required maxLength={120} /></label>{" "}
          <label>Environment <input name="environment" required maxLength={120} /></label>{" "}
          <label>Operator host label <input name="host" required maxLength={120} /></label><br />
          <label>Exact interfaces, comma-separated <input name="interfaces" required placeholder="eth0,lo" /></label>{" "}
          <label>Sample interval (seconds) <input name="interval" type="number" min="1" max="30" defaultValue="5" required /></label><br />
          <label>Absolute directory paths, one per line <textarea name="paths" defaultValue="/" required /></label><br />
          <button disabled={busy}>Register scope (30-minute window)</button>
        </form>
      </details>
      <details><summary>2. Approve scope and download operator authorization</summary>
        <label>Scope <select value={plan?.subject_id ?? ""} onChange={(event) => setPlan(plans.find((p) => p.subject_id === event.target.value) ?? null)}>
          <option value="">Select scope</option>{plans.map((p) => <option key={p.subject_id} value={p.subject_id}>{p.payload.scope.host_label} — {p.payload.state} — {p.subject_id}</option>)}
        </select></label>
        {plan && <><p>Scope ID: <code>{plan.subject_id}</code> · {plan.payload.state}</p>
          <form onSubmit={(event) => {
            event.preventDefault(); const f = new FormData(event.currentTarget); const selected = plan;
            void run(async (request) => {
              const row = await request(`/plans/${encodeURIComponent(selected.subject_id)}/approve`, { method: "POST", body: JSON.stringify({ expected_revision: selected.revision, evidence_ref: f.get("reference"), reason: f.get("reason") }) });
              setPlan(row); setPlans((old) => old.map((p) => p.subject_id === row.subject_id ? row : p)); setMessage("Scope approved. Download it and run the CLI on the intended Linux host as an ordinary user.");
            });
          }}>
            <label>Change reference <input name="reference" required maxLength={120} /></label>{" "}
            <label>Approval reason <input name="reason" required minLength={20} maxLength={500} /></label>{" "}
            <button disabled={busy || plan.payload.state !== "DRAFT"}>Approve scope (reviewer permission required)</button>
          </form>
          <button type="button" disabled={busy || plan.payload.state !== "APPROVED"} onClick={() => void run(async (request) => {
            const value = await request(`/plans/${encodeURIComponent(plan.subject_id)}/authorization`);
            const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
            try { const a = document.createElement("a"); a.href = url; a.download = `resource-scope-${plan.subject_id}.json`; a.click(); }
            finally { URL.revokeObjectURL(url); }
            setMessage(`Authorization downloaded. Approved record SHA256: ${value.plan_record_sha256}`);
          })}>Download approved scope</button>
        </>}
        <p>On that host: <code>python scripts/collect_resources.py collect --authorization /absolute/scope.json --approved-record-sha256 HASH --output /absolute/capture.json</code>. No sudo.</p>
      </details>
      <details><summary>3. Import the operator capture</summary>
        <form onSubmit={(event) => {
          event.preventDefault(); const f = new FormData(event.currentTarget); const file = f.get("file") as File;
          void run(async (request) => {
            if (!file?.size || file.size > 131072) throw new Error("Select a capture JSON file no larger than 128 KiB");
            const text = await file.text(); JSON.parse(text);
            // Keep original JSON numeric tokens: parsing/re-stringifying uint64 counters in JS loses precision.
            const body = `{"capture":${text},"expected_capture_sha256":${JSON.stringify(f.get("sha"))}}`;
            const row = await request("/captures", { method: "POST", body }); setCapture(row); setMessage("Capture retained. Rates are reconstructed from counter pairs; no configuration changed.");
          });
        }}>
          <label>Capture JSON <input name="file" type="file" accept="application/json,.json" required /></label>{" "}
          <label>Capture SHA256 from CLI <input name="sha" required pattern="[0-9a-f]{64}" maxLength={64} /></label>{" "}
          <button disabled={busy}>Import capture</button>
        </form>
      </details>
      <label>Retained sample <select value={capture?.subject_id ?? ""} disabled={busy} onChange={(event) => {
        const id = event.target.value; setCapture(null);
        if (id) void run(async (request) => setCapture(await request(`/captures/${encodeURIComponent(id)}`)));
      }}><option value="">Select a retained sample</option>{captures.map((s) => <option key={s.capture_id} value={s.capture_id}>{s.host_label} — {s.finished_at}</option>)}</select></label>
      {payload && <div>
        <h3>{payload.capture.authorization.scope.host_label}</h3>
        <p>Captured: {payload.capture.finished_at} · {number(payload.report.sample_seconds)} seconds · IMPORTED, source authenticity unverified. {stale && <strong>Stale or invalid capture time: not a current reading.</strong>}</p>
        <p>Network namespace {payload.capture.network_namespace_inode}; mount namespace {payload.capture.mount_namespace_inode}. These are not whole-host/whole-network totals.</p>
        <div style={{ overflowX: "auto" }}><table><caption>Average interface traffic (decimal Mbps)</caption><thead><tr><th>Interface</th><th>Status</th><th>Receive Mbps</th><th>Transmit Mbps</th><th>RX/TX packets in window</th><th>RX/TX drops in window</th><th>RX/TX errors in window</th></tr></thead>
          <tbody>{payload.report.network.map((n) => <tr key={n.interface}><td>{n.interface}</td><td>{n.status}</td><td>{number(n.rx_mbps)}</td><td>{number(n.tx_mbps)}</td><td>{n.delta ? `${n.delta.rx_packets} / ${n.delta.tx_packets}` : "Unknown"}</td><td>{n.delta ? `${n.delta.rx_dropped} / ${n.delta.tx_dropped}` : "Unknown"}</td><td>{n.delta ? `${n.delta.rx_errors} / ${n.delta.tx_errors}` : "Unknown"}</td></tr>)}</tbody></table></div>
        <div style={{ overflowX: "auto" }}><table><caption>Path-filesystem capacity (approximate GiB display)</caption><thead><tr><th>Path</th><th>Status</th><th>Total</th><th>Used</th><th>Available to collector</th><th>Used %</th><th>Filesystem device</th></tr></thead>
          <tbody>{payload.report.storage.map((s) => <tr key={s.path}><td>{s.path}</td><td>{s.status}</td><td>{gib(s.total_bytes)}</td><td>{gib(s.used_bytes)}</td><td>{gib(s.available_bytes)}</td><td>{number(s.used_percent, 1)}</td><td>{s.filesystem_device ?? "Unknown"}</td></tr>)}</tbody></table></div>
        <p>Do not add these rows: multiple paths can refer to the same filesystem. Free space is not all available to this user; physical disks, RAID/SAN and quotas are not discovered. Counter errors/drops do not prove end-to-end packet loss.</p>
        <form onSubmit={(event) => {
          event.preventDefault(); const f = new FormData(event.currentTarget);
          void run(async (request) => {
            const row = await request("/traffic-proposals", { method: "POST", body: JSON.stringify({ capture_id: capture!.subject_id, interface: f.get("interface"), egress_limit_mbps: Number(f.get("limit")), reason: f.get("reason") }) });
            setMessage(`Draft ${row.subject_id}: ${row.payload.state}. NOT APPLIED; no enforcement adapter, management-path safety or rollback verification.`);
          });
        }}>
          <h3>4. Draft a traffic limit — not enforcement</h3>
          <label>Interface <select name="interface" required>{payload.report.network.filter((n) => n.status === "MEASURED").map((n) => <option key={n.interface}>{n.interface}</option>)}</select></label>{" "}
          <label>Egress limit (Mbps) <input name="limit" type="number" min="1" max="100000" required /></label>{" "}
          <label>Change reason <input name="reason" minLength={20} maxLength={500} required /></label>{" "}
          <button disabled={busy || stale || !payload.report.network.some((n) => n.status === "MEASURED")}>Save draft limit (not apply)</button>
        </form>
      </div>}
    </div>
    {message && <p role="status">{message}</p>}
  </section>;
}
