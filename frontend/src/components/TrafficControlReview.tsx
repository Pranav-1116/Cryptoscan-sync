import { useEffect, useRef, useState } from "react";
import { tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";

const BASE = "/api/v1/traffic-control";

/** Manual, explicit API actions. Raw text preserves uint64 namespace identifiers. */
export default function TrafficControlReview() {
  const epoch = useRef(0);
  const pending = useRef<AbortController | null>(null);
  const [generation, setGeneration] = useState(0);
  const [result, setResult] = useState("");
  const [download, setDownload] = useState(false);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const clear = () => { epoch.current++; pending.current?.abort(); setResult(""); setDownload(false); setBusy(false); setGeneration((n) => n + 1); };
    const unsubscribe = watchPrivateScope(clear);
    return () => { unsubscribe(); epoch.current++; pending.current?.abort(); };
  }, []);

  return <section className="panel" aria-label="Linux traffic preflight and isolated validation" style={{ padding: 20, margin: "16px 0" }}>
    <h2>Linux traffic control: preflight &amp; isolated validation</h2>
    <p>No real-host apply. Existing policies are preserved. Management routes cover declared IPs only, not complete management safety. A distinct assigned human reviews namespace-only validation.</p>
    <ol><li>Use a fresh measured traffic proposal from Traffic &amp; storage.</li><li>Register a preflight request with canonical management IPs. Save its specification and run the read-only operator CLI.</li><li>Import the original preflight JSON and inspect retained blockers.</li><li>Propose isolated validation, then have the assigned separate reviewer approve. Download the namespace-only packet.</li><li>Run the local isolated-drill CLI. A missing kernel qdisc is a blocked result; no sudo or host fallback. Results remain local artifacts, not an API-certified production change.</li></ol>
    <form key={generation} onSubmit={async (event) => {
      event.preventDefault(); const f = new FormData(event.currentTarget);
      const action = String(f.get("action")); const id = String(f.get("id")).trim();
      if (!/^[0-9a-f-]{36}$/.test(id)) { setDownload(false); setResult("An exact retained record UUID is required."); return; }
      const controller = new AbortController(); pending.current?.abort(); pending.current = controller;
      const current = ++epoch.current; setBusy(true); setResult(""); setDownload(false);
      const hash = String(f.get("hash")).trim(); const reason = String(f.get("reason"));
      let path = ""; let body: string | undefined;
      try {
        if (action === "request") { path = `/proposals/${id}/preflight-requests`; body = JSON.stringify({ expected_proposal_record_sha256: hash, management_ips: String(f.get("ips")).split(",").map((s) => s.trim()).filter(Boolean) }); }
        else if (action === "spec") path = `/preflight-requests/${id}/specification`;
        else if (action === "import") { path = `/preflight-requests/${id}/captures`; const raw = String(f.get("capture")); if (new TextEncoder().encode(raw).length > 65536) throw new Error("Preflight exceeds 64 KiB"); body = `{"capture":${raw},"expected_preflight_sha256":${JSON.stringify(hash)}}`; }
        else if (action === "inspect") path = `/preflights/${id}`;
        else if (action === "propose") { path = "/validations"; body = JSON.stringify({ preflight_id: id, expected_preflight_record_sha256: hash, reviewer_user_id: f.get("reviewer"), duration_seconds: Number(f.get("duration")), reason }); }
        else if (action === "approve") { path = `/validations/${id}/approve`; body = JSON.stringify({ expected_revision: 1, evidence_ref: f.get("evidence"), reason }); }
        else if (action === "history") path = `/validations/${id}`;
        else if (action === "packet") path = `/validations/${id}/authorization`;
        else throw new Error("Unsupported operation");
        const response = await tenantFetch(BASE + path, { method: body === undefined ? "GET" : "POST", body, signal: controller.signal, headers: { "Content-Type": "application/json" } });
        const raw = await response.text();
        if (current !== epoch.current) return;
        setResult(response.ok ? raw : `Refused (${response.status}): ${raw}`);
        setDownload(response.ok && (action === "spec" || action === "packet"));
      } catch (error) { if (current === epoch.current) { setResult(error instanceof Error ? error.message : "Request failed"); setDownload(false); } }
      finally { if (current === epoch.current) { setBusy(false); pending.current = null; } }
    }}>
      <label>Operation <select name="action"><option value="request">1. Register preflight request</option><option value="spec">2. Download specification</option><option value="import">3. Import preflight</option><option value="inspect">4. Inspect preflight blockers</option><option value="propose">5. Propose isolated validation</option><option value="history">Inspect validation history</option><option value="approve">6. Assigned reviewer approval</option><option value="packet">7. Download namespace-only packet</option></select></label><br />
      <label>Record UUID for selected operation <input name="id" required maxLength={36} /></label><br />
      <label>Expected proposal/preflight record hash, or capture canonical hash <input name="hash" maxLength={64} /></label><br />
      <label>Declared management IPs (comma-separated) <input name="ips" maxLength={400} /></label><br />
      <label>Assigned reviewer user UUID <input name="reviewer" maxLength={36} /></label>{" "}
      <label>Drill seconds <input name="duration" type="number" min={1} max={5} defaultValue={1} /></label><br />
      <label>Review evidence reference <input name="evidence" maxLength={120} /></label><br />
      <label>Proposal/review reason <input name="reason" maxLength={500} /></label><br />
      <label>Original preflight JSON (never parsed/re-encoded by this page) <textarea name="capture" rows={5} maxLength={65536} /></label><br />
      <button disabled={busy} type="submit">{busy ? "Working…" : "Run selected step"}</button>
    </form>
    <p>CLI: <code>python scripts/traffic_control.py preflight</code> or <code>isolated-drill --acknowledge-disposable-namespace-only</code>; see Guide 87 for required file/hash arguments. No credentials or private keys needed.</p>
    {download && <button type="button" onClick={() => { const url = URL.createObjectURL(new Blob([result], { type: "application/json" })); const a = document.createElement("a"); a.href = url; a.download = "traffic-control-packet.json"; a.click(); URL.revokeObjectURL(url); }}>Save original JSON</button>}
    <pre role="status" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 400, overflow: "auto" }}>{result}</pre>
  </section>;
}
