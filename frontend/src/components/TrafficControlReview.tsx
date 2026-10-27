import { useEffect, useRef, useState } from "react";
import { tenantFetch } from "../lib/api";
import { watchPrivateScope } from "../lib/privateScope";
import { IconSatellite, IconSecurity, IconTarget, IconNetwork } from "./icons";

const BASE = "/api/v1/traffic-control";

const STEPS: Array<{ key: string; n: number; title: string; desc: string }> = [
  { key: "request", n: 1, title: "Register preflight request", desc: "Canonical management IPs" },
  { key: "spec", n: 2, title: "Download specification", desc: "Read-only operator CLI" },
  { key: "import", n: 3, title: "Import preflight", desc: "Preserve uint64 inodes" },
  { key: "inspect", n: 4, title: "Inspect blockers", desc: "Retained validation" },
  { key: "propose", n: 5, title: "Propose validation", desc: "Assign reviewer" },
  { key: "approve", n: 6, title: "Reviewer approval", desc: "Separate human" },
  { key: "packet", n: 7, title: "Namespace packet", desc: "Disposable drill" },
];

function stepFor(action: string) {
  const idx = STEPS.findIndex(s => s.key === action);
  return idx >= 0 ? idx : 0;
}

/** Manual, explicit API actions. Raw text preserves uint64 namespace identifiers. */
export default function TrafficControlReview() {
  const epoch = useRef(0);
  const pending = useRef<AbortController | null>(null);
  const [generation, setGeneration] = useState(0);
  const [result, setResult] = useState("");
  const [download, setDownload] = useState(false);
  const [busy, setBusy] = useState(false);
  const [action, setAction] = useState("request");
  useEffect(() => {
    const clear = () => { epoch.current++; pending.current?.abort(); setResult(""); setDownload(false); setBusy(false); setGeneration((n) => n + 1); };
    const unsubscribe = watchPrivateScope(clear);
    return () => { unsubscribe(); epoch.current++; pending.current?.abort(); };
  }, []);

  const activeIdx = stepFor(action);

  return <section className="panel" aria-label="Linux traffic preflight and isolated validation" style={{ padding: 0, margin: "16px 0", overflow: "hidden" }}>
    {/* ── header — visual with icon + concise theory ── */}
    <div style={{ padding: "18px 20px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)", display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
      <div style={{ display: "flex", gap: 14, alignItems: "center", minWidth: 0 }}>
        <span className="brandmark" style={{ width: 38, height: 38, display: "grid", placeItems: "center" }}><IconSatellite size={18} /></span>
        <div style={{ minWidth: 0 }}>
          <h2 style={{ margin: 0, fontSize: 15, fontWeight: 700, letterSpacing: "-0.01em" }}>Linux traffic control: preflight & isolated validation</h2>
          <div style={{ fontSize: 12, color: "var(--dim)", marginTop: 2 }}>Namespace-only drill — no host enforcement, no sudo, no packet enforcement from this console.</div>
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>No real-host apply. Existing policies are preserved. Management routes cover declared IPs only, not complete management safety. A distinct assigned human reviews namespace-only validation.</div>
        </div>
      </div>
      <span className="badge" style={{ borderColor: "color-mix(in srgb, var(--accent) 30%, var(--line))", background: "color-mix(in srgb, var(--accent) 10%, var(--panel))", color: "var(--accent)" }}><span className="dot" style={{ background: "var(--accent)" }} /> ISOLATED DRILL</span>
    </div>

    {/* ── visual theory strip — compact, not wall of text ── */}
    <div style={{ padding: "10px 16px", background: "var(--panel)", borderBottom: "1px solid var(--line)", display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center", fontSize: 11, color: "var(--dim)" }}>
      <span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><span style={{ width: 6, height: 6, borderRadius: 999, background: "var(--accent)" }} /> A missing kernel qdisc is a blocked result; no sudo or host fallback.</span>
      <span style={{ opacity: .4 }}>·</span>
      <span>Results remain local artifacts, not an API-certified production change.</span>
      <span style={{ marginLeft: "auto", fontFamily: "var(--mono)", color: "var(--faint)" }}>CLI: <code>python scripts/traffic_control.py preflight</code> · <code>isolated-drill --acknowledge-disposable-namespace-only</code></span>
    </div>

    {/* ── visual 7-step pipeline ── */}
    <div style={{ padding: "16px 16px 8px", background: "var(--panel)" }}>
      <div style={{ display: "grid", gridTemplateColumns: `repeat(${STEPS.length}, 1fr)`, gap: 0, position: "relative" }}>
        {/* connector line */}
        <div style={{ position: "absolute", top: 18, left: "6%", right: "6%", height: 2, background: "var(--line)", zIndex: 0 }} />
        <div style={{ position: "absolute", top: 18, left: "6%", width: `${(activeIdx / (STEPS.length - 1)) * 88}%`, height: 2, background: "var(--accent)", zIndex: 0, transition: "width .25s ease" }} />
        {STEPS.map((s, i) => {
          const state = i === activeIdx ? "active" : i < activeIdx ? "done" : "";
          return <div key={s.key} onClick={() => setAction(s.key)} role="button" tabIndex={0} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setAction(s.key)} style={{ position: "relative", zIndex: 1, textAlign: "center", cursor: "pointer", padding: "0 4px" }}>
            <div style={{
              width: 36, height: 36, borderRadius: 999, margin: "0 auto 8px", display: "grid", placeItems: "center",
              border: `2px solid ${state === "active" ? "var(--accent)" : state === "done" ? "var(--green)" : "var(--line-strong)"}`,
              background: state === "active" ? "var(--panel-2)" : state === "done" ? "color-mix(in srgb, var(--green) 12%, var(--panel))" : "var(--bg-2)",
              color: state === "active" ? "var(--accent)" : state === "done" ? "var(--green)" : "var(--faint)",
              fontFamily: "var(--mono)", fontWeight: 700, fontSize: 13, transition: "all .18s ease"
            }}>{state === "done" ? "✓" : s.n}</div>
            <div style={{ fontSize: 10.5, fontWeight: 600, color: state === "active" ? "var(--accent)" : state === "done" ? "var(--text)" : "var(--dim)", lineHeight: 1.2 }}>{s.title}</div>
            <div style={{ fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)", marginTop: 2, letterSpacing: ".02em" }}>{s.desc}</div>
          </div>;
        })}
      </div>
      <div style={{ display: "flex", justifyContent: "center", gap: 6, marginTop: 12, flexWrap: "wrap" }}>
        <span className="badge slate">Fresh measured proposal → preflight request → inspect blockers</span>
        <span className="badge slate">Propose validation → separate review → namespace-only packet</span>
      </div>
    </div>

    {/* ── professional form card ── */}
    <div style={{ padding: 16 }}>
      <div className="panel" style={{ background: "var(--panel-2)", border: "1px solid var(--line)", padding: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 8 }}>
          <b style={{ fontSize: 13, display: "flex", alignItems: "center", gap: 8 }}><IconTarget size={14} style={{ color: "var(--accent)" }} /> Execute workflow step</b>
          <span className="badge" style={{ background: "var(--panel)", borderColor: "var(--line-strong)" }}>Step {activeIdx + 1} of {STEPS.length}: {STEPS[activeIdx].title}</span>
        </div>

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
          <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 12, alignItems: "start" }}>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Operation <select className="inp" name="action" value={action} onChange={(e) => setAction(e.target.value)}>
              <option value="request">1. Register preflight request</option><option value="spec">2. Download specification</option><option value="import">3. Import preflight</option><option value="inspect">4. Inspect preflight blockers</option><option value="propose">5. Propose isolated validation</option><option value="history">Inspect validation history</option><option value="approve">6. Assigned reviewer approval</option><option value="packet">7. Download namespace-only packet</option>
            </select></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Record UUID for selected operation <input className="inp" name="id" required maxLength={36} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" style={{ fontFamily: "var(--mono)" }} /></label>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginTop: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Expected proposal/preflight record hash, or capture canonical hash <input className="inp" name="hash" maxLength={64} placeholder="64-hex SHA256" style={{ fontFamily: "var(--mono)" }} /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Declared management IPs (comma-separated) <input className="inp" name="ips" maxLength={400} placeholder="10.0.0.1,10.0.0.2" style={{ fontFamily: "var(--mono)" }} /></label>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 110px 1fr", gap: 12, marginTop: 10 }}>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Assigned reviewer user UUID <input className="inp" name="reviewer" maxLength={36} placeholder="reviewer UUID" style={{ fontFamily: "var(--mono)" }} /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Drill seconds <input className="inp" name="duration" type="number" min={1} max={5} defaultValue={1} /></label>
            <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5 }}>Review evidence reference <input className="inp" name="evidence" maxLength={120} placeholder="change-ticket-123" /></label>
          </div>

          <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5, marginTop: 10 }}>Proposal/review reason <input className="inp" name="reason" maxLength={500} placeholder="Describe the intent (kept as audit note)" /></label>

          <label style={{ fontSize: 11, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 5, marginTop: 10 }}>Original preflight JSON (never parsed/re-encoded by this page) <textarea className="inp" name="capture" rows={4} maxLength={65536} placeholder='Paste raw JSON capture — uint64 inodes preserved verbatim' style={{ fontFamily: "var(--mono)", fontSize: 12 }} /></label>

          <div style={{ display: "flex", gap: 8, marginTop: 14, alignItems: "center", flexWrap: "wrap" }}>
            <button className="btn primary" disabled={busy} type="submit">{busy ? "Working…" : "Run selected step"}</button>
            <span style={{ fontSize: 11, color: "var(--faint)" }}>No credentials or private keys needed · Guide 87 for required files</span>
          </div>
        </form>
      </div>

      {/* ── result — visual ── */}
      <div style={{ marginTop: 12, display: download ? "flex" : "block", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        {download && <button className="btn" type="button" onClick={() => { const url = URL.createObjectURL(new Blob([result], { type: "application/json" })); const a = document.createElement("a"); a.href = url; a.download = "traffic-control-packet.json"; a.click(); URL.revokeObjectURL(url); }}>Save original JSON</button>}
        {result && <span className={`badge ${result.startsWith("Refused") ? "red" : result.includes("secret") ? "slate" : "green"}`} style={{ maxWidth: "100%", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{result.slice(0, 80)}</span>}
      </div>
      <pre role="status" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 300, overflow: "auto", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 12, marginTop: 10, fontSize: 11, fontFamily: "var(--mono)", lineHeight: 1.5 }}>{result || "No operation yet — select a step and submit a UUID. Responses preserve raw JSON with uint64 fidelity."}</pre>
    </div>
  </section>;
}
