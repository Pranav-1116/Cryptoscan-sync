import React, { useEffect, useRef, useState } from "react";
import { activeTenantId, getToken, tenantFetch } from "../lib/api.js";
import { watchPrivateScope } from "../lib/privateScope.js";
import AuthenticatedDownload from "./AuthenticatedDownload.js";
import { Panel, Badge } from "./ui.jsx";

const BASE = "/api/v1/collection/qualification/campaigns";
type Campaign = {
  state: string; evaluated_at: string; blockers: string[]; dispatch: string; channel: string;
  assignees: Record<string, { user_id: string; username: string | null; display_name: string | null }>;
  record: { subject_id: string; revision: number; payload: {
    policy: { campaign_id: string }; return_channel_reference: string; index: unknown; withdrawn: boolean;
    artifacts: Record<string, { bytes: number; kind: string; category: string | null; native_result: string | null }>;
    reviews: Record<string, { statement: { decision: string } }>;
  } };
};

/** Public-only operator receipt/review controls, not a remote collector or signer.
 * Scope fencing covers fetch, local file reads, exports, visibility and unmount.
 * It cannot undo a write already accepted by the server in the original estate.
 */
export default function HostQualification() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [current, setCurrent] = useState<Campaign | null>(null);
  const [identifier, setIdentifier] = useState("");
  const [reference, setReference] = useState("");
  const [channel, setChannel] = useState("");
  const [policy, setPolicy] = useState("");
  const [assignments, setAssignments] = useState("");
  const [index, setIndex] = useState("");
  const [review, setReview] = useState("");
  const [kind, setKind] = useState("native");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const epoch = useRef(0);
  const active = useRef<AbortController | null>(null);

  const clearDrafts = () => {
    setReference(""); setChannel(""); setPolicy(""); setAssignments(""); setIndex(""); setReview(""); setFile(null); setKind("native");
  };
  useEffect(() => {
    const invalidate = () => {
      epoch.current++; active.current?.abort(); active.current = null;
      setCampaigns([]); setCursor(null); setCurrent(null); setIdentifier(""); clearDrafts(); setBusy(false); setError("");
    };
    const stop = watchPrivateScope(invalidate);
    return () => { stop(); epoch.current++; active.current?.abort(); active.current = null; };
  }, []);

  const run = async (work: (request: (path: string, init?: RequestInit) => Promise<any>, live: () => boolean) => Promise<void>) => {
    if (active.current) return;
    const controller = new AbortController(); active.current = controller;
    const generation = epoch.current, tenant = activeTenantId(), token = getToken();
    const live = () => generation === epoch.current && !controller.signal.aborted && tenant === activeTenantId() && token === getToken();
    const request = async (path: string, init?: RequestInit) => {
      if (!live()) throw new Error("Private scope changed; reload.");
      const response = await tenantFetch(path, { ...init, signal: controller.signal });
      if (!live()) throw new Error("Private scope changed; reload.");
      const body = await response.json();
      if (!live()) throw new Error("Private scope changed; reload.");
      if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `Request refused (${response.status}); validate the public schema and authority.`);
      return body;
    };
    setBusy(true); setError("");
    try { await work(request, live); }
    catch (e) { if (live()) setError(e instanceof Error ? e.message : "Request failed"); }
    finally { if (active.current === controller) { active.current = null; setBusy(false); } }
  };
  const list = (next: string | null = null) => void run(async (request, live) => {
    const data = await request(BASE + (next ? `?cursor=${encodeURIComponent(next)}` : ""));
    if (live()) { setCampaigns(data.campaigns); setCursor(data.next_cursor); }
  });
  const open = (id: string) => void run(async (request, live) => {
    const data = await request(`${BASE}/${encodeURIComponent(id)}`);
    if (live()) { setCurrent(data); setIdentifier(id); clearDrafts(); }
  });
  const mutate = (action: string, extra: Record<string, unknown>) => {
    if (!current) return;
    const id = current.record.subject_id;
    void run(async (request, live) => {
      const data = await request(`${BASE}/${encodeURIComponent(id)}/${action}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ expected_revision: current.record.revision, evidence_reference: reference, ...extra }),
      });
      if (live()) { setCurrent(data); setCampaigns([]); setCursor(null); clearDrafts(); }
    });
  };
  const jsonAction = (action: string, field: string, text: string) => {
    try { mutate(action, { [field]: JSON.parse(text) }); }
    catch { setError(`Invalid ${field} JSON. No submission made.`); }
  };
  const create = () => void run(async (request, live) => {
    const data = await request(BASE, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ policy: JSON.parse(policy), return_channel_reference: channel, evidence_reference: reference }) });
    if (live()) { setCurrent(data); setIdentifier(data.record.subject_id); setCampaigns([]); setCursor(null); clearDrafts(); }
  });
  const upload = () => {
    if (!current || !file) return;
    const id = current.record.subject_id;
    void run(async (request, live) => {
      if (file.size > 2 * 1024 * 1024 || !file.size) throw new Error("Original must be nonempty and at most 2 MiB.");
      // Keep exact original bytes. Never parse/reserialize or label an upload PASS.
      const bytes = await file.arrayBuffer();
      if (!live()) return;
      const query = new URLSearchParams({ expected_revision: String(current.record.revision), kind, evidence_reference: reference });
      const data = await request(`${BASE}/${encodeURIComponent(id)}/artifacts?${query}`, { method: "POST", headers: { "Content-Type": ["native", "public_json"].includes(kind) ? "application/json" : "application/octet-stream" }, body: bytes });
      if (live()) { setCurrent(data); setCampaigns([]); setCursor(null); clearDrafts(); }
    });
  };
  const payload = current?.record.payload;
  const locked = busy || !reference.trim();
  return <Panel title="Approved-host qualification" sub="Named-human assignments → original public evidence → frozen index → separate externally signed reviews. No remote execution or automatic production approval." className="mt">
    <p>Use only the bank-approved return channel and authorized hosts. This authenticated API is <strong>not proof of bank-approved secure transport</strong>. No people have been contacted or hosts dispatched by this screen.</p>
    <p><strong>Do not upload credentials, private keys or private logs.</strong></p>
    <div className="row" style={{ gap: 8 }}>
      <button className="btn sm" disabled={busy} onClick={() => list()}>Load campaigns</button>
      {cursor && <button className="btn sm" disabled={busy} onClick={() => list(cursor)}>Next page</button>}
      <input className="inp" aria-label="Campaign record ID" value={identifier} onChange={e => setIdentifier(e.target.value)} />
      <button className="btn sm" disabled={busy || !identifier} onClick={() => open(identifier)}>Open / refresh</button>
    </div>
    {campaigns.length === 0 && <p className="faint">No campaign list loaded.</p>}
    <ul>{campaigns.map(c => <li key={c.record.subject_id}><button className="btn sm" disabled={busy} onClick={() => open(c.record.subject_id)}>{c.record.payload.policy.campaign_id} — {c.state}</button></li>)}</ul>
    {error && <p role="alert">{error} A failed request does not prove an earlier submission was rolled back; refresh before retrying.</p>}
    <label>Change / evidence reference<input className="inp" aria-label="Change / evidence reference" value={reference} onChange={e => setReference(e.target.value)} maxLength={120} /></label>
    <details><summary>Create approved campaign (trust authority)</summary>
      <p>Paste the approved AcceptancePolicy JSON with exact tenant, scope, platform-release/plan digests and two distinct public reviewer keys. No private signing keys. Policy and campaign identity are immutable.</p>
      <label>Bank-approved return channel reference (not a URL or credential)<input className="inp" aria-label="Return channel approval reference" value={channel} onChange={e => setChannel(e.target.value)} maxLength={120} /></label>
      <p><span title={"Record the authorized bank approval reference only. The product does not provision or attest TLS, encryption, channel approval or notification delivery."}>{"Record the authorized bank approval reference only."}</span></p>
      <textarea className="inp" aria-label="Approved policy JSON" rows={8} value={policy} onChange={e => setPolicy(e.target.value)} />
      <button className="btn sm" disabled={locked || !policy || !channel.trim()} onClick={create}>Create campaign</button>
    </details>
    {current && payload && <section aria-label="Current qualification campaign">
      <p>State evaluated at {current.evaluated_at}. Refresh to recheck authority and signature expiry before relying on it.</p>
      <p>Return channel approval reference: {payload.return_channel_reference} (recorded reference, not transport attestation).</p>
      <h3>{payload.policy.campaign_id} · revision {current.record.revision}</h3>
      <Badge tone={current.state === "BLOCKED" ? "red" : "amber"}>{current.state}</Badge>
      <p>Not production clearance — separate approval required.</p>
      <p className="mono">{current.dispatch} · {current.channel}</p>
      <ul>{current.blockers.map((b, n) => <li key={n}>{b}</li>)}</ul>
      <h4>Named responsibilities</h4>
      {Object.keys(current.assignees).length === 0 && <p>Unassigned.</p>}
      <ul>{Object.entries(current.assignees).map(([role, a]) => <li key={role}>{role}: {a.display_name || a.username || "User unavailable"} ({a.user_id})</li>)}</ul>
      <details><summary>Assign humans (trust authority, before first original)</summary>
        <p>Role-to-assignee JSON: linux_operator, windows_operator, verifier, independent_assessor, bank_acceptor. Each needs user_id; reviewers also need reviewer_id matching their pinned policy key. Reviewers must be separate from operators, approver and each other. Assigning does not notify anyone or prove organizational independence.</p>
        <textarea className="inp" aria-label="Assignments JSON" rows={6} value={assignments} onChange={e => setAssignments(e.target.value)} />
        <button className="btn sm" disabled={locked || !assignments || payload.withdrawn || Object.keys(payload.artifacts).length > 0} onClick={() => jsonAction("assignments", "assignments", assignments)}>Save assignments</button>
      </details>
      <h4>Original public artifacts</h4>
      <p><span title={"Assigned operators return native receipts; assigned operators/verifier may return supporting public JSON or raw TPM public quote/signature structures. No ZIPs. 2 MiB per file / 256 artifacts / 16 MiB campaign total. Preserve original bytes and failure/UNKNOWN results; they are not converted into PASS."}>{"Assigned operators return native receipts"}</span></p>
      <select className="inp" aria-label="Artifact kind" value={kind} onChange={e => setKind(e.target.value)}><option value="native">Native receipt</option><option value="public_json">Supporting public JSON</option><option value="tpm_attest">Raw TPM public quote</option><option value="tpm_signature">Raw TPM public signature</option></select>
      <input key={`${epoch.current}:${current.record.subject_id}:${current.record.revision}`} type="file" aria-label="Original public artifact" onChange={e => setFile(e.target.files?.[0] || null)} />
      <button className="btn sm" disabled={locked || !file || payload.withdrawn || payload.index !== null} onClick={upload}>Return original</button>
      <ul>{Object.entries(payload.artifacts).map(([digest, a]) => <li key={digest}><span className="mono">{digest}</span> · {a.kind} {a.category} · {a.bytes} bytes · {a.native_result || "No native verdict"} <AuthenticatedDownload path={`${BASE}/${current.record.subject_id}/artifacts/${digest}`} filename={`${digest}.original`}>Download original (raw privilege)</AuthenticatedDownload></li>)}</ul>
      <details><summary>Freeze verified index (assigned verifier)</summary>
        <p><span title={"Paste the complete EvidenceIndex JSON. All referenced originals must already be retained. Missing/changed or unqualified native evidence cannot freeze; an index does not prove the worker checks ran."}>{"Paste the complete EvidenceIndex JSON."}</span></p>
        <textarea className="inp" aria-label="Evidence index JSON" rows={6} value={index} onChange={e => setIndex(e.target.value)} />
        <button className="btn sm" disabled={locked || !index || payload.withdrawn || payload.index !== null} onClick={() => jsonAction("freeze", "index", index)}>Freeze evidence</button>
      </details>
      <details><summary>Return externally signed decision (assigned reviewer)</summary>
        <p>Each separate reviewer signs the exact tenant/campaign/release/policy/index scope outside this product with their own private signer. Paste only SignedReview JSON (public statement/signature). Signed REJECT, FAIL and NOT_RUN are retained and block acceptance; decisions cannot be overwritten.</p>
        <textarea className="inp" aria-label="Signed review JSON" rows={6} value={review} onChange={e => setReview(e.target.value)} />
        <button className="btn sm" disabled={locked || !review || payload.withdrawn || payload.index === null} onClick={() => jsonAction("reviews", "review", review)}>Submit signed review</button>
      </details>
      <ul>{Object.entries(payload.reviews).map(([role, proof]) => <li key={role}>{role}: {proof.statement.decision}</li>)}</ul>
      <AuthenticatedDownload path={`${BASE}/${current.record.subject_id}/export`} filename="qualification-record.json">Export current public review record</AuthenticatedDownload>
      <details><summary>Inspect policy, index and retained record</summary><pre style={{ maxHeight: 420, overflow: "auto", whiteSpace: "pre-wrap" }}>{JSON.stringify(current, null, 2)}</pre></details>
      <button className="btn sm" disabled={locked || payload.withdrawn} onClick={() => mutate("withdraw", {})}>Withdraw campaign (trust authority)</button>
    </section>}
  </Panel>;
}
