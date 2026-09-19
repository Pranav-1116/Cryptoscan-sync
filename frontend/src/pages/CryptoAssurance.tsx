import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code, Tabs } from "../components/ui.jsx";
import { ApiResult } from "../lib/api.js";
import {
  apiTlsAudit, apiCtMonitor, apiExpiryAlerts, apiHsmCheck,
  apiTrustStore, apiPqcDowngrade, apiCodeRuleScan,
} from "../lib/api.js";

/* Crypto & key assurance — active TLS/cipher enumeration, certificate-
   transparency monitoring, key/cert expiry alerts + SLA, HSM/KMS key residence,
   trust-store inventory, hybrid-PQC downgrade detection, and deterministic
   weak-primitive code scanning. Every panel drives the live backend; offline
   or unauthorized renders an explicit empty/error state. No demo data. */

function ResultBox({ res, height = 320 }: { res: ApiResult<any> | null; height?: number }) {
  if (!res) return <p className="faint" style={{ fontSize: 12 }}>Run a check to see live results.</p>;
  if (res.source === "offline" || res.ok === false)
    return <Badge tone="red"><span className="dot" /> {res.error || "BACKEND OFFLINE / UNAUTHORIZED"}</Badge>;
  return <div style={{ maxHeight: height, overflow: "auto" }}><Code>{JSON.stringify(res.data, null, 2)}</Code></div>;
}

function gradeTone(g?: string) { return g === "F" || g === "D" ? "red" : g === "C" ? "amber" : "green"; }

/* ------------------------------- TLS audit ------------------------------- */
function TlsPanel() {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("443");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    if (!host.trim()) return;
    setBusy(true);
    setRes(await apiTlsAudit(host.trim(), parseInt(port || "443", 10)));
    setBusy(false);
  };
  const d = res?.data;
  return (
    <Panel title="Active TLS / cipher enumeration" sub="Real outbound TLS handshakes: protocol downgrade (TLS 1.0/1.1), weak cipher suites, certificate chain, expiry, SAN mismatch" className="mt">
      <div className="grid" style={{ gridTemplateColumns: "2fr 1fr auto", gap: 8, alignItems: "center", marginBottom: 12 }}>
        <input className="inp" placeholder="target host (e.g. edge.example.com)" value={host} onChange={(e) => setHost(e.target.value)} />
        <input className="inp" type="number" placeholder="port" value={port} onChange={(e) => setPort(e.target.value)} />
        <button className="btn sm" onClick={() => void run()} disabled={busy}>{busy ? "Auditing…" : "Run TLS audit"}</button>
      </div>
      {res?.ok && d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone={gradeTone(d.grade)}>GRADE {d.grade}</Badge>
            <Badge tone={d.summary?.downgrade_accepted ? "red" : "green"}>TLS 1.0/1.1 downgrade {d.summary?.downgrade_accepted ? "ACCEPTED" : "blocked"}</Badge>
            <Badge tone={d.summary?.weak_cipher_accepted ? "red" : "green"}>weak ciphers {d.summary?.weak_cipher_accepted ? "ACCEPTED" : "refused"}</Badge>
            <Badge tone={d.certificate?.issues?.length ? "amber" : "green"}>{d.certificate?.issues?.length || 0} cert issues</Badge>
          </div>
          <Table
            head={["protocol", "status", "cipher"]}
            rows={(d.protocols || []).map((p: any) => [
              <span className="mono">{p.version}</span>,
              <Badge tone={p.status === "NEGOTIATED" ? (p.severity === "INFO" ? "green" : "red") : ""}>{p.status}</Badge>,
              <span className="mono">{p.cipher || "—"}</span>,
            ])}
          />
          {d.certificate?.subject && (
            <div className="mt">
              <Table head={["certificate", "value"]} rows={[
                ["subject", <span className="mono">{d.certificate.subject}</span>],
                ["issuer", <span className="mono">{d.certificate.issuer}</span>],
                ["SAN", <span className="mono">{(d.certificate.san || []).join(", ")}</span>],
                ["key", <span className="mono">{d.certificate.key_type} {d.certificate.key_bits}</span>],
                ["days to expiry", <span className="num">{d.certificate.days_until_expiry}</span>],
                ["issues", <span>{(d.certificate.issues || []).map((i: any) => i.code).join(", ") || "none"}</span>],
              ]} />
            </div>
          )}
        </>
      )}
      {(!res?.ok) && <ResultBox res={res} height={120} />}
    </Panel>
  );
}

/* ----------------------------- CT monitoring ----------------------------- */
function CtPanel() {
  const [domains, setDomains] = useState("");
  const [issuers, setIssuers] = useState("");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    const d = domains.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
    if (!d.length) return;
    setBusy(true);
    setRes(await apiCtMonitor(d, issuers.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)));
    setBusy(false);
  };
  const s = res?.data?.summary;
  return (
    <Panel title="Certificate-transparency monitoring" sub="Poll CT logs for your domains and flag new/rogue issuances against an approved-issuer allowlist" className="mt">
      <div className="grid" style={{ gridTemplateColumns: "1.4fr 1.4fr auto", gap: 8, alignItems: "center", marginBottom: 12 }}>
        <input className="inp" placeholder="monitored domains (comma-separated)" value={domains} onChange={(e) => setDomains(e.target.value)} />
        <input className="inp" placeholder="approved issuer CNs (comma-separated, optional)" value={issuers} onChange={(e) => setIssuers(e.target.value)} />
        <button className="btn sm" onClick={() => void run()} disabled={busy}>{busy ? "Polling…" : "Poll CT logs"}</button>
      </div>
      {res?.ok && s && (
        <div className="row" style={{ gap: 8, marginBottom: 10 }}>
          <Badge tone=""><span className="dot" /> {s.total_observed} observed</Badge>
          <Badge tone={s.new_cert_alerts ? "amber" : "green"}>{s.new_cert_alerts} new</Badge>
          <Badge tone={s.rogue_cert_alerts ? "red" : "green"}>{s.rogue_cert_alerts} rogue</Badge>
        </div>
      )}
      <ResultBox res={res} />
    </Panel>
  );
}

/* --------------------------- Expiry alerts + SLA -------------------------- */
function ExpiryPanel() {
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [rows, setRows] = useState<Array<{ subject: string; not_after: string; sla_tier: string }>>([
    { subject: "", not_after: "", sla_tier: "tier1" },
  ]);
  const set = (i: number, k: string, v: string) => setRows(rows.map((r, j) => j === i ? { ...r, [k]: v } : r));
  const run = async () => {
    const assets = rows.filter((r) => r.subject && r.not_after);
    if (!assets.length) return;
    setBusy(true);
    setRes(await apiExpiryAlerts(assets));
    setBusy(false);
  };
  const d = res?.data;
  return (
    <Panel title="Key / cert expiry alerts & SLA" sub="Fixed 90 / 60 / 30 / 7-day rules with per-tier SLA renewal-lead tracking and breach detection" className="mt">
      {rows.map((r, i) => (
        <div key={i} className="grid" style={{ gridTemplateColumns: "2fr 1.4fr 1fr", gap: 8, marginBottom: 8 }}>
          <input className="inp" placeholder="certificate / key subject" value={r.subject} onChange={(e) => set(i, "subject", e.target.value)} />
          <input className="inp" placeholder="not-after (YYYY-MM-DD)" value={r.not_after} onChange={(e) => set(i, "not_after", e.target.value)} />
          <select className="inp" value={r.sla_tier} onChange={(e) => set(i, "sla_tier", e.target.value)}>
            <option value="tier1">tier1 (edge, 60d lead)</option>
            <option value="tier2">tier2 (internal, 30d)</option>
            <option value="tier3">tier3 (dev, 14d)</option>
          </select>
        </div>
      ))}
      <div className="row" style={{ marginBottom: 12 }}>
        <button className="btn sm" onClick={() => setRows([...rows, { subject: "", not_after: "", sla_tier: "tier1" }])}>+ add asset</button>
        <button className="btn sm primary" onClick={() => void run()} disabled={busy}>{busy ? "Evaluating…" : "Run campaign"}</button>
      </div>
      {res?.ok && d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone={d.sla_breached ? "red" : "green"}>{d.sla_breached} SLA breached</Badge>
            <Badge tone={d.sla_at_risk ? "amber" : "green"}>{d.sla_at_risk} at risk</Badge>
            <Badge tone="">{d.actionable_alerts} actionable alerts</Badge>
          </div>
          <Table
            head={["subject", "days left", "highest", "SLA", "rules"]}
            rows={(d.alerts || []).map((a: any) => [
              <span className="mono">{a.subject}</span>,
              <span className="num">{a.days_until_expiry}</span>,
              <Badge tone={a.severity === "CRITICAL" ? "red" : a.severity === "HIGH" ? "amber" : ""}>{a.severity}</Badge>,
              <Badge tone={a.sla_status === "BREACHED" ? "red" : a.sla_status === "AT_RISK" ? "amber" : "green"}>{a.sla_status}</Badge>,
              <span className="mono" style={{ fontSize: 11 }}>{(a.codes || []).join(" ")}</span>,
            ])}
          />
        </>
      )}
      {!res?.ok && <ResultBox res={res} height={100} />}
    </Panel>
  );
}

/* --------------------------- HSM/KMS residence --------------------------- */
function HsmPanel() {
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState(JSON.stringify({
    keys: [
      { key_ref: "alias/edge-signing", provider: "aws_kms", describe: { metadata: { origin: "AWS_CLOUDHSM", protection_level: "HARDWARE", exportable: false } } },
      { key_ref: "alias/soft", provider: "aws_kms", describe: { metadata: { origin: "AWS_KMS", protection_level: "SOFTWARE", exportable: true } } },
    ],
  }, null, 2));
  const run = async () => {
    setBusy(true);
    try { setRes(await apiHsmCheck(JSON.parse(text).keys)); }
    catch (e) { setRes({ source: "live", ok: false, data: null, error: "invalid JSON: " + String(e) }); }
    setBusy(false);
  };
  const d = res?.data;
  return (
    <Panel title="HSM / KMS / PKCS#11 key residence" sub="Verify keys live in hardware (AWS KMS CloudHSM, Azure Managed HSM, Luna/PKCS#11) and are non-exportable; sign challenge proves in-boundary use" className="mt">
      <div className="row" style={{ marginBottom: 10 }}><button className="btn sm primary" onClick={() => void run()} disabled={busy}>{busy ? "Checking…" : "Verify residence"}</button>
        <span className="faint" style={{ fontSize: 12 }}>paste collector-reported key attributes (key material never included)</span></div>
      <textarea className="inp" rows={7} value={text} onChange={(e) => setText(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 12 }} />
      {res?.ok && d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone="green"><span className="dot" /> {d.summary.hardware_backed} hardware-backed</Badge>
            <Badge tone={d.summary.software_keys ? "red" : "green"}>{d.summary.software_keys} software</Badge>
            <Badge tone={d.summary.connectivity_failures ? "red" : "green"}>{d.summary.connectivity_failures} unreachable</Badge>
          </div>
          <Table
            head={["key", "provider", "residence", "connect", "sign", "issues"]}
            rows={(d.results || []).map((r: any) => [
              <span className="mono">{r.key_ref}</span>,
              <span className="mono">{r.provider}</span>,
              <Badge tone={r.key_residence === "HSM" ? "green" : r.key_residence === "SOFTWARE" ? "red" : "amber"}>{r.key_residence || r.error}</Badge>,
              <span className="mono">{r.connectivity}</span>,
              <span className="mono">{r.sign_challenge}</span>,
              <span style={{ fontSize: 11 }}>{(r.issues || []).map((i: any) => i.code).join(", ") || "—"}</span>,
            ])}
          />
        </>
      )}
      {!res?.ok && <ResultBox res={res} height={100} />}
    </Panel>
  );
}

/* ---------------------------- Trust store -------------------------------- */
function TrustPanel() {
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [bundle, setBundle] = useState("");
  const [approved, setApproved] = useState("");
  const run = async () => {
    setBusy(true);
    const b64 = btoa(unescape(encodeURIComponent(bundle)));
    setRes(await apiTrustStore({ pem_bundle_b64: b64, approved_subjects: approved.split(",").map((s) => s.trim()).filter(Boolean) }));
    setBusy(false);
  };
  const d = res?.data;
  return (
    <Panel title="Trust-store inventory" sub="Parse container/OS CA bundles (and Java cacerts via keytool); flag expired roots, non-root anchors, and extra/rogue CAs vs a baseline" className="mt">
      <textarea className="inp" rows={5} placeholder="paste PEM CA bundle (-----BEGIN CERTIFICATE----- blocks)" value={bundle} onChange={(e) => setBundle(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 8 }} />
      <div className="grid" style={{ gridTemplateColumns: "1fr auto", gap: 8, marginBottom: 12 }}>
        <input className="inp" placeholder="approved root CNs (comma-separated, optional baseline)" value={approved} onChange={(e) => setApproved(e.target.value)} />
        <button className="btn sm primary" onClick={() => void run()} disabled={busy || !bundle.trim()}>{busy ? "Auditing…" : "Audit trust store"}</button>
      </div>
      {res?.ok && d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone=""><span className="dot" /> {d.total_anchors} anchors</Badge>
            <Badge tone={d.extra_or_rogue_roots?.length ? "red" : "green"}>{d.extra_or_rogue_roots?.length || 0} rogue/extra</Badge>
            <Badge tone={d.expired_roots?.length ? "red" : "green"}>{d.expired_roots?.length || 0} expired</Badge>
          </div>
          <ResultBox res={res} />
        </>
      )}
      {!res?.ok && <ResultBox res={res} height={100} />}
    </Panel>
  );
}

/* ------------------------- Hybrid PQC downgrade -------------------------- */
function PqcPanel() {
  const [host, setHost] = useState("");
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => { setBusy(true); setRes(await apiPqcDowngrade(host.trim())); setBusy(false); };
  const d = res?.data;
  return (
    <Panel title="Hybrid-PQC downgrade detector" sub="Offer ML-KEM hybrid groups and verify negotiation cannot be downgraded to classic-only (handshake inspection). Requires a PQC-enabled scanner build for live negotiation." className="mt">
      <div className="grid" style={{ gridTemplateColumns: "1fr auto", gap: 8, marginBottom: 12 }}>
        <input className="inp" placeholder="TLS endpoint host" value={host} onChange={(e) => setHost(e.target.value)} />
        <button className="btn sm" onClick={() => void run()} disabled={busy || !host.trim()}>{busy ? "Testing…" : "Test hybrid negotiation"}</button>
      </div>
      {res?.ok && d && (
        <Badge tone={d.downgrade_resisted ? "green" : d.overall_outcome === "DOWNGRADE_DETECTED" ? "red" : "amber"}>
          {d.overall_outcome}
        </Badge>
      )}
      <div className="mt"><ResultBox res={res} /></div>
    </Panel>
  );
}

/* --------------------------- Code weak rules ----------------------------- */
function CodePanel() {
  const [name, setName] = useState("snippet.py");
  const [src, setSrc] = useState('import hashlib\nfrom Crypto.Cipher import AES\nSECRET_KEY = "hardcoded-please-change-123"\ndef digest(x):\n    return hashlib.md5(x).hexdigest()\ndef encrypt(k, d):\n    return AES.new(k, AES.MODE_ECB).encrypt(d)\n');
  const [res, setRes] = useState<ApiResult<any> | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => { setBusy(true); setRes(await apiCodeRuleScan(name, src)); setBusy(false); };
  const d = res?.data;
  return (
    <Panel title="Weak-primitive code rules" sub="Deterministic AST (Python) + pattern rules (Java/JS/Go/C): MD5, DES, ECB, RSA<2048, SecureRandom misuse, hardcoded keys, static IV" className="mt">
      <div className="row" style={{ gap: 8, marginBottom: 8 }}>
        <input className="inp" style={{ maxWidth: 200 }} value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn sm primary" onClick={() => void run()} disabled={busy}>{busy ? "Scanning…" : "Scan snippet"}</button>
      </div>
      <textarea className="inp" rows={7} value={src} onChange={(e) => setSrc(e.target.value)} style={{ fontFamily: "var(--mono)", fontSize: 11.5, marginBottom: 12 }} />
      {res?.ok && d && (
        <>
          <div className="row" style={{ gap: 8, marginBottom: 10 }}>
            <Badge tone={d.total_findings ? "red" : "green"}><span className="dot" /> {d.total_findings} findings</Badge>
            {Object.entries(d.by_rule || {}).map(([rule, n]) => <Badge key={rule} tone="amber">{rule}: {String(n)}</Badge>)}
          </div>
          <Table
            head={["line", "rule", "severity", "snippet"]}
            rows={(d.findings || []).map((f: any) => [
              <span className="num">{f.line}</span>,
              <span className="mono">{f.rule_id}</span>,
              <Badge tone={f.severity === "CRITICAL" ? "red" : f.severity === "HIGH" ? "amber" : ""}>{f.severity}</Badge>,
              <span className="mono" style={{ fontSize: 11 }}>{f.snippet}</span>,
            ])}
          />
        </>
      )}
      {!res?.ok && <ResultBox res={res} height={100} />}
    </Panel>
  );
}

export default function CryptoAssurance() {
  const [tab, setTab] = useState(0);
  const tabs = ["TLS audit", "CT monitoring", "Expiry & SLA", "HSM / KMS", "Trust store", "Hybrid-PQC", "Code rules"];
  return (
    <>
      <PageHead
        crumb="operate / crypto assurance"
        title="Crypto & key assurance"
        sub="Active TLS/cipher enumeration · certificate-transparency monitoring · expiry alerts & SLA · HSM/KMS residence · trust-store inventory · hybrid-PQC downgrade · weak-primitive code rules — deterministic, fail-closed"
        right={<Badge tone=""><span className="dot" /> ACTIVE CRYPTO AUDIT</Badge>}
      />
      <div className="mt"><Tabs tabs={tabs} active={tab} onChange={setTab} /></div>
      {tab === 0 && <TlsPanel />}
      {tab === 1 && <CtPanel />}
      {tab === 2 && <ExpiryPanel />}
      {tab === 3 && <HsmPanel />}
      {tab === 4 && <TrustPanel />}
      {tab === 5 && <PqcPanel />}
      {tab === 6 && <CodePanel />}
    </>
  );
}
