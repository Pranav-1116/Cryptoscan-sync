/* Resilience, compliance & air-gap console (features 21, 22, 25, 26, 27).
   All actions call the LIVE backend (/api/v1/resilience/*). No demo data:
   panels render zeros/empty until real operations run. Deterministic, no AI. */
import React, { useEffect, useState } from "react";
import {
  apiComplianceReport, apiRetentionPlan, apiBackupCreate, apiBackupRestore,
  apiAuditAttestation, apiAirgapStatus, apiAirgapImportFeed, apiOtDecode,
} from "../lib/api.js";
import { useI18n } from "../i18n/I18n.jsx";

const FRAMEWORKS = [
  { id: "NIST_SP_800_53", label: "NIST SP 800-53" },
  { id: "PCI_DSS_4", label: "PCI-DSS 4.0" },
  { id: "DORA", label: "DORA" },
  { id: "UAE_PDPL", label: "UAE PDPL" },
];

function Err({ e }: { e: string | undefined }) {
  if (!e) return null;
  return <div style={{ color: "var(--red,#e01e5a)", fontSize: 12, marginTop: 8 }}>{e}</div>;
}
function Badge({ ok, children }: { ok?: boolean; children: React.ReactNode }) {
  return <span className="badge" style={{ background: ok ? "rgba(47,184,119,0.12)" : "rgba(232,161,61,0.12)", color: ok ? "var(--green)" : "var(--amber)" }}>{children}</span>;
}

const TABS = ["report", "backup", "attestation", "airgap", "ot"];

export default function Resilience() {
  const { t } = useI18n();
  const [tab, setTab] = useState("report");
  const TAB_LABELS: Record<string, string> = {
    report: t("resilience.complianceReport"), backup: t("resilience.backup"),
    attestation: t("resilience.auditAttestation"), airgap: t("resilience.airgap"),
    ot: t("resilience.otDecode"),
  };

  return (
    <div className="page" style={{ padding: 24 }}>
      <h1 style={{ fontSize: 22, margin: 0 }}>{t("resilience.title")}</h1>
      <p style={{ color: "var(--faint)", fontSize: 13, marginTop: 6 }}>
        signed reports · encrypted backups &amp; PITR · hash-chain attestation · air-gap feeds · passive OT decode
      </p>
      <div style={{ display: "flex", gap: 8, margin: "16px 0", flexWrap: "wrap" }}>
        {TABS.map((x) => (
          <button key={x} className={`btn sm ${tab === x ? "primary" : ""}`}
            onClick={() => setTab(x)}
            style={tab === x ? { background: "var(--grad)", color: "#fff", border: "none" } : {}}>
            {TAB_LABELS[x]}
          </button>
        ))}
      </div>

      {tab === "report" && <ReportPanel />}
      {tab === "backup" && <BackupPanel />}
      {tab === "attestation" && <AttestationPanel />}
      {tab === "airgap" && <AirgapPanel />}
      {tab === "ot" && <OtPanel />}
    </div>
  );
}

function ReportPanel() {
  const { t } = useI18n();
  const [fw, setFw] = useState("PCI_DSS_4");
  const [org, setOrg] = useState("CryptoScan Tenant");
  const [evidenceText, setEvidenceText] = useState('{\n  "tls": [{"id":"tls-1","title":"TLS 1.3 enforced","status":"PASS"}],\n  "audit": [{"id":"au-1","title":"Chained audit","status":"PASS"}]\n}');
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);

  const gen = async (download: boolean) => {
    setBusy(true); setErr(undefined);
    let evidence = {};
    try { evidence = JSON.parse(evidenceText || "{}"); }
    catch (e) { setErr("evidence JSON invalid: " + String(e)); setBusy(false); return; }
    if (download) {
      // PDF download directly from backend
      const token = localStorage.getItem("zelnx_token");
      const r = await fetch("/api/v1/resilience/compliance-report", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ framework: fw, org, evidence, format: "pdf" }),
      });
      if (!r.ok) { setErr(`HTTP ${r.status}`); setBusy(false); return; }
      const blob = await r.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `compliance-${fw}.pdf`; a.click();
      URL.revokeObjectURL(url);
      setBusy(false);
      return;
    }
    const out = await apiComplianceReport(fw, org, evidence);
    setBusy(false);
    if (!out.ok) { setErr(out.error); return; }
    setRes(out.data);
  };

  return (
    <div className="card" style={{ padding: 18 }}>
      <label style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.framework")}</label>
      <select className="input" value={fw} onChange={(e) => setFw(e.target.value)}
        style={{ display: "block", margin: "6px 0 12px", minWidth: 260 }}>
        {FRAMEWORKS.map((f) => <option key={f.id} value={f.id}>{f.label}</option>)}
      </select>
      <label style={{ fontSize: 12, color: "var(--faint)" }}>Organization</label>
      <input className="input" value={org} onChange={(e) => setOrg(e.target.value)}
        style={{ display: "block", margin: "6px 0 12px", minWidth: 320 }} />
      <label style={{ fontSize: 12, color: "var(--faint)" }}>Evidence by tag (JSON)</label>
      <textarea className="input" value={evidenceText} onChange={(e) => setEvidenceText(e.target.value)}
        rows={6} style={{ display: "block", width: "100%", fontFamily: "var(--mono)", fontSize: 12, margin: "6px 0 12px" }} />
      <div style={{ display: "flex", gap: 8 }}>
        <button className="btn sm" disabled={busy} onClick={() => gen(false)}>preview mapping</button>
        <button className="btn sm primary" disabled={busy} onClick={() => gen(true)}
          style={{ background: "var(--grad)", color: "#fff", border: "none" }}>{t("resilience.generatePdf")}</button>
      </div>
      <Err e={err} />
      {res && (
        <div style={{ marginTop: 16 }}>
          <Badge ok>compliance {res.mapping?.compliance_pct}% · signature {String(res.signature || "").slice(0, 16)}…</Badge>
          <table className="table" style={{ width: "100%", marginTop: 12, fontSize: 12 }}>
            <thead><tr><th>control</th><th>title</th><th>status</th><th>evidence</th></tr></thead>
            <tbody>
              {res.mapping?.control_rows?.map((r: any) => (
                <tr key={r.control}>
                  <td style={{ fontFamily: "var(--mono)" }}>{r.control}</td>
                  <td>{r.title}</td>
                  <td>{r.status}</td>
                  <td>{r.evidence?.length ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function BackupPanel() {
  const { t } = useI18n();
  const [db, setDb] = useState("proddb");
  const [created, setCreated] = useState<any>(null);
  const [restored, setRestored] = useState<any>(null);
  const [retention, setRetention] = useState<any>(null);
  const [err, setErr] = useState<string>();

  const create = async () => {
    setErr(undefined);
    const out = await apiBackupCreate(db, "postgres", 1);
    if (!out.ok) return setErr(out.error);
    setCreated(out.data);
  };
  const restore = async () => {
    if (!created) return setErr("create a backup first");
    setErr(undefined);
    const out = await apiBackupRestore(db, created.ciphertext_b64, created.manifest);
    if (!out.ok) return setErr(out.error);
    setRestored(out.data);
  };
  const plan = async () => {
    const backups = [
      { backup_id: "daily-stale", created_at: "2026-08-01T00:00:00+00:00" },
      { backup_id: "daily-fresh", created_at: new Date().toISOString() },
    ];
    const out = await apiRetentionPlan(backups);
    if (!out.ok) return setErr(out.error);
    setRetention(out.data);
  };

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.backup")}</h3>
        <input className="input" value={db} onChange={(e) => setDb(e.target.value)} style={{ marginRight: 8, minWidth: 220 }} />
        <button className="btn sm" onClick={create}>{t("resilience.createBackup")}</button>
        <button className="btn sm" onClick={restore} style={{ marginLeft: 8 }} disabled={!created}>{t("resilience.restore")}</button>
        <Err e={err} />
        {created && <div style={{ marginTop: 10, fontSize: 12 }}>
          <Badge ok>created {created.manifest?.backup_id} · {created.manifest?.engine} · {created.manifest?.size_bytes}B · HMAC signed</Badge>
        </div>}
        {restored && <div style={{ marginTop: 8, fontSize: 12 }}>
          <Badge ok={restored.restored}>restored={String(restored.restored)} · PIT wal_applied={String(restored.wal_applied)}</Badge>
        </div>}
      </div>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.retention")}</h3>
        <button className="btn sm" onClick={plan}>run sample GFS retention plan</button>
        {retention && <div style={{ marginTop: 10, fontSize: 12 }}>
          <Badge ok>kept {retention.kept} · purged {retention.purged}</Badge>
          <ul style={{ marginTop: 8 }}>
            {retention.purge?.map((p: any) => <li key={p.backup_id} style={{ color: "var(--amber)" }}>
              {p.backup_id} — {p.tier} · {p.reason}</li>)}
          </ul>
        </div>}
      </div>
    </div>
  );
}

function AttestationPanel() {
  const { t } = useI18n();
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string>();
  useEffect(() => {
    apiAuditAttestation().then((o) => { if (o.ok) setRes(o.data); else setErr(o.error); });
  }, []);
  const verified = res?.attestation?.status === "VERIFIED";
  return (
    <div className="card" style={{ padding: 18 }}>
      <h3 style={{ marginTop: 0 }}>{t("resilience.auditAttestation")}</h3>
      <Err e={err} />
      {!res && <div style={{ color: "var(--faint)" }}>{t("common.loading")}</div>}
      {res && (
        <>
          <Badge ok={verified}>{verified ? t("dash.verified") : t("dash.tampered")}</Badge>
          <table className="table" style={{ width: "100%", marginTop: 12, fontSize: 12 }}>
            <tbody>
              <tr><td>entries checked</td><td>{res.attestation?.entries_checked}</td></tr>
              <tr><td>tamper detected</td><td>{String(res.attestation?.tamper_detected)}</td></tr>
              <tr><td>mismatches</td><td>{res.attestation?.mismatch_count}</td></tr>
              <tr><td>sequence gaps</td><td>{res.attestation?.sequence_gap_count}</td></tr>
              <tr><td>chain head</td><td style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{res.attestation?.chain_head}</td></tr>
              <tr><td>signature (HMAC-SHA256)</td><td style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{res.signature}</td></tr>
              <tr><td>signer</td><td>{res.attestation?.signer}</td></tr>
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function AirgapPanel() {
  const { t } = useI18n();
  const [status, setStatus] = useState<any>(null);
  const [bundleText, setBundleText] = useState("");
  const [imported, setImported] = useState<any>(null);
  const [err, setErr] = useState<string>();
  useEffect(() => { apiAirgapStatus().then((o) => { if (o.ok) setStatus(o.data); }); }, []);
  const doImport = async () => {
    setErr(undefined);
    let bundle;
    try { bundle = JSON.parse(bundleText); } catch (e) { return setErr("bundle JSON invalid: " + String(e)); }
    const out = await apiAirgapImportFeed(bundle);
    if (!out.ok) return setErr(out.error);
    setImported(out.data);
  };
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.airgap")}</h3>
        {status && <Badge ok={!status.airgap}>
          {status.airgap ? t("dash.on") : t("dash.off")} · {status.external_feed_hosts_blocked?.length ?? 0} external feed hosts blocked
        </Badge>}
        <p style={{ fontSize: 12, color: "var(--faint)" }}>
          Set <code>AIRGAP_MODE=true</code> and <code>AIRGAP_ALLOWLIST</code> to block all external feeds;
          offline CVE/registry updates arrive as signed bundles.
        </p>
      </div>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.importFeed")}</h3>
        <textarea className="input" rows={5} placeholder='{"manifest":{...},"tar_b64":"..."}'
          value={bundleText} onChange={(e) => setBundleText(e.target.value)}
          style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 11 }} />
        <button className="btn sm" style={{ marginTop: 8 }} onClick={doImport}>verify &amp; import signed bundle</button>
        <Err e={err} />
        {imported && <div style={{ marginTop: 10 }}><Badge ok>imported {imported.imported} entries · {JSON.stringify(imported.by_feed)}</Badge></div>}
      </div>
    </div>
  );
}

function OtPanel() {
  const { t } = useI18n();
  const [hexInput, setHexInput] = useState("0300000d02f08032010001000400000400");
  const [proto, setProto] = useState<"tcp" | "udp">("tcp");
  const [dport, setDport] = useState(102);
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string>();
  const decode = async () => {
    setErr(undefined);
    const frame = proto === "tcp"
      ? { tcp_payload_hex: hexInput.trim(), dport }
      : { udp_payload_hex: hexInput.trim(), dport };
    const out = await apiOtDecode([frame]);
    if (!out.ok) return setErr(out.error);
    setRes(out.data);
  };
  return (
    <div className="card" style={{ padding: 18 }}>
      <h3 style={{ marginTop: 0 }}>{t("resilience.otDecode")}</h3>
      <p style={{ fontSize: 12, color: "var(--faint)" }}>
        Passive decode of observed spans (S7comm/102, EtherNet-IP/44818, BACnet/47808, OPC-UA/4840).
        <b style={{ color: "var(--green)" }}> {t("resilience.activeProbes")}: 0</b> — SIS/ESD are never probed.
      </p>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <select className="input" value={proto} onChange={(e) => { setProto(e.target.value as any); setDport(e.target.value === "udp" ? 47808 : 102); }}>
          <option value="tcp">TCP (S7comm / ENIP / OPC-UA)</option>
          <option value="udp">UDP (BACnet/IP)</option>
        </select>
        <input className="input" type="number" value={dport} onChange={(e) => setDport(Number(e.target.value))} style={{ width: 90 }} />
      </div>
      <textarea className="input" rows={3} value={hexInput} onChange={(e) => setHexInput(e.target.value)}
        style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 12, margin: "10px 0" }} />
      <button className="btn sm primary" onClick={decode} style={{ background: "var(--grad)", color: "#fff", border: "none" }}>decode frame</button>
      <Err e={err} />
      {res && (
        <div style={{ marginTop: 14 }}>
          <Badge ok={!res.cleartext_engineering_detected}>
            {res.frames_flagged} flagged · protocols {res.protocols?.join(", ") || "none"} · probes {res.active_probes_sent}
          </Badge>
          {res.findings?.map((f: any, i: number) => (
            <div key={i} className="card" style={{ padding: 12, marginTop: 10, fontSize: 12 }}>
              <b style={{ color: f.risk === "HIGH" ? "var(--red,#e01e5a)" : "var(--amber)" }}>{f.protocol} · {f.risk}</b>
              <div style={{ marginTop: 4 }}>{f.flags?.join(", ")}</div>
              <div style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 11, marginTop: 4 }}>{JSON.stringify(f.detail)}</div>
            </div>
          ))}
          {res.frames_flagged === 0 && <p style={{ fontSize: 12, color: "var(--faint)", marginTop: 10 }}>{t("common.noData")} / no cleartext engineering detected in this frame.</p>}
        </div>
      )}
    </div>
  );
}
