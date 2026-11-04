/* Resilience, compliance & air-gap console (features 21, 22, 25, 26, 27).
   Actions use the bank API. Backup and retention views show retained records,
   never generated sample results; a successful response is not a restore drill. */
import React, { useEffect, useState } from "react";
import {
  apiComplianceReport, apiRetentionPlan, apiBackupCreate,
  apiAuditAttestation, apiAirgapStatus, apiAirgapImportFeed, apiOtDecode,
  apiBackupRunScheduled, apiBackupList, apiAirgapBuildBundle, apiOtIngestPcap,
  apiBackupConfigSet, apiBackupSweep,
  tenantFetch,
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
  return <div style={{ color: "var(--red)", fontSize: 12, marginTop: 8 }}>{e}</div>;
}
function Badge({ ok, children }: { ok?: boolean; children: React.ReactNode }) {
  return <span className="badge" style={{ background: ok ? "color-mix(in srgb, var(--green) 12%, transparent)" : "color-mix(in srgb, var(--amber) 12%, transparent)", color: ok ? "var(--green)" : "var(--amber)" }}>{children}</span>;
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
        {t("resilience.subtitle")}
      </p>
      <div style={{ display: "flex", gap: 8, margin: "16px 0", flexWrap: "wrap" }}>
        {TABS.map((x) => (
          <button key={x} className={`btn sm ${tab === x ? "primary" : ""}`}
            onClick={() => setTab(x)}
            style={tab === x ? { background: "var(--grad)", color: "var(--text)", border: "none" } : {}}>
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
  const [evidenceText, setEvidenceText] = useState("{}");
  const [res, setRes] = useState<any>(null);
  const [err, setErr] = useState<string>();
  const [busy, setBusy] = useState(false);

  const gen = async (download: boolean) => {
    setBusy(true); setErr(undefined);
    let evidence = {};
    try { evidence = JSON.parse(evidenceText || "{}"); }
    catch (e) { setErr(t("resilience.evidenceJsonInvalid") + String(e)); setBusy(false); return; }
    if (download) {
      // PDF download directly from backend
      // The session travels as the httpOnly cookie that tenantFetch sends
      // (credentials: "include"). Reading a token out of localStorage here was
      // both an XSS surface and broken: the key it read never existed.
      const r = await tenantFetch("/api/v1/resilience/compliance-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
      <label style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.organization")}</label>
      <input className="input" value={org} onChange={(e) => setOrg(e.target.value)}
        style={{ display: "block", margin: "6px 0 12px", minWidth: 320 }} />
      <label style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.evidenceLabel")}</label>
      <p style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.evidenceHelp")}</p>
      <textarea className="input" value={evidenceText} onChange={(e) => setEvidenceText(e.target.value)}
        rows={6} style={{ display: "block", width: "100%", fontFamily: "var(--mono)", fontSize: 12, margin: "6px 0 12px" }} />
      <div style={{ display: "flex", gap: 8 }}>
        <button className="btn sm" disabled={busy} onClick={() => gen(false)}>{t("resilience.previewMapping")}</button>
        <button className="btn sm primary" disabled={busy} onClick={() => gen(true)}
          style={{ background: "var(--grad)", color: "var(--text)", border: "none" }}>{t("resilience.generatePdf")}</button>
      </div>
      <Err e={err} />
      {res && (
        <div style={{ marginTop: 16 }}>
          <Badge ok>{t("resilience.compliance")} {res.mapping?.compliance_pct}% · {t("resilience.signature")} {String(res.signature || "").slice(0, 16)}…</Badge>
          <table className="table" style={{ width: "100%", marginTop: 12, fontSize: 12 }}>
            <thead><tr><th>{t("resilience.colControl")}</th><th>{t("resilience.colTitle")}</th><th>{t("resilience.colStatus")}</th><th>{t("resilience.colEvidence")}</th></tr></thead>
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
  const [db, setDb] = useState("");
  const [created, setCreated] = useState<any>(null);
  const [retention, setRetention] = useState<any>(null);
  const [sched, setSched] = useState<any>(null);
  const [stored, setStored] = useState<any[]>([]);
  const [persisted, setPersisted] = useState<any>(null);
  const [err, setErr] = useState<string>();

  const create = async () => {
    setErr(undefined);
    if (!db.trim()) return setErr(t("resilience.databaseRequired"));
    const out = await apiBackupCreate(db.trim(), "postgres", 1);
    if (!out.ok) return setErr(out.error);
    setCreated(out.data);
    const listed = await apiBackupList();
    if (listed.ok) setStored(listed.data?.backups ?? []);
  };
  const plan = async () => {
    setErr(undefined);
    const listed = await apiBackupList();
    if (!listed.ok) return setErr(listed.error);
    const backups = listed.data?.backups ?? [];
    setStored(backups);
    if (!backups.length) return setErr(t("resilience.noRetainedBackups"));
    const out = await apiRetentionPlan(backups);
    if (!out.ok) return setErr(out.error);
    setRetention(out.data);
  };
  const runScheduled = async () => {
    setErr(undefined);
    if (!db.trim()) return setErr(t("resilience.databaseRequired"));
    const out = await apiBackupRunScheduled([
      { database_id: db.trim(), engine: "postgres", interval_hours: 24 },
    ], false);
    if (!out.ok) return setErr(out.error);
    setSched(out.data);
    const l = await apiBackupList();
    if (l.ok) setStored(l.data?.backups ?? []);
  };
  const persistAndSweep = async () => {
    setErr(undefined);
    if (!db.trim()) return setErr(t("resilience.databaseRequired"));
    const dbs = [{ database_id: db.trim(), engine: "postgres", interval_hours: 24 }];
    const cfg = await apiBackupConfigSet(dbs);
    if (!cfg.ok) return setErr(cfg.error);
    setPersisted(cfg.data);
    const out = await apiBackupSweep(false);
    if (!out.ok) return setErr(out.error);
    setSched(out.data);
    const l = await apiBackupList();
    if (l.ok) setStored(l.data?.backups ?? []);
  };

  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.logicalBackups")}</h3>
        <p style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.backupHelp")}</p>
        <button className="btn sm primary" onClick={runScheduled}
          style={{ background: "var(--grad)", color: "var(--text)", border: "none" }}>{t("resilience.runScheduled")}</button>
        <button className="btn sm" onClick={persistAndSweep} style={{ marginLeft: 8 }}>
          {t("resilience.persistSweep")}
        </button>
        <Err e={err} />
        {persisted && <div style={{ marginTop: 6, fontSize: 12 }}>
          <Badge>{t("resilience.persisted")} {persisted.configured} {t("resilience.persistedSuffix")}</Badge>
        </div>}
        {sched && <div style={{ marginTop: 10, fontSize: 12 }}>
          <Badge ok={Array.isArray(sched.results) && sched.results.length > 0 && !sched.results.some((row: any) => row.ok === false)}>
            {t("resilience.attempted")} {sched.ran} · {t("resilience.skipped")} {sched.skipped} · {t("resilience.retained")} {sched.stored_backups}
            {sched.results?.some((row: any) => row.ok === false) ? " · " + t("resilience.failuresReported") : ""}
          </Badge>
          {sched.results?.filter((row: any) => row.ok === false).map((row: any, index: number) =>
            <div key={`${row.database_id}-${index}`} role="alert" style={{ color: "var(--red)", marginTop: 6 }}>
              {row.database_id}: {row.error || t("resilience.backupFailed")}
            </div>)}
          {sched.retention && <div style={{ marginTop: 4, color: "var(--faint)" }}>
            {t("resilience.retention")}: {t("resilience.kept")} {sched.retention.kept} · {t("resilience.purged")} {sched.retention.purged} · {t("resilience.deleted")} {sched.retention.deleted_keys?.length ?? 0}
          </div>}
        </div>}
        {stored.length > 0 && (
          <table className="table" style={{ width: "100%", marginTop: 10, fontSize: 11 }}>
            <thead><tr><th>{t("resilience.colBackup")}</th><th>{t("resilience.colDatabase")}</th><th>{t("resilience.colEngine")}</th><th>{t("resilience.colSequence")}</th><th>{t("resilience.colSha256")}</th></tr></thead>
            <tbody>
              {stored.map((m: any, index: number) => <tr key={m.storage_key || `${m.backup_id}-${index}`}>
                <td style={{ fontFamily: "var(--mono)" }}>{m.backup_id}</td>
                <td>{m.database_id}</td><td>{m.engine}</td><td>{m.sequence}</td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{String(m.ciphertext_sha256 || "").slice(0, 16)}…</td>
              </tr>)}
            </tbody>
          </table>
        )}
      </div>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.backup")}</h3>
        <label style={{ fontSize: 12, color: "var(--faint)" }} htmlFor="backup-database">{t("resilience.databaseLabel")}</label>
        <input id="backup-database" className="input" value={db} onChange={(e) => setDb(e.target.value)}
          placeholder={t("resilience.databasePlaceholder")} style={{ display: "block", margin: "8px 0", minWidth: 220 }} />
        <button className="btn sm" onClick={create} disabled={!db.trim()}>{t("resilience.createBackup")}</button>
        <p style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.restoreNotAvailable")}</p>
        <Err e={err} />
        {created && <div style={{ marginTop: 10, fontSize: 12 }}>
          <Badge ok>{t("resilience.created")} {created.manifest?.backup_id} · {created.manifest?.engine} · {created.manifest?.size_bytes}B · {t("resilience.hmacSigned")}</Badge>
        </div>}
      </div>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.retention")}</h3>
        <button className="btn sm" onClick={plan}>{t("resilience.planRetention")}</button>
        <span style={{ marginLeft: 8, fontSize: 12, color: "var(--faint)" }}>{t("resilience.previewOnly")}</span>
        <Err e={err} />
        {retention && <div style={{ marginTop: 10, fontSize: 12 }}>
          <Badge ok>{t("resilience.kept")} {retention.kept} · {t("resilience.purged")} {retention.purged}</Badge>
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
              <tr><td>{t("resilience.entriesChecked")}</td><td>{res.attestation?.entries_checked}</td></tr>
              <tr><td>{t("resilience.totalChainEntries")}</td><td>{res.attestation?.entry_count ?? "—"}</td></tr>
              <tr><td>{t("resilience.verification")}</td><td>{res.attestation?.mode ?? "full"}{res.attestation?.full_verified_at ? ` · ${t("resilience.fullAt")} ${res.attestation.full_verified_at}` : ""}</td></tr>
              <tr><td>{t("resilience.tamperDetected")}</td><td>{String(res.attestation?.tamper_detected)}</td></tr>
              <tr><td>{t("resilience.mismatches")}</td><td>{res.attestation?.mismatch_count}</td></tr>
              <tr><td>{t("resilience.sequenceGaps")}</td><td>{res.attestation?.sequence_gap_count}</td></tr>
              <tr><td>{t("resilience.chainHead")}</td><td style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{res.attestation?.chain_head}</td></tr>
              <tr><td>{t("resilience.signatureHmac")}</td><td style={{ fontFamily: "var(--mono)", fontSize: 10 }}>{res.signature}</td></tr>
              <tr><td>{t("resilience.signer")}</td><td>{res.attestation?.signer}</td></tr>
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function BundleBuilder() {
  const { t } = useI18n();
  const [entriesText, setEntriesText] = useState(JSON.stringify([
    { feed: "nvd", id: "CVE-2026-0001", payload: { package: "openssl", cvss: 9.8, version: "3.0.2", summary: "example advisory" } },
  ], null, 2));
  const [bundle, setBundle] = useState<any>(null);
  const [err, setErr] = useState<string>();
  const build = async () => {
    setErr(undefined);
    let entries;
    try { entries = JSON.parse(entriesText); } catch (e) { return setErr(t("resilience.entriesJsonInvalid") + String(e)); }
    const out = await apiAirgapBuildBundle(entries);
    if (!out.ok) return setErr(out.error);
    setBundle(out.data);
  };
  return (
    <div>
      <p style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.bundleHelp")}</p>
      <textarea className="input" rows={4} value={entriesText} onChange={(e) => setEntriesText(e.target.value)}
        style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 11 }} />
      <button className="btn sm" style={{ marginTop: 8 }} onClick={build}>{t("resilience.buildBundle")}</button>
      <Err e={err} />
      {bundle && (
        <div style={{ marginTop: 10 }}>
          <Badge ok>{bundle.manifest?.entry_count} {t("resilience.entries")} · {t("resilience.sha")} {String(bundle.manifest?.bundle_sha256 || "").slice(0, 16)}… · {t("resilience.hmacSigned")}</Badge>
          <textarea className="input" readOnly rows={4} value={JSON.stringify(bundle)}
            style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 10, marginTop: 8 }}
            onFocus={(e) => e.target.select()} />
        </div>
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
    try { bundle = JSON.parse(bundleText); } catch (e) { return setErr(t("resilience.bundleJsonInvalid") + String(e)); }
    const out = await apiAirgapImportFeed(bundle);
    if (!out.ok) return setErr(out.error);
    setImported(out.data);
  };
  return (
    <div style={{ display: "grid", gap: 14 }}>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.airgap")}</h3>
        {status && <Badge ok={!status.airgap}>
          {status.airgap ? t("dash.on") : t("dash.off")} · {status.external_feed_hosts_blocked?.length ?? 0} {t("resilience.externalHostsBlocked")}
        </Badge>}
        <p style={{ fontSize: 12, color: "var(--faint)" }}>
          {t("resilience.airgapSet")} <code>AIRGAP_MODE=true</code> {t("resilience.airgapAnd")}{" "}
          <code>AIRGAP_ALLOWLIST</code> {t("resilience.airgapHelp")}
        </p>
      </div>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.buildBundleHeading")}</h3>
        <BundleBuilder />
      </div>
      <div className="card" style={{ padding: 18 }}>
        <h3 style={{ marginTop: 0 }}>{t("resilience.importFeed")}</h3>
        <textarea className="input" rows={5} placeholder='{"manifest":{...},"tar_b64":"..."}'
          value={bundleText} onChange={(e) => setBundleText(e.target.value)}
          style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 11 }} />
        <button className="btn sm" style={{ marginTop: 8 }} onClick={doImport}>{t("resilience.verifyImport")}</button>
        <Err e={err} />
        {imported && <div style={{ marginTop: 10 }}><Badge ok>{t("resilience.imported")} {imported.imported} {t("resilience.entries")} · {JSON.stringify(imported.by_feed)}</Badge></div>}
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
        {t("resilience.otHelp")} {t("resilience.otProtocols")}
        <b style={{ color: "var(--green)" }}> {t("resilience.activeProbes")}: 0</b> {t("resilience.sisNeverProbed")}
      </p>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <select className="input" value={proto} onChange={(e) => { setProto(e.target.value as any); setDport(e.target.value === "udp" ? 47808 : 102); }}>
          <option value="tcp">{t("resilience.protocolTcp")}</option>
          <option value="udp">{t("resilience.protocolUdp")}</option>
        </select>
        <input className="input" type="number" value={dport} onChange={(e) => setDport(Number(e.target.value))} style={{ width: 90 }} />
      </div>
      <textarea className="input" rows={3} value={hexInput} onChange={(e) => setHexInput(e.target.value)}
        style={{ width: "100%", fontFamily: "var(--mono)", fontSize: 12, margin: "10px 0" }} />
      <button className="btn sm primary" onClick={decode} style={{ background: "var(--grad)", color: "var(--text)", border: "none" }}>{t("resilience.decodeFrame")}</button>
      <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
        <label style={{ fontSize: 12, color: "var(--faint)" }}>{t("resilience.pcapLabel")}</label>
        <input type="file" accept=".pcap,.cap" className="input" style={{ display: "block", margin: "6px 0" }}
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const buf = new Uint8Array(await file.arrayBuffer());
            let bin = ""; for (const b of buf) bin += String.fromCharCode(b);
            const b64 = btoa(bin);
            const out = await apiOtIngestPcap(b64);
            if (!out.ok) { setErr(out.error); return; }
            setRes(out.data);
          }} />
      </div>
      <Err e={err} />
      {res && (
        <div style={{ marginTop: 14 }}>
          <Badge ok={!res.cleartext_engineering_detected}>
            {res.frames_flagged} {t("resilience.flagged")} · {t("resilience.protocols")} {res.protocols?.join(", ") || t("resilience.none")} · {t("resilience.probes")} {res.active_probes_sent}
          </Badge>
          {res.findings?.map((f: any, i: number) => (
            <div key={i} className="card" style={{ padding: 12, marginTop: 10, fontSize: 12 }}>
              <b style={{ color: f.risk === "HIGH" ? "var(--red)" : "var(--amber)" }}>{f.protocol} · {f.risk}</b>
              <div style={{ marginTop: 4 }}>{f.flags?.join(", ")}</div>
              <div style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 11, marginTop: 4 }}>{JSON.stringify(f.detail)}</div>
            </div>
          ))}
          {res.frames_flagged === 0 && <p style={{ fontSize: 12, color: "var(--faint)", marginTop: 10 }}>{t("common.noData")} / {t("resilience.noCleartext")}</p>}
        </div>
      )}
    </div>
  );
}
