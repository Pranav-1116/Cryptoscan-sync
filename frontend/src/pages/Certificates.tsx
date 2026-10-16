import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer, Code } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { StatusMark } from "../components/icons";
import {
  apiLiveInventory,
  apiExpiryCalendar,
  apiCertCsr,
  apiCertIssue,
  apiCertRenew,
  apiCertRevoke,
  apiCertRenewalQueue,
  apiCertificateEstate,
  apiCertificateOwnership,
  apiCertificateRevocationCheck,
  apiCertificateUsages,
  CertificateEstateRow,
  CertificateUsageRow,
  RevocationProbe,
  LiveCertificate,
  LiveInventory,
  ExpiryCalendar,
} from "../lib/api.js";

/* Certificates — TWO honest surfaces:
   1. The live TLS-scan inventory (GET /api/v1/live-scan/inventory) —
      certificates a scan-run happened to observe. Empty until a scan
      runs; ephemeral by nature.
   2. The persisted certificate ESTATE (GET /api/v1/certificates,
      round 74) — rows deduped by SHA-256 fingerprint with owner,
      recorded usage locations, revocation state and the renewal
      workflow. Owner absent renders as UNKNOWN — a fact, not an
      inference; no task linkage is invented (tasks bind to evidence
      records, certificates are not evidence records). */

type CertRow = LiveCertificate & { sanCount?: number };

function certTone(status: string): "green" | "amber" | "red" | "" {
  if (status === "EXPIRED") return "red";
  if (status === "EXPIRING") return "amber";
  return "green";
}

function CertDrawer({ cert, onClose }: { cert: CertRow; onClose: () => void }) {
  const days = cert.days ?? 0;
  return (
    <Drawer title={cert.cn} sub={`${cert.key} · ${cert.sig} · owner ${cert.owner}`} onClose={onClose}>
      <div className="row" style={{ marginBottom: 16 }}>
        <Badge tone={certTone(cert.status)}>{cert.status}</Badge>
        <Badge tone={days < 30 ? "red" : days < 90 ? "amber" : "green"}>{days} DAYS LEFT</Badge>
        <Badge tone="cyan">{cert.endpoint}</Badge>
      </div>
      <Panel title="Certificate" sub="parsed properties from the live TLS scan" frame>
        <div className="tree">
          CN: <span className="hl">{cert.cn}</span><br />
          signature: {cert.sig}<br />
          key: {cert.key} · SAN: {cert.san}<br />
          EKU: {cert.eku} · issuer: {cert.owner}<br />
          chain position: {cert.chain_position} of {cert.chain_length}
        </div>
      </Panel>
      <Panel title="Evidence" sub="what links here" frame className="mt">
        <div className="dim" style={{ fontSize: 12 }}>
          A live-scan certificate row is one observation run, not an evidence-chain record —
          there is no per-record verification or task linkage to show here. The persisted
          estate below carries the durable facts (owner, usages, revocation state).
        </div>
      </Panel>
    </Drawer>
  );
}

/* ── The persisted estate drawer (round 74) ────────────────────────── */

function EstateCertDrawer({ cert, onClose }: { cert: CertificateEstateRow; onClose: () => void }) {
  const days = cert.days_until_expiry;
  // where this certificate was observed — the recorded usage locations
  const [usages, setUsages] = useState<CertificateUsageRow[] | null>(null);
  // revocation check result (OCSP + CRL probes)
  const [revocation, setRevocation] = useState<{ ocsp: RevocationProbe; crl: RevocationProbe } | null>(null);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeErr, setRevokeErr] = useState<string | null>(null);
  // ownership assignment (audited, certificates.manage)
  const [owner, setOwner] = useState("");
  const [contact, setContact] = useState("");
  const [reason, setReason] = useState("");
  const [ownBusy, setOwnBusy] = useState(false);
  const [ownMsg, setOwnMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    let alive = true;
    setUsages(null);
    setRevocation(null);
    void apiCertificateUsages(cert.id).then((r) => {
      if (!alive) return;
      setUsages(r.source === "live" && r.data ? (r.data.usages ?? []) : null);
    });
    return () => { alive = false; };
  }, [cert.id]);

  async function runRevocationCheck() {
    setRevokeBusy(true);
    setRevokeErr(null);
    const r = await apiCertificateRevocationCheck(cert.id);
    setRevokeBusy(false);
    if (r.source === "live" && r.data) {
      setRevocation(r.data);
    } else {
      setRevocation(null);
      setRevokeErr(r.error || "revocation check failed");
    }
  }

  async function assignOwnership() {
    if (!reason.trim()) {
      setOwnMsg({ ok: false, text: "A reason is mandatory — the assignment is audited." });
      return;
    }
    setOwnBusy(true);
    setOwnMsg(null);
    const r = await apiCertificateOwnership(cert.fingerprint_sha256, {
      owner: owner.trim() || undefined,
      technical_contact: contact.trim() || undefined,
      reason: reason.trim(),
    });
    setOwnBusy(false);
    if (r.source === "live" && r.data) {
      setOwnMsg({ ok: true, text: `Ownership recorded — owner ${r.data.owner ?? "unchanged"}.` });
    } else {
      setOwnMsg({
        ok: false,
        text: r.error === "HTTP 403"
          ? "Requires certificates.manage (superadmin / ciso / security_analyst)."
          : r.error || "ownership assignment failed",
      });
    }
  }

  return (
    <Drawer title={cert.subject || cert.fingerprint_sha256.slice(0, 16)}
            sub={`estate row · ${cert.public_key_algorithm || "—"} ${cert.public_key_size ?? ""} · fp ${cert.fingerprint_sha256.slice(0, 12)}…`}
            onClose={onClose}>
      <div className="row" style={{ marginBottom: 16, flexWrap: "wrap" }}>
        <Badge tone={certTone(cert.expiry_status || "")}>{cert.expiry_status || "UNKNOWN"}</Badge>
        {days !== null && (
          <Badge tone={days < 0 ? "red" : days < 30 ? "red" : days < 90 ? "amber" : "green"}>
            {days} DAYS {days < 0 ? "PAST" : "LEFT"}
          </Badge>
        )}
        {cert.owner
          ? <Badge tone="green">OWNER {cert.owner}</Badge>
          : <Badge tone="amber">OWNER UNKNOWN</Badge>}
        {cert.revocation_status
          ? <Badge tone={String(cert.revocation_status).toUpperCase().includes("REVOK") ? "red" : "cyan"}>
              {String(cert.revocation_status).toUpperCase()}
            </Badge>
          : <Badge>REVOCATION UNCHECKED</Badge>}
        {cert.is_self_signed && <Badge tone="amber">SELF-SIGNED</Badge>}
      </div>

      <Panel title="Certificate facts" sub="the persisted estate row" frame>
        <div className="tree">
          subject: <span className="hl">{cert.subject || "—"}</span><br />
          issuer: {cert.issuer || "—"}<br />
          serial: <span className="mono">{cert.serial_number || "—"}</span><br />
          key: {cert.public_key_algorithm || "—"} {cert.public_key_size ?? ""} bits<br />
          valid: {(cert.not_before || "—")} → {(cert.not_after || "—")}<br />
          SAN: {(cert.san ?? []).join(", ") || "—"}
        </div>
      </Panel>

      <Panel title="Where observed" sub="recorded usage locations (usages)" frame className="mt">
        {usages === null && (
          <div className="dim" style={{ fontSize: 12.5 }}>Usage lookup unavailable.</div>
        )}
        {usages !== null && usages.length === 0 && (
          <div className="dim" style={{ fontSize: 12.5 }}>
            No usage locations recorded for this certificate — it exists in the estate, but no
            endpoint observation has been linked to it yet (unknown, not zero).
          </div>
        )}
        {usages !== null && usages.length > 0 && (
          <div className="mono-list">
            {usages.map((u) => (
              <div key={u.id || u.location} className="spread" style={{ fontSize: 12.5, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
                <span className="mono">{u.location}</span>
                <span className="row" style={{ gap: 6 }}>
                  <Badge>{u.usage_type}</Badge>
                  {u.last_seen && <span className="dim" style={{ fontSize: 11.5 }}>
                    {new Date(u.last_seen).toLocaleString()}
                  </span>}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="Revocation check" sub="OCSP / CRL probes — what they determined, no guesses" frame className="mt">
        <button className="btn sm" disabled={revokeBusy} onClick={() => void runRevocationCheck()} style={{ fontSize: 11.5 }}>
          {revokeBusy ? "Checking…" : "Check revocation (OCSP / CRL)"}
        </button>
        {revokeErr && <div style={{ fontSize: 12.5, color: "var(--red)", marginTop: 8 }}>{revokeErr}</div>}
        {revocation && (
          <div className="mono-list" style={{ marginTop: 10 }}>
            {(["ocsp", "crl"] as const).map((kind) => {
              const probe = revocation[kind];
              return (
                <div key={kind} className="spread" style={{ fontSize: 12.5, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
                  <span className="mono">{kind.toUpperCase()}</span>
                  <span className="row" style={{ gap: 6 }}>
                    <Badge tone={probe.status ? (String(probe.status).toUpperCase().includes("REVOK") ? "red" : "green") : ""}>
                      {probe.status ? String(probe.status).toUpperCase() : "UNDETERMINED"}
                    </Badge>
                    {probe.method && <span className="dim" style={{ fontSize: 11.5 }}>{probe.method}</span>}
                  </span>
                </div>
              );
            })}
            <div className="dim" style={{ fontSize: 11.5, marginTop: 6 }}>
              The offline parse reports what the certificate's own AIA URLs allow — absent URLs
              mean UNDETERMINED, never "good". Checked at is recorded even then.
            </div>
          </div>
        )}
      </Panel>

      <Panel title="Ownership" sub="assign a direct owner + technical contact (audited)" frame className="mt">
        <div className="tree" style={{ marginBottom: 10 }}>
          current owner: <span className="hl">{cert.owner || "— none assigned —"}</span><br />
          technical contact: {cert.technical_contact || "—"}
        </div>
        <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
          <input className="inp" style={{ maxWidth: 200 }} placeholder="owner" value={owner} onChange={(e) => setOwner(e.target.value)} />
          <input className="inp" style={{ maxWidth: 220 }} placeholder="technical contact" value={contact} onChange={(e) => setContact(e.target.value)} />
        </div>
        <input className="inp" style={{ marginTop: 8, width: "100%" }} placeholder="reason (mandatory — the assignment is audited)" value={reason} onChange={(e) => setReason(e.target.value)} />
        <button className="btn sm primary" disabled={ownBusy} onClick={() => void assignOwnership()} style={{ fontSize: 11.5, marginTop: 8 }}>
          {ownBusy ? "Assigning…" : "Assign ownership"}
        </button>
        {ownMsg && (
          <div style={{ fontSize: 12.5, marginTop: 8, color: ownMsg.ok ? "var(--green)" : "var(--amber)" }}>
            {ownMsg.text}
          </div>
        )}
      </Panel>

      <Panel title="Tasks & verification" sub="what can and cannot be linked" frame className="mt">
        <div className="dim" style={{ fontSize: 12 }}>
          Remediation tasks bind to evidence records (scan findings); a certificate is not an
          evidence record, so no task linkage exists to show — none is invented. Revocation and
          expiry state above are the verifiable facts this row carries.
        </div>
      </Panel>
    </Drawer>
  );
}

const SLA_TIERS: { key: string; label: string; tone: "red" | "amber" | "cyan" | "green" | "" }[] = [
  { key: "expired", label: "Expired", tone: "red" },
  { key: "critical", label: "0–7 days", tone: "red" },
  { key: "warning", label: "8–30 days", tone: "amber" },
  { key: "scheduled", label: "31–90 days", tone: "cyan" },
  { key: "healthy", label: ">90 days", tone: "green" },
];

function ExpiryCalendarPanel() {
  const cal = usePollingApi(apiExpiryCalendar, 30000);
  useRealtimeRefresh(cal.run);
  const data = (cal.data ?? null) as ExpiryCalendar | null;
  if (!data) {
    return (
      <Panel title="Renewal SLA calendar" sub="deterministic day-based expiry buckets" className="mt">
        <div className="dim" style={{ fontSize: 13 }}>No expiry calendar yet — run a certificate scan to populate it.</div>
      </Panel>
    );
  }
  const actionable = data.actionable_count ?? 0;
  return (
    <Panel
      title="Renewal SLA calendar"
      sub={`${data.total_tracked} tracked · ${actionable} need action · deterministic day-based buckets`}
      className="mt"
    >
      <div className="grid cols-5" style={{ marginBottom: 16 }}>
        {SLA_TIERS.map((t) => (
          <div className="kpi" key={t.key}>
            <span className="k">{t.label}</span>
            <span className="v" style={{ color: `var(--${t.tone === "" ? "cyan" : t.tone})` }}>
              {data.counts?.[t.key] ?? 0}
            </span>
          </div>
        ))}
      </div>
      {SLA_TIERS.filter((t) => (data.buckets?.[t.key] ?? []).length > 0).map((t) => (
        <div key={t.key} style={{ marginBottom: 12 }}>
          <div className="dim mono" style={{ fontSize: 11, marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>
            {t.label} · {data.buckets[t.key].length}
          </div>
          {data.buckets[t.key].slice(0, 6).map((e) => (
            <div key={e.fingerprint_sha256 ?? e.subject} className="spread" style={{ fontSize: 13 }}>
              <span className="mono">{e.subject ?? "unknown"}</span>
              <span className="dim mono">
                {e.days_until_expiry === null ? "no expiry" : `${e.days_until_expiry} days`}
                {e.renewal_ticket ? ` · ticket ${e.renewal_ticket}` : ""}
              </span>
            </div>
          ))}
        </div>
      ))}
    </Panel>
  );
}

type Issued = { fingerprint: string; cn: string; not_after?: string; serial?: string; pem: string; status: string };

function CertLifecyclePanel() {
  const queue = usePollingApi(apiCertRenewalQueue, 20000);
  useRealtimeRefresh(queue.run);
  const [cn, setCn] = useState("");
  const [san, setSan] = useState("");
  const [days, setDays] = useState(365);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [issued, setIssued] = useState<Issued[]>([]);
  const [showPem, setShowPem] = useState<string | null>(null);

  const sans = san.split(",").map((s) => s.trim()).filter(Boolean);
  const input: React.CSSProperties = { flex: 1, minWidth: 150, background: "color-mix(in srgb, var(--bg) 80%, transparent)", border: "1px solid var(--line-strong)", borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "8px 12px" };

  const genCsr = async () => {
    if (!cn.trim()) { setMsg({ ok: false, text: "common name (CN) is required" }); return; }
    setBusy(true);
    const r = await apiCertCsr({ subject: { CN: cn.trim(), O: "" }, ...(sans.length ? { san: sans } : {}) });
    setBusy(false);
    if (r.ok) { setMsg({ ok: true, text: `CSR generated for ${cn}` }); setShowPem(r.data?.csr_pem ?? ""); }
    else setMsg({ ok: false, text: r.error ?? "CSR generation failed" });
  };

  const issue = async () => {
    if (!cn.trim()) { setMsg({ ok: false, text: "common name (CN) is required" }); return; }
    setBusy(true);
    const r = await apiCertIssue({ subject: { CN: cn.trim() }, ...(sans.length ? { san: sans } : {}), validity_days: days, signed_by_ca: false });
    setBusy(false);
    if (r.ok) {
      const d = r.data;
      const fp: string = d.fingerprint_sha256 ?? d.fingerprint;
      setIssued((p) => [{ fingerprint: fp, cn, not_after: d.not_after, serial: d.serial_number, pem: d.certificate_pem, status: "ISSUED" }, ...p]);
      setMsg({ ok: true, text: `issued ${cn} · fp ${fp.slice(0, 16)}… · valid to ${(d.not_after ?? "").replace("T", " ").slice(0, 10)}` });
      queue.run();
    } else setMsg({ ok: false, text: r.error ?? "issuance failed" });
  };

  const renew = async (fp: string) => {
    const r = await apiCertRenew(fp, { validity_days: days, rotate_key: true });
    if (r.ok) {
      setIssued((p) => p.map((c) => c.fingerprint === fp ? { ...c, fingerprint: r.data.fingerprint_sha256 ?? fp, not_after: r.data.not_after, pem: r.data.certificate_pem, status: "RENEWED" } : c));
      setMsg({ ok: true, text: `renewed with rotated key · new fp ${(r.data.fingerprint_sha256 ?? "").slice(0, 16)}…` });
      queue.run();
    } else setMsg({ ok: false, text: r.error ?? "renew failed" });
  };

  const revoke = async (fp: string) => {
    const r = await apiCertRevoke(fp, "cessation_of_operation");
    if (r.ok) {
      setIssued((p) => p.map((c) => c.fingerprint === fp ? { ...c, status: r.data.revocation_status ?? "REVOKED" } : c));
      setMsg({ ok: true, text: `revoked · ${r.data.revocation_method ?? "CRL"}` });
      queue.run();
    } else setMsg({ ok: false, text: r.error ?? "revoke failed" });
  };

  const due = (queue.data as any)?.due ?? [];

  return (
    <Panel title="Certificate lifecycle" sub="issue · renew (key rotation) · revoke (CRL) — deterministic local PKI" className="mt">
      <div className="row" style={{ flexWrap: "wrap", gap: 10, marginBottom: 10 }}>
        <input style={input} placeholder="common name (e.g. tls.payments.example.invalid)" value={cn} onChange={(e) => setCn(e.target.value)} />
        <input style={input} placeholder="SAN hostnames (comma-separated)" value={san} onChange={(e) => setSan(e.target.value)} />
        <label style={{ fontSize: 12.5, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 2 }}>
          validity (days)
          <input type="number" min={1} max={3998} style={{ ...input, minWidth: 120 }} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        </label>
        <button className="btn sm" onClick={() => void genCsr()} disabled={busy}>{busy ? "…" : "Generate CSR"}</button>
        <button className="btn primary" onClick={() => void issue()} disabled={busy}>{busy ? "Issuing…" : "Issue certificate"}</button>
      </div>
      {msg && <div style={{ marginBottom: 10 }}><Badge tone={msg.ok ? "green" : "red"}>{msg.ok ? <StatusMark ok muted /> : null}{msg.text}</Badge></div>}

      {due.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <div className="dim mono" style={{ fontSize: 11.5, marginBottom: 6, textTransform: "uppercase" }}>Renewal queue · {due.length} due (lead {(queue.data as any)?.lead_days ?? 30}d)</div>
          {due.slice(0, 6).map((e: any) => (
            <div key={e.fingerprint_sha256 ?? e.subject} className="spread" style={{ fontSize: 12.5 }}>
              <span className="mono">{e.subject ?? "unknown"}</span>
              <span className="dim mono">{e.days_until_expiry === null ? "no expiry" : `${e.days_until_expiry} days`}</span>
            </div>
          ))}
        </div>
      )}

      <Table
        head={["common name", "valid to", "status", "actions"]}
        rows={issued.map((c) => [
          <span className="mono" style={{ fontWeight: 600 }} key="cn">{c.cn}</span>,
          <span className="mono" key="v" style={{ fontSize: 12 }}>{(c.not_after ?? "").replace("T", " ").slice(0, 10) || "—"}</span>,
          <Badge key="s" tone={c.status === "REVOKED" ? "red" : c.status === "RENEWED" ? "cyan" : "green"}>{c.status}</Badge>,
          <span key="a" className="row" style={{ gap: 6 }}>
            <button className="btn sm" onClick={() => setShowPem(c.pem)}>view PEM</button>
            {c.status !== "REVOKED" && <button className="btn sm" onClick={() => void renew(c.fingerprint)}>renew</button>}
            {c.status !== "REVOKED" && <button className="btn sm" style={{ borderColor: "var(--red)", color: "var(--red)" }} onClick={() => void revoke(c.fingerprint)}>revoke</button>}
          </span>,
        ])}
      />
      {issued.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No certificates issued in this session. Issue a leaf above; renewed/revoked certs stay here for the session.</p>}

      {showPem && (
        <div style={{ marginTop: 12 }}>
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
            <span className="dim mono" style={{ fontSize: 11.5 }}>PEM</span>
            <button className="btn sm" onClick={() => setShowPem(null)}>close</button>
          </div>
          <Code>{showPem}</Code>
        </div>
      )}
    </Panel>
  );
}

export default function Certificates() {
  const [sel, setSel] = useState<number | null>(null);
  const inv = usePollingApi(apiLiveInventory, 8000);
  useRealtimeRefresh(inv.run);
  const live = inv.source === "live";
  const data = (inv.data ?? null) as LiveInventory | null;
  const certs: CertRow[] = (data?.certificates ?? []).map((c) => ({ ...c, sanCount: c.san === "—" ? 0 : c.san.split(",").length }));
  const center = data?.cert_center ?? { expired: 0, expiring30: 0, weak_algorithm: 0, unknown_owner: 0, total: 0 };
  const detail = sel !== null ? certs[sel] : null;

  // the persisted estate (round 74) — the durable inventory, distinct
  // from the live observation run above
  const [estateSel, setEstateSel] = useState<number | null>(null);
  const estate = usePollingApi(apiCertificateEstate, 15000);
  const estateRows = estate.data?.certificates ?? [];
  const unknownOwner = estateRows.filter((c) => !c.owner).length;
  const estateDetail = estateSel !== null ? (estateRows[estateSel] ?? null) : null;

  return (
    <>
      <PageHead
        crumb="inventory / certificates"
        title="Certificates"
        sub="Expiration · chains · signature · key size — observed live on TLS endpoints"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={certs.length ? "cyan" : ""}><span className="dot" /> {certs.length.toLocaleString()} CERTIFICATES</Badge>
          </>
        }
      />
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["expired", center.expired, "red"],
          ["expiring <30d", center.expiring30, "amber"],
          ["weak signature", center.weak_algorithm, "red"],
          ["total", center.total, "cyan"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={k as string}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{v}</span>
          </div>
        ))}
      </div>
      <Panel title="Certificate inventory" sub="from live TLS scans — click a row to inspect the chain">
        <Table
          clickable
          selected={sel ?? -1}
          onSelect={setSel}
          head={["common name", "signature", "key", "days left", "SAN", "EKU", "issuer / endpoint", "status"]}
          rows={certs.map((c) => [
            <span className="mono" style={{ fontWeight: 600 }}>{c.cn}</span>,
            c.sig,
            <span className="num">{c.key}</span>,
            <span className="num">{c.days ?? "—"}</span>,
            <span title={c.san}>{(c.sanCount ?? 0) || "—"}</span>,
            <span style={{ fontSize: 12 }}>{c.eku}</span>,
            <span style={{ fontSize: 12 }}>{c.owner}<br /><span className="dim mono">{c.endpoint}</span></span>,
            <Badge tone={certTone(c.status)}>{c.status}</Badge>,
          ])}
        />
        {!certs.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No certificates yet — run a live network scan with a host:port target in Operations → Realtime scanners.
          </div>
        )}
      </Panel>
      {detail && <CertDrawer cert={detail} onClose={() => setSel(null)} />}
      {estateDetail && <EstateCertDrawer cert={estateDetail} onClose={() => setEstateSel(null)} />}
      <Panel
        title="Persisted certificate estate"
        sub="certificates deduped by SHA-256 fingerprint — the durable inventory with owner, usages and revocation state"
        className="mt"
      >
        <div className="row" style={{ gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
          {estate.source === "live" && <LiveBadge source="live" label="LIVE" />}
          <Badge tone={estateRows.length ? "cyan" : ""}>
            <span className="dot" /> {estateRows.length.toLocaleString()} ESTATE ROWS
          </Badge>
          <Badge tone={unknownOwner ? "amber" : "green"}>{unknownOwner} UNKNOWN OWNER</Badge>
        </div>
        <Table
          clickable
          selected={estateSel ?? -1}
          onSelect={setEstateSel}
          head={["subject", "issuer", "key", "days left", "owner", "revocation", "renewal"]}
          rows={estateRows.map((c) => [
            <span className="mono" style={{ fontWeight: 600 }}>{c.subject || c.fingerprint_sha256.slice(0, 16)}</span>,
            <span style={{ fontSize: 12 }}>{c.issuer || "—"}</span>,
            <span className="num">{c.public_key_algorithm || "—"}{c.public_key_size ? ` ${c.public_key_size}` : ""}</span>,
            <span className="num">{c.days_until_expiry ?? "—"}</span>,
            c.owner
              ? <span style={{ fontSize: 12 }}>{c.owner}</span>
              : <Badge tone="amber">UNKNOWN</Badge>,
            <Badge tone={String(c.revocation_status || "").toUpperCase().includes("REVOK") ? "red" : ""}>
              {c.revocation_status ? String(c.revocation_status).toUpperCase() : "UNCHECKED"}
            </Badge>,
            <span style={{ fontSize: 12 }}>{c.renewal_status || "NONE"}</span>,
          ])}
        />
        {!estateRows.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {estate.source === "live"
              ? "The persisted estate is empty — certificates land here when scans or CT monitoring store them (deduped by fingerprint)."
              : "Estate unavailable — the durable inventory could not be loaded."}
          </div>
        )}
        <div className="dim" style={{ fontSize: 12, marginTop: 8 }}>
          Distinct from the live panel above: this is the whole persisted estate (every stored
          certificate), not one scan-run's observation. UNKNOWN owner is a fact, not an
          inference — assign one from the row.
        </div>
      </Panel>
      <CertLifecyclePanel />
      <ExpiryCalendarPanel />
    </>
  );
}
