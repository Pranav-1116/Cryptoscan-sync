import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer, Code } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import {
  apiLiveInventory,
  apiExpiryCalendar,
  apiCertCsr,
  apiCertIssue,
  apiCertRenew,
  apiCertRevoke,
  apiCertRenewalQueue,
  LiveCertificate,
  LiveInventory,
  ExpiryCalendar,
} from "../lib/api.js";

/* Certificates — live certificate inventory observed on TLS endpoints by the
   network scanner via GET /api/v1/live-scan/inventory. Empty until a network
   scan runs. */

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
      <Panel title="Evidence" sub="linked artifacts" frame className="mt">
        <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
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
  const [cn, setCn] = useState("");
  const [san, setSan] = useState("");
  const [days, setDays] = useState(365);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [issued, setIssued] = useState<Issued[]>([]);
  const [showPem, setShowPem] = useState<string | null>(null);

  const sans = san.split(",").map((s) => s.trim()).filter(Boolean);
  const input: React.CSSProperties = { flex: 1, minWidth: 150, background: "rgba(8,12,24,0.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 13, padding: "8px 12px" };

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
    <Panel title="Certificate lifecycle" sub="issue · renew (key rotation) · revoke (CRL) — deterministic local PKI, no AI" className="mt">
      <div className="row" style={{ flexWrap: "wrap", gap: 10, marginBottom: 10 }}>
        <input style={input} placeholder="common name (e.g. tls.payments.demo.local)" value={cn} onChange={(e) => setCn(e.target.value)} />
        <input style={input} placeholder="SAN hostnames (comma-separated)" value={san} onChange={(e) => setSan(e.target.value)} />
        <label style={{ fontSize: 12.5, color: "var(--dim)", display: "flex", flexDirection: "column", gap: 2 }}>
          validity (days)
          <input type="number" min={1} max={3998} style={{ ...input, minWidth: 120 }} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        </label>
        <button className="btn sm" onClick={() => void genCsr()} disabled={busy}>{busy ? "…" : "Generate CSR"}</button>
        <button className="btn primary" onClick={() => void issue()} disabled={busy}>{busy ? "Issuing…" : "Issue certificate"}</button>
      </div>
      {msg && <div style={{ marginBottom: 10 }}><Badge tone={msg.ok ? "green" : "red"}>{msg.ok ? "✓ " : ""}{msg.text}</Badge></div>}

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
  const live = inv.source === "live";
  const data = (inv.data ?? null) as LiveInventory | null;
  const certs: CertRow[] = (data?.certificates ?? []).map((c) => ({ ...c, sanCount: c.san === "—" ? 0 : c.san.split(",").length }));
  const center = data?.cert_center ?? { expired: 0, expiring30: 0, weak_algorithm: 0, unknown_owner: 0, total: 0 };
  const detail = sel !== null ? certs[sel] : null;

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
      <CertLifecyclePanel />
      <ExpiryCalendarPanel />
    </>
  );
}
