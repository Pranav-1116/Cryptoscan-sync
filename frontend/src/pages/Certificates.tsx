import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import {
  apiLiveInventory,
  apiExpiryCalendar,
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
      <ExpiryCalendarPanel />
    </>
  );
}
