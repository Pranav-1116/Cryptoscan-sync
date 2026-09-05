import React, { useState } from "react";
import { Panel, Badge, Table, Bar, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiLiveInventory, LiveCertificate, LiveInventory } from "../lib/api.js";

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
      <Panel title="Expiration calendar" sub="certificate lifetimes from the live inventory" className="mt">
        {certs.length ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {certs.slice(0, 10).map((c) => (
              <div key={`${c.cn}-${c.endpoint}-${c.chain_position}`} className="spread" style={{ fontSize: 13 }}>
                <span className="mono">{c.cn} <span className="dim">({c.endpoint})</span></span>
                <div style={{ flex: 1, maxWidth: 320 }}>
                  <Bar value={Math.max(0, Math.min(1, (c.days ?? 0) / 365))} tone={(c.days ?? 0) < 30 ? "red" : (c.days ?? 0) < 90 ? "amber" : "green"} />
                </div>
                <span className="mono">{c.days ?? "—"} days</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>No certificates discovered yet — run a network scan to populate the expiration calendar.</div>
        )}
      </Panel>
    </>
  );
}
