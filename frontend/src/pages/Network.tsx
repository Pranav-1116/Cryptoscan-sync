import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Drawer } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiLiveInventory, LiveNetworkAsset } from "../lib/api.js";

/* Network — live TLS endpoints from the network scanner via
   GET /api/v1/live-scan/inventory. Topology/subnet views populate from subnet
   discovery; TLS endpoint posture populates from a live network scan. */

const TOPO: { id: string; label: string; x: number; y: number; kind: string }[] = [];

function statusTone(status: string): "green" | "red" | "amber" | "" {
  if (status === "OK") return "green";
  if (/REFUSED|FAILED|EXPIRED|CLOSED|TIMEOUT/.test(status)) return "red";
  if (status && status !== "discovered" && status !== "open") return "amber";
  return "";
}

export default function Network() {
  const [sel, setSel] = useState<string | null>(null);
  const inv = usePollingApi(apiLiveInventory, 8000);
  const live = inv.source === "live";
  const assets: LiveNetworkAsset[] = (inv.data as { network?: LiveNetworkAsset[] } | null)?.network ?? [];
  const detail = assets.find((n) => n.id === sel);

  const tlsEndpoints = assets.filter((n) => n.kind === "tls_endpoint");
  const withIssues = tlsEndpoints.filter((n) => n.status !== "OK").length;
  const chainValid = tlsEndpoints.filter((n) => n.chain_valid === true).length;
  const discovered = assets.filter((n) => n.kind === "discovered").length;
  const c = {
    endpoints: tlsEndpoints.length,
    policyIssues: withIssues,
    chainValid,
    discovered,
  };

  return (
    <>
      <PageHead
        crumb="discovery / network"
        title="Network"
        sub="Live TLS endpoint posture — versions, ciphers, certificates, chain validity (network scanner)"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={assets.length ? "green" : ""}><span className="dot" /> {assets.length} ENDPOINTS</Badge>
          </>
        }
      />
      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["TLS endpoints", c.endpoints], ["with policy issues", c.policyIssues], ["valid chain", c.chainValid], ["discovered (open)", c.discovered]].map(([k, v]) => (
          <div className="kpi" key={k as string}><span className="k">{k}</span>
            <span className="v" style={{ color: k === "with policy issues" && Number(v) ? "var(--red,#d36a6a)" : undefined }}>{v}</span>
          </div>
        ))}
      </div>

      {TOPO.length > 0 && (
        <Panel title="Network topology" sub="click any node for detail">
          <div className="graphwrap">
            <svg viewBox="0 0 800 500" width="100%" style={{ minWidth: 680 }}>
              {TOPO.slice(0, -1).map((node, i) => {
                const next = TOPO[i + 1];
                if (!next) return null;
                return <path key={`${node.id}-${next.id}`} className="edge" d={`M${node.x} ${node.y + 26} L${next.x} ${next.y - 26}`} />;
              })}
              {TOPO.map((t) => (
                <g key={t.id} className={`gnode ${sel === t.id ? "sel" : ""}`} onClick={() => setSel(sel === t.id ? null : t.id)}>
                  <rect x={t.x - 80} y={t.y} width="160" height="52" />
                  <text x={t.x} y={t.y + 21} textAnchor="middle" style={{ fontWeight: 600 }}>{t.label}</text>
                  <text x={t.x} y={t.y + 36} textAnchor="middle" className="gsub">{t.id}</text>
                </g>
              ))}
            </svg>
          </div>
        </Panel>
      )}

      <Panel title="TLS endpoints" sub="version · cipher · certificate · chain · policy posture (live scan)" className={TOPO.length ? "mt" : ""}>
        <Table
          head={["kind", "id", "ip", "tls / cipher", "certificate", "chain", "status"]}
          rows={assets.map((n) => [
            <Badge tone="cyan">{n.kind}</Badge>,
            <span className="mono">{n.id}</span>,
            <span className="num">{n.ip}</span>,
            n.tls,
            n.certs.length ? n.certs.join(", ") : <span className="faint">—</span>,
            n.chain_valid === undefined ? <span className="faint">—</span>
              : n.chain_valid ? <Badge tone="green">valid</Badge> : <Badge tone="red">invalid</Badge>,
            <Badge tone={statusTone(n.status)}>
              {n.status}{n.cert_expiry_days != null ? ` · ${n.cert_expiry_days}d` : ""}
            </Badge>,
          ])}
        />
        {!assets.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No network data yet — run a live network scan (set a host:port target) in Operations → Realtime scanners.
          </div>
        )}
      </Panel>

      {detail && (
        <Drawer title={detail.id} sub={`${detail.kind} · ${detail.ip}`} onClose={() => setSel(null)}>
          <div className="row" style={{ marginBottom: 16 }}>
            <Badge tone="cyan">{detail.kind}</Badge>
            <Badge tone={statusTone(detail.status)}>{detail.status}</Badge>
            {detail.cert_expiry_days != null && <Badge>cert {detail.cert_expiry_days}d</Badge>}
          </div>
          <div className="tree" style={{ marginBottom: 16 }}>
            Crypto posture:<br />
            {" └── "}{detail.tls}
          </div>
          <Panel title="Certificates" sub="served by this endpoint" frame>
            {detail.certs.length ? detail.certs.map((c) => <Badge key={c} tone="cyan">{c}</Badge>) : <span className="faint" style={{ fontSize: 13 }}>none observed</span>}
          </Panel>
          <Panel title="Evidence" sub="linked artifacts" frame className="mt">
            <a href="#/evidence" className="mono" style={{ fontSize: 12 }}>open evidence chain →</a>
          </Panel>
        </Drawer>
      )}
    </>
  );
}
