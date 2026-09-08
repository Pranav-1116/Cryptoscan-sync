import React, { useMemo } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { apiLiveInventory, LiveInventory } from "../lib/api.js";

/* Asset inventory — unified from the live scan inventory (hardware, network,
   libraries, processes). Zero demo data; empty until a live scan runs. */

interface AssetRow {
  id: string;
  type: string;
  name: string;
  env: string;
  region: string;
  owner: string;
  risk: string;
  evidence: number;
}

export default function Assets() {
  const inv = usePollingApi(apiLiveInventory, 9000);
  useRealtimeRefresh(inv.run);
  const live = inv.source === "live";
  const data: LiveInventory | null = inv.data ?? null;

  const rows: AssetRow[] = useMemo(() => {
    if (!data) return [];
    const out: AssetRow[] = [];
    const host = data.host ?? "host";
    for (const h of data.hardware ?? []) {
      out.push({ id: h.id, type: h.type, name: h.vendor || h.id, env: "runtime", region: host, owner: "—", risk: h.status, evidence: h.caps.length });
    }
    for (const n of data.network ?? []) {
      out.push({ id: n.ip, type: n.kind, name: n.id, env: "network", region: n.os || host, owner: "—", risk: n.status, evidence: n.certs.length });
    }
    for (const p of data.processes ?? []) {
      out.push({ id: String(p.pid ?? "—"), type: "process", name: p.process ?? "process", env: p.containerized ? "container" : "runtime", region: p.runtime ?? host, owner: "—", risk: p.status, evidence: p.tls_libraries.length });
    }
    return out;
  }, [data]);

  const riskTone = (r: string) =>
    /deprecat|weak|risk|vulnerab/i.test(r) ? "amber" : /critical|high|disallow/i.test(r) ? "red" : "green";

  return (
    <>
      <PageHead
        crumb="inventory / assets"
        title="Assets"
        sub="Hardware, network assets and processes discovered by the live scans — owner, host and risk"
        right={<><LiveBadge source={inv.source} /><Badge tone={live && rows.length ? "green" : ""}><span className="dot" /> {rows.length.toLocaleString()} TOTAL</Badge></>}
      />
      <Panel title="Asset inventory" sub={rows.length ? "unified from live hardware + network + runtime scans" : "no assets yet — run a live scan to populate the estate"}>
        <Table
          head={["asset id", "type", "name", "env", "host/runtime", "owner", "risk", "evidence"]}
          rows={rows.map((a) => [
            <span className="mono">{a.id}</span>,
            <Badge tone="cyan">{a.type}</Badge>,
            <span className="mono">{a.name}</span>,
            a.env,
            a.region,
            a.owner,
            <Badge tone={riskTone(a.risk)}>{a.risk}</Badge>,
            <span className="num">{a.evidence}</span>,
          ])}
        />
        {!rows.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            {live ? "No assets discovered yet — start a scan in Operations → Realtime scanners." : "Backend offline — asset inventory unavailable."}
            <br /><a href="#/live-scanners" className="mono" style={{ fontSize: 12 }}>open realtime scanners →</a>
          </div>
        )}
      </Panel>
    </>
  );
}
