import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { apiLiveBom, LiveBomResponse } from "../lib/api.js";

/* HBOM — Hardware Bill of Materials from the live hardware scanner via
   GET /api/v1/live-scan/bom. Empty until a live scan runs. */

export default function Hbom() {
  const res = usePollingApi(apiLiveBom, 8000);
  useRealtimeRefresh(res.run);
  const live = res.source === "live";
  const bom = (res.data ?? null) as LiveBomResponse | null;
  const devices = bom?.hbom.components ?? [];

  return (
    <>
      <PageHead
        crumb="boms / hbom"
        title="HBOM"
        sub="Hardware Bill of Materials — TPM · HSM · CPU crypto · secure elements · firmware · capability"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={devices.length ? "green" : ""}><span className="dot" /> {devices.length} COMPONENTS</Badge>
          </>
        }
      />
      <Panel title="Trusted hardware layer" sub="every crypto-capable hardware device from the live scan">
        <Table
          head={["type", "vendor / component", "firmware", "capabilities", "host"]}
          rows={devices.map((h) => [
            <Badge tone="violet">{h.type}</Badge>,
            <span className="mono" style={{ fontWeight: 600 }}>{h.name}</span>,
            <span className="num">{h.version || "—"}</span>,
            <span className="row">{(h.caps ?? []).map((c) => <Badge key={c}>{c}</Badge>)}</span>,
            <span className="mono">{h.ref}</span>,
          ])}
        />
        {!devices.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No HBOM yet — run a live hardware scan in Operations → Realtime scanners.
          </div>
        )}
      </Panel>
    </>
  );
}
