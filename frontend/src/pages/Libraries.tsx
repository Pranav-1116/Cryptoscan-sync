import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import { apiLiveInventory, LiveLibrary } from "../lib/api.js";

/* Crypto libraries — live versions/status from the runtime scanner via
   GET /api/v1/live-scan/inventory. Empty until a live scan runs. */

const TONE: Record<string, "green" | "amber" | "red" | ""> = {
  ALLOWED: "green",
  UNKNOWN: "",
  DEPRECATED: "amber",
  DISALLOWED: "red",
  RESTRICTED: "red",
};

export default function Libraries() {
  const inv = usePollingApi(apiLiveInventory, 8000);
  useRealtimeRefresh(inv.run);
  const live = inv.source === "live";
  const libs: LiveLibrary[] = (inv.data as { libraries?: LiveLibrary[] } | null)?.libraries ?? [];

  return (
    <>
      <PageHead
        crumb="inventory / crypto libraries"
        title="Crypto libraries"
        sub="Library · version · source package · processes · verdict (live runtime scanner)"
        right={
          <>
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone={libs.length ? "cyan" : ""}><span className="dot" /> {libs.length.toLocaleString()} LIBRARIES</Badge>
          </>
        }
      />
      <Panel title="Library center" sub="unique TLS/crypto libraries detected across running processes">
        <Table
          head={["library", "version", "source package", "processes", "verdict"]}
          rows={libs.map((l) => [
            <span className="mono" style={{ fontWeight: 600 }}>{l.name}</span>,
            <span className="num">{l.version || "?"}</span>,
            l.package || <span className="faint">unmanaged / bundled</span>,
            <span className="num">{l.processes ?? 0}</span>,
            <Badge tone={TONE[l.status || ""] ?? ""}>{l.status || "UNKNOWN"}</Badge>,
          ])}
        />
        {!libs.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No library data yet — run a live scan in Operations → Realtime scanners.
          </div>
        )}
      </Panel>
    </>
  );
}
