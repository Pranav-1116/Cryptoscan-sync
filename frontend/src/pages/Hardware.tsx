import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiLiveInventory, LiveInventory } from "../lib/api.js";

/* Hardware — real, live data from the hardware scanner (CPU/TPM/HSM/smart
   card) via GET /api/v1/live-scan/inventory. Empty until a live scan runs. */

export default function Hardware() {
  const inv = usePollingApi(apiLiveInventory, 8000);
  const data = (inv.data ?? null) as LiveInventory | null;
  const devices = data?.hardware ?? [];
  const firmware = data?.firmware ?? [];
  const live = inv.source === "live";

  return (
    <>
      <PageHead
        crumb="discovery / hardware"
        title="Hardware"
        sub="CPU · TPM · HSM · secure elements · crypto accelerators · firmware (live hardware scanner)"
        right={
          <>
            {live && <LiveBadge source="live" label={data?.generated_at ? `LIVE · ${new Date(data.generated_at).toLocaleTimeString()}` : "LIVE"} />}
            <Badge tone={devices.length ? "green" : ""}><span className="dot" /> {devices.length.toLocaleString()} DEVICES</Badge>
          </>
        }
      />
      <Panel title="CPU · TPM · HSM · secure elements" sub="capabilities and firmware from the live hardware scan">
        <Table
          head={["id", "type", "vendor", "firmware", "capabilities", "host", "status"]}
          rows={devices.map((h) => [
            <span className="mono">{h.id}</span>,
            <Badge tone="violet">{h.type}</Badge>,
            h.vendor || "—",
            <span className="num">{h.firmware}</span>,
            <span className="row">{h.caps.map((c) => <Badge key={c}>{c}</Badge>)}</span>,
            <span className="mono">{h.host}</span>,
            <Badge tone={h.status.startsWith("middleware") ? "amber" : "green"}>{h.status}</Badge>,
          ])}
        />
        {!devices.length && (
          <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
            No hardware data yet — run a live scan in Operations → Realtime scanners.
          </div>
        )}
      </Panel>
      <Panel title="Firmware vs baseline" sub="CPU microcode and TPM firmware" className="mt">
        <Table
          head={["device", "kind", "version", "status"]}
          rows={firmware.map((f) => [
            <span className="mono">{f.device}</span>,
            f.kind,
            <span className="num">{f.version}</span>,
            f.status.startsWith("DRIFT") ? <Badge tone="red">{f.status}</Badge> : <Badge tone="green">{f.status}</Badge>,
          ])}
        />
      </Panel>
      <Panel title="Hardware timeline" sub="every change is evidence-linked" className="mt">
        {firmware.length ? (
          <div className="timeline">
            {firmware.slice(0, 8).map((f, i) => (
              <div className="tl" key={`${f.device}-${i}`}>
                <span className="dim" style={{ fontSize: 13 }}>{f.kind} {f.version} — {f.device} · {f.status}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>
            No hardware events yet — CPU/TPM/HSM discoveries and firmware changes appear here after a live scan.
          </div>
        )}
      </Panel>
    </>
  );
}
