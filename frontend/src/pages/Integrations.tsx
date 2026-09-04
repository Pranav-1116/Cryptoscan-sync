import React, { useState } from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import { integrations as configuredIntegrations } from "../data/initial.js";
import {
  apiIntegrations, apiDeliveries, apiTestIntegration, apiFlushDeliveries,
  LiveBadge,
} from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";

const KIND_TONE: Record<string, string> = { siem: "cyan", itsm: "violet", cmdb: "amber", soar: "green" };

function statusTone(status: string): "green" | "red" | "amber" | "cyan" {
  if (status === "delivered" || status === "resolved") return "green";
  if (status === "failed") return "red";
  return "amber";
}

export default function Integrations() {
  const ints = usePollingApi(apiIntegrations, 12000);
  const deliv = usePollingApi(apiDeliveries, 12000);
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const liveInts = (ints.data?.integrations ?? []) as Array<Record<string, unknown>>;
  const deliveries = (deliv.data?.deliveries ?? []) as Array<Record<string, unknown>>;
  const stats = (deliv.data?.stats ?? {}) as Record<string, number>;
  const live = ints.source === "live";

  async function test(id: string) {
    setBusy(id);
    setMsg(null);
    const r = await apiTestIntegration(id);
    setBusy(null);
    if (r.ok) {
      setMsg(`Delivery test: ${r.status} (HTTP ${r.http_status ?? "—"})`);
      void deliv.run();
      void ints.run();
    } else {
      setMsg(`Test failed: ${r.error}`);
    }
  }

  async function flush() {
    setBusy("flush");
    const r = await apiFlushDeliveries(25);
    setBusy(null);
    setMsg(r.ok ? `Flushed ${r.events_flushed} events · ${r.delivered} delivered · ${r.failed} failed`
               : `Flush failed: ${r.error}`);
    void deliv.run();
  }

  const rows = live
    ? liveInts.map((i) => {
        const id = String(i.id);
        const lastSync = String(i.last_sync_status ?? "—");
        return [
          <span style={{ fontWeight: 600 }}>{String(i.name)}</span>,
          <Badge tone={KIND_TONE[String(i.kind)] || "cyan"}>{String(i.kind)}</Badge>,
          <Badge tone={statusTone(lastSync)}>{lastSync}</Badge>,
          <span style={{ fontSize: 12.5 }} className="dim">
            {i.endpoint ? String(i.endpoint) : "outbox only (air-gap)"}
          </span>,
          <button className="btn" style={{ padding: "4px 10px", fontSize: 12 }}
                  disabled={busy === id} onClick={() => void test(id)}>
            {busy === id ? "…" : "Test"}
          </button>,
        ];
      })
    : configuredIntegrations.map((i) => [
        <span style={{ fontWeight: 600 }}>{i.name}</span>,
        <Badge tone="cyan">{i.kind}</Badge>,
        <Badge tone="green">{i.status}</Badge>,
        <span style={{ fontSize: 12.5 }} className="dim">{i.detail}</span>,
        <span className="dim" style={{ fontSize: 12 }}>configured</span>,
      ]);

  return (
    <>
      <PageHead
        crumb="operate / integrations"
        title="Integrations"
        sub="Real signed HTTP fan-out to SIEM / SOC, ticketing (ITSM) and CMDB — every attempt audited"
        right={
          <div className="row">
            <LiveBadge source={live ? "live" : "offline"} label={live ? "LIVE PLATFORM" : "BACKEND OFFLINE"} />
            {live && <Badge tone="violet"><span className="dot" /> {liveInts.length} REGISTERED</Badge>}
          </div>
        }
      />

      <Panel title="Connected systems" sub="SIEM / ITSM / CMDB / SOAR — endpoint URL is non-secret; credentials resolve from the vault at delivery time">
        <Table
          head={["integration", "kind", "last delivery", "endpoint", ""]}
          rows={rows}
        />
        {rows.length === 0 && (
          <div className="dim" style={{ fontSize: 13, marginTop: 12 }}>
            No integrations registered yet. Connect a SIEM/SOC, ticketing (ITSM), CMDB or webhook
            destination below; credentials are referenced from the vault, never stored.
          </div>
        )}
        {live && (
          <div className="row" style={{ marginTop: 12, gap: 10 }}>
            <button className="btn primary" disabled={busy === "flush"} onClick={() => void flush()}>
              {busy === "flush" ? "Flushing…" : "Flush outbox now (real delivery)"}
            </button>
            {msg && <span className="dim" style={{ fontSize: 12.5 }}>{msg}</span>}
          </div>
        )}
      </Panel>

      {live && (
        <Panel title="Outbound delivery log" sub="cp_delivery_logs — real HTTP POST results to external systems" className="mt">
          <div className="row" style={{ gap: 8, marginBottom: 12 }}>
            <Badge tone="green">{stats.delivered ?? 0} DELIVERED</Badge>
            <Badge tone="red">{stats.failed ?? 0} FAILED</Badge>
            <Badge tone="amber">{stats.skipped ?? 0} SKIPPED (air-gap/outbox)</Badge>
          </div>
          <Table
            head={["time", "provider", "kind", "event", "status", "HTTP", "attempts"]}
            rows={deliveries.slice(0, 20).map((d) => [
              <span className="mono faint" style={{ fontSize: 11.5 }}>{String(d.created_at ?? "").slice(11, 19)}</span>,
              <span style={{ fontWeight: 600 }}>{String(d.provider)}</span>,
              String(d.kind),
              <span className="mono" style={{ fontSize: 11.5 }}>{String(d.event_type)}</span>,
              <Badge tone={statusTone(String(d.status))}>{String(d.status)}</Badge>,
              d.http_status != null ? String(d.http_status) : <span className="faint">—</span>,
              String(d.attempts ?? 0),
            ])}
          />
        </Panel>
      )}
    </>
  );
}
