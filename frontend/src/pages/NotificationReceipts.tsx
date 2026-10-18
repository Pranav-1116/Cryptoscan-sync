import React, { useState } from "react";
import { Badge, Panel, Table } from "../components/ui.jsx";
import { useLive } from "../lib/useLive.js";
import type { NotificationReceiptPage, NotificationReceiptSummary } from "../lib/api.js";

const labels: Record<string, string> = {
  pending: "Pending", inflight: "In flight", delivered: "HTTP acknowledged",
  failed: "Failed", skipped: "Skipped", legacy_unknown: "Legacy outcome unknown",
};
const when = (value: string | null) => value ? new Date(value).toLocaleString() : "not recorded";

function ReceiptPage({ status, cursor, onNext }: { status: string; cursor: string | null; onNext: (cursor: string) => void }) {
  const params = new URLSearchParams({ limit: "25" });
  if (status) params.set("status", status);
  if (cursor) params.set("cursor", cursor);
  const page = useLive<NotificationReceiptPage | null>(`/api/v1/notifications/deliveries?${params}`, null);
  if (page.loading) return <p role="status">Loading receipt metadata…</p>;
  if (page.error || !page.data) return <p role="alert">Receipt ledger unavailable — not measured. No delivery conclusion can be drawn.</p>;
  return <>
    <Table head={["Receipt / event", "Destination / channel", "State", "Attempts / timing"]} rows={page.data.items.map((item) => [
      <span key="identity"><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{item.id}</span><br />Event: {item.event_id}<br />{item.event_class || "legacy event class unknown"}</span>,
      <span key="destination">{item.integration_id}<br />{item.channel}</span>,
      <span key="state"><Badge tone={item.status === "failed" || item.status === "skipped" || item.status === "legacy_unknown" ? "amber" : ""}>{labels[item.status] ?? item.status}</Badge>
        {item.http_status !== null && <span> · HTTP {item.http_status}</span>}
        {item.has_error && <div className="dim">Error recorded; details withheld</div>}</span>,
      <span key="timing">{item.attempt_count} claim(s)<br />Created: {when(item.created_at)}
        {item.next_attempt_at && <div>Retry eligible after: {when(item.next_attempt_at)}</div>}
        {item.lease_expires_at && <div>Claim expires: {when(item.lease_expires_at)}</div>}
        {item.delivered_at && <div>Acknowledged: {when(item.delivered_at)}</div>}
        {item.time_eligible && <div className="dim">Time-eligible; routing/destination may defer</div>}</span>,
    ])} />
    {!page.data.items.length && <p className="dim">No receipts match this view. This is not proof all events were delivered.</p>}
    {page.data.next_cursor && <button className="btn" onClick={() => onNext(page.data!.next_cursor!)}>Older receipts</button>}
  </>;
}

export default function NotificationReceipts() {
  const summary = useLive<NotificationReceiptSummary | null>("/api/v1/notifications/delivery-summary", null);
  const [status, setStatus] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const refresh = () => { setCursor(null); setRevision((n) => n + 1); summary.reload(); };
  return <Panel title="Durable delivery receipts" sub="read-only diagnostics — inspecting never sends or retries" className="mt">
    {summary.loading ? <p role="status">Loading receipt counts…</p> : summary.error || !summary.data ?
      <p role="alert">Receipt counts unavailable — not measured.</p> : <>
        <div className="row" aria-label="Receipt counts">
          <Badge>Total receipts: {summary.data.total}</Badge>
          <Badge tone={summary.data.pending ? "amber" : ""}>Pending receipts: {summary.data.pending}</Badge>
          <Badge>HTTP acknowledged: {summary.data.counts.delivered ?? 0}</Badge>
          <Badge tone={summary.data.counts.legacy_unknown ? "amber" : ""}>Legacy unknown: {summary.data.counts.legacy_unknown ?? 0}</Badge>
          <Badge>Time-eligible: {summary.data.time_eligible}</Badge>
          <Badge tone={summary.data.expired_claims ? "amber" : ""}>Expired claims: {summary.data.expired_claims}</Badge>
        </div>
        <p className="dim">Observed: {when(summary.data.observed_at)} · Oldest pending: {when(summary.data.oldest_pending_at)}</p>
      </>}
    <p className="dim">Counts are destination receipts, not unique events. Time eligibility does not override routing or destination settings. HTTP acknowledgement is not downstream ingestion or scheduler liveness; legacy unknown is not delivered. Payloads, endpoints, raw errors and claim credentials are withheld.</p>
    <div className="row" style={{ marginBottom: 10 }}>
      <label>Receipt state <select aria-label="Receipt status" value={status} onChange={(event) => { setStatus(event.target.value); setCursor(null); }}>
        <option value="">All receipt states</option>
        {Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      <button className="btn" onClick={refresh}>Refresh receipt view</button>
      {cursor && <button className="btn" onClick={() => setCursor(null)}>Newest receipts</button>}
    </div>
    {/* Remount the request on navigation: old-page rows must never masquerade
        as the newly selected filter/page while its request is in flight. */}
    <ReceiptPage key={`${status}:${cursor}:${revision}`} status={status} cursor={cursor} onNext={setCursor} />
    <p className="dim">Newest-created first. Counts and pages are separate observations, not a frozen snapshot; concurrent status changes may move receipts between filtered views. Unknown-history redrive is not offered here.</p>
  </Panel>;
}
