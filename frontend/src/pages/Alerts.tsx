import React, { useMemo, useState } from "react";
import { Badge, PageHead, Table, Panel } from "../components/ui.jsx";
import { usePollingApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiLiveAlerts, LiveAlert, LiveAlertsResponse } from "../lib/api.js";

/* Alerts — deterministic, cross-scanner risk aggregation from the live scans
   (GET /api/v1/live-scan/alerts), plus a strip of the most recent high-severity
   SSE events. Empty until scans produce findings. No static/seed data. */

interface AlertRow {
  id: string;
  severity: string;
  scanner: string;
  title: string;
  detail: string;
  asset: string;
}

const SEV_TONE: Record<string, "red" | "amber" | "cyan" | "green" | ""> = {
  CRITICAL: "red",
  HIGH: "red",
  MEDIUM: "amber",
  LOW: "cyan",
};

export default function Alerts() {
  const [filter, setFilter] = useState("all");
  const [acked, setAcked] = useState<Set<string>>(new Set());
  const res = usePollingApi(apiLiveAlerts, 6000);
  const live = res.source === "live";
  const data = (res.data ?? null) as LiveAlertsResponse | null;
  const counts = data?.counts ?? {};

  const rows: AlertRow[] = useMemo(
    () =>
      (data?.alerts ?? []).map((a: LiveAlert, i) => ({
        id: `${a.scanner}-${a.kind}-${a.asset}-${i}`,
        severity: a.severity,
        scanner: a.scanner,
        title: a.title,
        detail: a.detail,
        asset: a.asset,
      })),
    [data],
  );

  const visible = rows
    .filter((r) => (filter === "all" ? true : r.severity === filter.toUpperCase()))
    .filter((r) => !acked.has(r.id));

  return (
    <>
      <PageHead
        crumb="post-quantum / alerts"
        title="Alerts"
        sub="Cross-scanner risk aggregation — weak/EOL libraries, weak TLS & ciphers, certificate expiry/signature, chain failures, hardware root-of-trust, static findings"
        right={
          <div className="row">
            {live && <LiveBadge source="live" label="LIVE" />}
            <Badge tone="red">{visible.length} UNACKED</Badge>
          </div>
        }
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[["CRITICAL", counts.CRITICAL ?? 0, "red"], ["HIGH", counts.HIGH ?? 0, "red"],
          ["MEDIUM", counts.MEDIUM ?? 0, "amber"], ["LOW", counts.LOW ?? 0, "cyan"]].map(([k, v, tone]) => (
          <div className="kpi" key={k as string}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{v as number}</span>
          </div>
        ))}
      </div>

      <div className="tabs">
        {["all", "critical", "high", "medium", "low"].map((t) => (
          <button key={t} className={filter === t ? "active" : ""} onClick={() => setFilter(t)}>{t}</button>
        ))}
      </div>

      {live && visible.length === 0 && (
        <div className="dim" style={{ padding: 30, textAlign: "center" }}>
          No unacked alerts in this view — run scans from Operations → Realtime scanners; findings aggregate here.
        </div>
      )}
      {!live && (
        <div className="dim" style={{ padding: 30, textAlign: "center" }}>
          Backend offline — start the control plane and run a scan to see risk alerts.
        </div>
      )}

      {visible.map((a) => (
        <div className={`alertcard ${a.severity.toLowerCase()}`} key={a.id}>
          <div>
            <div className="ttl">
              <Badge tone={SEV_TONE[a.severity]}>{a.severity}</Badge>
              <Badge>{a.scanner}</Badge> {a.title}
            </div>
            <div className="det">{a.detail}{a.asset ? <span className="dim mono"> · {a.asset}</span> : null}</div>
          </div>
          <button className="btn sm" onClick={() => setAcked((s) => new Set(s).add(a.id))}>ack</button>
        </div>
      ))}

      <Panel title="All findings" sub="sorted by severity" className="mt" >
        <Table
          head={["severity", "scanner", "finding", "detail", "asset", ""]}
          rows={rows.map((r) => [
            <Badge tone={SEV_TONE[r.severity]}>{r.severity}</Badge>,
            r.scanner,
            <span style={{ fontWeight: 600 }}>{r.title}</span>,
            <span style={{ fontSize: 12 }}>{r.detail}</span>,
            <span className="mono" style={{ fontSize: 12 }}>{r.asset || "—"}</span>,
            <button className="btn sm" onClick={() => setAcked((s) => new Set(s).add(r.id))}>ack</button>,
          ])}
        />
        {rows.length === 0 && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>No findings yet.</div>}
      </Panel>
    </>
  );
}
