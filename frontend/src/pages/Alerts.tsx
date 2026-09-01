import React, { useState } from "react";
import { Badge, PageHead } from "../components/ui.jsx";
import { alerts } from "../data/demo.js";
import { useRealtime, severityOf } from "../lib/realtime.js";

interface AlertRow { id: string; severity: string; title: string; detail: string; ago: string; acked: boolean }

export default function Alerts() {
  const [acked, setAcked] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState("all");
  const rt = useRealtime();

  const liveAlerts: AlertRow[] = rt.events
    .filter((e) => ["CRITICAL", "HIGH"].includes(severityOf(e.type)))
    .slice(0, 20)
    .map((e) => ({
      id: String(e.id),
      severity: severityOf(e.type),
      title: e.type.replace(/^(platform|monitor|demo)\./, "").replace(/_/g, " "),
      detail: String(e.payload?.detail || e.payload?.target || ""),
      ago: new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false }),
      acked: false,
    }));

  const filtered = [...liveAlerts, ...alerts.map((a, i) => ({ ...a, id: `demo-${i}` }))]
    .filter((a) => (filter === "all" ? true : a.severity === filter.toUpperCase()) && !acked.has(a.id + a.title))
    .slice(0, 30);

  return (
    <>
      <PageHead
        crumb="post-quantum / alerts"
        title="Alerts"
        sub="Critical crypto change · new asset · new certificate · PQC risk · crypto drift · scanner failure · cloud/vendor/hardware change · compliance failure"
        right={
          <div className="row">
            {rt.connected && <Badge tone="green"><span className="dot" /> LIVE STREAM</Badge>}
            <Badge tone="red">{filtered.length} UNACKED</Badge>
          </div>
        }
      />
      <div className="tabs">
        {["all", "critical", "high", "medium", "low"].map((t) => (
          <button key={t} className={filter === t ? "active" : ""} onClick={() => setFilter(t)}>{t}</button>
        ))}
      </div>
      {filtered.length === 0 && <div className="dim" style={{ padding: 30, textAlign: "center" }}>no alerts in this view</div>}
      {filtered.map((a) => (
        <div className={`alertcard ${a.severity.toLowerCase()}`} key={a.title}>
          <div>
            <div className="ttl"><Badge>{a.severity}</Badge> {a.title}</div>
            <div className="det">{a.detail}</div>
          </div>
          <span className="ago">{a.ago}</span>
          <button className="btn sm" onClick={() => setAcked((s) => new Set(s).add(a.id + a.title))}>ack</button>
        </div>
      ))}
    </>
  );
}
