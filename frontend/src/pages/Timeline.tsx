import React from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { useRealtime, severityOf, isSystemEvent } from "../lib/realtime.js";
import { useLive } from "../lib/useLive.js";

/* Global timeline (spec §39) — shows REAL events only: backlog loaded from
   the live control plane (/events/recent) plus the realtime SSE stream.
   There is no static/demo fallback: with no events the list is empty. */

export default function Timeline() {
  const rt = useRealtime();
  const backlog = useLive<{ events: any[] }>("/api/v1/events/recent", { events: [] });

  const fromEvent = (e: any): { t: string; tag: string; text: string; cr: boolean; hi: boolean; id: any } => ({
    t: new Date(e.ts ?? e.timestamp).toLocaleTimeString("en-GB", { hour12: false }),
    tag: String(e.type ?? "").replace(/^(platform|monitor)\./, "").replace(/_/g, " "),
    text: String(e.payload?.detail || e.payload?.target || e.source || ""),
    cr: severityOf(e.type) === "CRITICAL",
    hi: severityOf(e.type) === "HIGH",
    id: e.id,
  });

  const backlogRows = (backlog.data.events ?? []).map(fromEvent);
  const liveRows = rt.events.filter((e) => !isSystemEvent(e.type)).map(fromEvent);

  const seen = new Set(liveRows.map((r) => r.id));
  const rows = liveRows.concat(backlogRows.filter((r) => !seen.has(r.id))).slice(0, 60);

  return (
    <>
      <PageHead
        crumb="live / global timeline"
        title="Global timeline"
        sub="One timeline across the entire platform — invaluable during audits and incidents"
        right={
          <div className="row">
            {rt.connected && <Badge tone="green"><span className="dot" /> LIVE STREAM · {rt.eps} EVENTS/SEC</Badge>}
            <span className="mono faint" style={{ fontSize: 12 }}>{rt.connected ? "REAL-TIME · UTC" : rows.length ? "SHOWING EVENT HISTORY" : "NO EVENTS YET"}</span>
          </div>
        }
      />
      <Panel title={rt.connected ? "Realtime" : "Event history"} sub={rt.connected ? "events as they arrive from the control plane" : "persisted events from the control plane"}>
        <div className="timeline">
          {rows.map((r) => (
            <div className={`tl ${r.cr ? "cr" : r.hi ? "hi" : ""}`} key={`${r.id}-${r.t}`}>
              <span className="mono faint">{r.t}</span> <span className="tag" style={{ fontFamily: "var(--mono)", fontSize: 10.5, padding: "2px 8px", borderRadius: "var(--r)", border: "1px solid var(--line)", color: "var(--cyan)" }}>{r.tag}</span>
              <span className="dim" style={{ fontSize: 13, marginLeft: 8 }}>{r.text}</span>
            </div>
          ))}
          {rows.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No events yet — run a discovery, scan or backup to populate the timeline.</p>}
        </div>
      </Panel>
    </>
  );
}
