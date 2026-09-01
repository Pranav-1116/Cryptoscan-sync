import React from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { timelineRows } from "../data/demo.js";
import { useRealtime, severityOf, isSystemEvent } from "../lib/realtime.js";

/* Global timeline (spec §39) — real stream events first when connected,
   deterministic demo events as baseline. */

export default function Timeline() {
  const rt = useRealtime();

  const liveRows = rt.events.filter((e) => !isSystemEvent(e.type)).map((e) => ({
    t: new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false }),
    tag: e.type.replace(/^(platform|monitor|demo)\./, "").replace(/_/g, " "),
    text: String(e.payload?.detail || e.payload?.target || ""),
    cr: severityOf(e.type) === "CRITICAL",
    hi: severityOf(e.type) === "HIGH",
    id: e.id,
  }));

  const demoRows = timelineRows.map((r, i) => ({
    t: r.t, tag: r.tag.replace(/_/g, " "), text: r.text,
    cr: r.tag === "CERT_EXPIRED", hi: r.tag.includes("CHANGED"), id: -i - 1,
  }));

  const rows = liveRows.concat(demoRows).slice(0, 60);

  return (
    <>
      <PageHead
        crumb="live / global timeline"
        title="Global timeline"
        sub="One timeline across the entire platform — invaluable during audits and incidents"
        right={
          <div className="row">
            {rt.connected && <Badge tone="green"><span className="dot" /> LIVE STREAM · {rt.eps} EVENTS/SEC</Badge>}
            <span className="mono faint" style={{ fontSize: 12 }}>{rt.connected ? "REAL-TIME · UTC" : "DEMO · LAST 24H"}</span>
          </div>
        }
      />
      <Panel title={rt.connected ? "Realtime" : "Today"} sub={rt.connected ? "events as they arrive from the control plane" : "every event, in order, with its source scanner (demo)"}>
        <div className="timeline">
          {rows.map((r) => (
            <div className={`tl ${r.cr ? "cr" : r.hi ? "hi" : ""}`} key={`${r.id}-${r.t}`}>
              <span className="mono faint">{r.t}</span> <span className="tag" style={{ fontFamily: "var(--mono)", fontSize: 10.5, padding: "2px 8px", borderRadius: 6, border: "1px solid var(--line)", color: "var(--cyan)" }}>{r.tag}</span>
              <span className="dim" style={{ fontSize: 13, marginLeft: 8 }}>{r.text}</span>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
