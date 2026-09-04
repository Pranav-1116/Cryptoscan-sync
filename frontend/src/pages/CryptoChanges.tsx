import React, { useState } from "react";
import { Panel, Badge, PageHead } from "../components/ui.jsx";
import { cryptoChanges } from "../data/initial.js";
import { useRealtime, severityOf, isSystemEvent } from "../lib/realtime.js";

const CATS = ["ALL", "CERTIFICATE", "PROTOCOL", "LIBRARY", "PQC", "HARDWARE", "CLOUD", "NETWORK", "ALGORITHM", "PLATFORM"];

/* Live crypto changes (spec §16) — the dedicated crypto event stream
   with per-category filtering. When the SSE stream is connected the real
   platform/monitor events stream in; offline the view is empty. */

function categoryOf(type: string): string {
  const t = type.toLowerCase();
  if (t.includes("certificate") || t.includes("cert")) return "CERTIFICATE";
  if (t.includes("tls") || t.includes("ssh") || t.includes("protocol") || t.includes("ipsec")) return "PROTOCOL";
  if (t.includes("library")) return "LIBRARY";
  if (t.includes("pqc") || t.includes("quantum") || t.includes("ml-kem") || t.includes("ml-dsa")) return "PQC";
  if (t.includes("hsm") || t.includes("tpm") || t.includes("firmware") || t.includes("hardware")) return "HARDWARE";
  if (t.includes("cloud")) return "CLOUD";
  if (t.includes("device") || t.includes("network")) return "NETWORK";
  if (t.includes("algorithm") || t.includes("key") || t.includes("crypto")) return "ALGORITHM";
  if (t.startsWith("platform.")) return "PLATFORM";
  return "PLATFORM";
}

export default function CryptoChanges() {
  const [cat, setCat] = useState("ALL");
  const rt = useRealtime();

  const streamRows = rt.events.filter((e) => !isSystemEvent(e.type)).map((e) => ({
    t: new Date(e.ts).toLocaleTimeString("en-GB", { hour12: false }),
    tag: categoryOf(e.type),
    text: `${e.type.replace(/^(platform|monitor|demo)\./, "")}: ${String(e.payload?.detail || e.payload?.target || "")}`,
    severity: severityOf(e.type),
    id: e.id,
  }));

  const staticRows = cryptoChanges.map((c, i) => ({
    t: c.t, tag: c.category, text: c.text, severity: c.severity, id: -i - 1000,
  }));
  const rows = (cat === "ALL" ? streamRows : streamRows.filter((r) => r.tag === cat))
    .concat(cat === "ALL" ? staticRows : staticRows.filter((r) => r.tag === cat))
    .slice(0, 40);

  return (
    <>
      <PageHead
        crumb="live / crypto changes"
        title="Live crypto changes"
        sub="Every crypto-relevant change, streamed from the scanners — the source of drift, CBOM bumps and alerts"
        right={
          <div className="row">
            <Badge tone={rt.connected ? "green" : "amber"}>
              <span className="dot" /> {rt.connected ? `STREAMING · ${rt.eps} EVENTS/SEC` : "AWAITING LIVE STREAM · SIGN IN & CONNECT"}
            </Badge>
          </div>
        }
      />
      <div className="tabs">
        {CATS.map((c) => (
          <button key={c} className={cat === c ? "active" : ""} onClick={() => setCat(c)}>
            {c === "ALL" ? "all" : c.toLowerCase()}
          </button>
        ))}
      </div>
      <Panel title={cat === "ALL" ? "All crypto changes" : `${cat} changes`} sub={rt.connected ? "live SSE stream — platform + monitor events" : "no live stream yet — sign in to connect"}>
        <div className="feed">
          {rows.length === 0 && <div className="dim" style={{ padding: 16, textAlign: "center" }}>no events in this view</div>}
          {rows.map((c, i) => (
            <div className="ev" key={`${c.id}-${i}`}>
              <span className="t">{c.t}</span>
              <span className="tag">{c.tag}</span>
              <span className="txt">{c.text}</span>
              <Badge>{c.severity}</Badge>
            </div>
          ))}
        </div>
      </Panel>
    </>
  );
}
