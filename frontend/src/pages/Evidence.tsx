import React, { useState } from "react";
import { Panel, Badge, Table, Code, PageHead } from "../components/ui.jsx";
import { evidenceChain } from "../data/demo.js";
import { apiEvidence, LiveBadge, ApiResult } from "../lib/api.js";

export default function Evidence() {
  const [sel, setSel] = useState(0);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);
  const e = evidenceChain[sel];

  const verify = async () => {
    setBusy(true);
    const res = await apiEvidence();
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="govern / evidence"
        title="Evidence explorer"
        sub="Finding → observation → evidence → source → timestamp → hash → previous evidence — every claim is reproducible"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> EVIDENCE HEALTH 99.8%</Badge>
            <button className="btn sm" onClick={() => void verify()} disabled={busy}>
              {busy ? "Verifying…" : "Verify chain (live)"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE — DEMO"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="GET /api/v1/platform/evidence — engine response" sub="evidence-chain verification from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <div className="grid cols-2">
        <Panel title="Evidence chain" sub="select a link to inspect it">
          <Table
            clickable
            selected={sel}
            onSelect={setSel}
            head={["id", "kind", "method", "confidence"]}
            rows={evidenceChain.map((x) => [
              <span className="mono" style={{ fontWeight: 600 }}>{x.id}</span>,
              <Badge tone="cyan">{x.kind}</Badge>,
              <span style={{ fontSize: 12.5 }}>{x.method}</span>,
              <span className="num">{(x.confidence * 100).toFixed(0)}%</span>,
            ])}
          />
        </Panel>
        <Panel title={e.id} sub={`${e.kind} · ${e.method}`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, fontSize: 13.5 }}>
            <div><span className="faint">detail:</span> {e.detail}</div>
            <div><span className="faint">detection method:</span> <Badge tone="violet">{e.method}</Badge></div>
            <div><span className="faint">confidence:</span> <Badge tone="green">{(e.confidence * 100).toFixed(0)}%</Badge></div>
            <div><span className="faint">first seen:</span> <span className="mono">{e.firstSeen}</span></div>
            <div><span className="faint">last seen:</span> <span className="mono">{e.lastSeen}</span></div>
            <div><span className="faint">changed at:</span> <span className="mono">2026-09-01 09:41:22 UTC</span></div>
            <div><span className="faint">source hash:</span> <span className="mono">{e.hash}</span></div>
            <div><span className="faint">previous evidence:</span> {e.prev ? <a className="mono" href="#/evidence">{e.prev}</a> : <span className="faint">root of chain</span>}</div>
          </div>
        </Panel>
      </div>
      <Panel title="Integrity" sub="the chain is append-only — tampering breaks the hashes" className="mt">
        <Code>{`ev-00921 (finding)
  └── ev-00920 (observation)     prev: ev-00881
        └── ev-00919 (source)    prev: ev-00880
              └── ev-00918 (dep) prev: ev-00862

hash(ev-00920) = sha256("observation|artifact scan|/etc/tls/payments.crt|0x0412|...")
verify: recompute → compare → immutable audit trail`}</Code>
      </Panel>
    </>
  );
}
