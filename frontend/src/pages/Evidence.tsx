import React, { useState } from "react";
import { Panel, Badge, Table, Code, PageHead } from "../components/ui.jsx";
import { evidenceChain } from "../data/initial.js";
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
            <Badge tone=""><span className="dot" /> {evidenceChain.length} EVIDENCE RECORDS</Badge>
            <button className="btn sm" onClick={() => void verify()} disabled={busy}>
              {busy ? "Verifying…" : "Verify chain (live)"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="GET /api/v1/platform/evidence — engine response" sub="evidence-chain verification from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      {evidenceChain.length === 0 && (
        <Panel className="mt" title="No evidence yet">
          <div className="dim" style={{ fontSize: 13.5 }}>
            Evidence records are produced by scans. Run discovery and a scan against your estate; each
            finding, observation, source and dependency is recorded with a detection method, confidence
            and an append-only hash chain (each record references the previous record's hash).
          </div>
        </Panel>
      )}
      {evidenceChain.length > 0 && (
      <>
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
            <div><span className="faint">source hash:</span> <span className="mono">{e.hash}</span></div>
            <div><span className="faint">previous evidence:</span> {e.prev ? <a className="mono" href="#/evidence">{e.prev}</a> : <span className="faint">root of chain</span>}</div>
          </div>
        </Panel>
      </div>
      <Panel title="Integrity" sub="the chain is append-only — tampering breaks the hashes" className="mt">
        <Code>{`record (finding)
  └── observation      prev: <hash>
        └── source     prev: <hash>
              └── dep  prev: <hash>

hash(record) = sha256("<kind>|<method>|<location>|<evidence bytes>")
verify: recompute each hash → compare with stored → any break fails the chain.

Records appear here after the first scan.`}</Code>
      </Panel>
      </>
      )}
    </>
  );
}
