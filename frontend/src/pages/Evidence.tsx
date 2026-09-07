import React, { useEffect, useState } from "react";
import { Panel, Badge, Code, PageHead } from "../components/ui.jsx";
import { apiEvidence, ApiResult } from "../lib/api.js";

interface EvidenceResp { valid?: boolean; records?: number; head?: string | null; chain?: any[]; details?: any; }

export default function Evidence() {
  const [live, setLive] = useState<ApiResult<EvidenceResp> | null>(null);
  const [busy, setBusy] = useState(false);

  const verify = async () => {
    setBusy(true);
    setLive(await apiEvidence() as ApiResult<EvidenceResp>);
    setBusy(false);
  };
  useEffect(() => { void verify(); /* live on mount — no static chain */ }, []);

  const d = live?.data;
  const records = d?.records ?? 0;

  return (
    <>
      <PageHead
        crumb="govern / evidence"
        title="Evidence explorer"
        sub="Finding → observation → evidence → source → timestamp → hash → previous evidence — every claim is reproducible"
        right={
          <div className="row">
            <Badge tone={records ? "green" : ""}><span className="dot" /> {records} EVIDENCE RECORD{records === 1 ? "" : "S"}</Badge>
            <Badge tone={d?.valid ? "green" : "amber"}>{d ? d.valid ? "CHAIN VALID" : "CHAIN INVALID" : "—"}</Badge>
            <button className="btn sm" onClick={() => void verify()} disabled={busy}>
              {busy ? "Verifying…" : "Verify chain (live)"}
            </button>
          </div>
        }
      />
      {d && (
        <Panel title="GET /api/v1/platform/evidence — live verification" sub="append-only hash-chain verification from the control plane" className="mt">
          <Code>{JSON.stringify(d, null, 2)}</Code>
        </Panel>
      )}
      {records === 0 && (
        <Panel className="mt" title="No evidence yet">
          <div className="dim" style={{ fontSize: 13.5 }}>
            Evidence records are produced by scans. Run discovery and a scan against your estate; each
            finding, observation, source and dependency is recorded with a detection method, confidence
            and an append-only hash chain (each record references the previous record's hash).
          </div>
        </Panel>
      )}
      <Panel title="Integrity" sub="the chain is append-only — tampering breaks the hashes" className="mt">
        <Code>{`record (finding)
  └── observation      prev: <hash>
        └── source     prev: <hash>
              └── dep  prev: <hash>

hash(record) = sha256("<kind>|<method>|<location>|<evidence bytes>")
verify: recompute each hash → compare with stored → any break fails the chain.

Records appear here after the first scan. The live count and validity above
come straight from the control plane — never fabricated.`}</Code>
      </Panel>
    </>
  );
}
