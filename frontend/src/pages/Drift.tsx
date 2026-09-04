import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { drift } from "../data/initial.js";
import { apiDrift, LiveBadge, ApiResult } from "../lib/api.js";

const CATS: { key: keyof typeof drift.baseline; label: string }[] = [
  { key: "network", label: "Network drift" },
  { key: "cloud", label: "Cloud drift" },
  { key: "vendor", label: "Vendor drift" },
  { key: "hardware", label: "Hardware drift" },
  { key: "crypto", label: "Crypto drift" },
  { key: "certificate", label: "Certificate drift" },
  { key: "firmware", label: "Firmware drift" },
  { key: "pqc", label: "PQC drift" },
];

function diff(base: string[], live: string[]) {
  const added = live.filter((x) => !base.includes(x));
  const removed = base.filter((x) => !live.includes(x));
  return { added, removed };
}

export default function Drift() {
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  const runLiveCheck = async () => {
    setBusy(true);
    const res = await apiDrift(drift.baseline, drift.live);
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="post-quantum / drift"
        title="Drift"
        sub="Baseline → current state → diff · every category watched continuously"
        right={
          <div className="row">
            <Badge tone="red"><span className="dot" /> 3 DRIFT EVENTS</Badge>
            <button className="btn sm" onClick={() => void runLiveCheck()} disabled={busy}>
              {busy ? "Checking…" : "Run live drift check"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/drift — engine response" sub="the deterministic drift evaluation from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <Panel title="Drift matrix" sub="frozen baseline vs latest live state">
        <Table
          head={["category", "added (live only)", "removed (baseline only)"]}
          rows={CATS.map((c) => {
            const d = diff(drift.baseline[c.key], drift.live[c.key]);
            return [
              c.label,
              d.added.length ? <Badge tone="red">+ {d.added.join(", ")}</Badge> : <Badge tone="green">none</Badge>,
              d.removed.length ? <Badge tone="amber">− {d.removed.join(", ")}</Badge> : <Badge tone="green">none</Badge>,
            ];
          })}
        />
      </Panel>
      <div className="grid cols-2 mt">
        <Panel title="Why drift matters" sub="deterministic change detection">
          <p className="dim" style={{ fontSize: 13.5, marginTop: 0 }}>
            A new network device and a newly active ML-KEM-768 exchange appeared without a change
            ticket. The control plane flagged both and re-scored the blast radius automatically —
            nothing waits for a human to notice.
          </p>
          <ul className="dim" style={{ fontSize: 13.5, paddingLeft: 18, display: "flex", flexDirection: "column", gap: 6 }}>
            <li>sw-dc-03 joined 10.0.2.0/24 — identity enrolled, posture scanned</li>
            <li>ML-KEM-768 now active — PQC readiness HYBRID_READY → PQC_READY</li>
            <li>fw-edge-01 PAN-OS 11.1.1 → 11.1.2 — targeted rescan dispatched</li>
          </ul>
        </Panel>
        <Panel title="Next scan" sub="scheduled · read-only · evidence-backed">
          <div className="mono" style={{ fontSize: 12.5, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">window:</span> sun 02:00–04:00 utc</div>
            <div><span className="faint">mode:</span> SAFE / READ_ONLY</div>
            <div><span className="faint">scope:</span> 10.0.0.0/8 · aws:123456789012 · gcp:pay-prod</div>
            <div><span className="faint">excluded:</span> 10.99.0.0/16 · legacy-mainframe</div>
            <div><Badge tone="green">POLICY COMPLIANT</Badge></div>
          </div>
        </Panel>
      </div>
    </>
  );
}
