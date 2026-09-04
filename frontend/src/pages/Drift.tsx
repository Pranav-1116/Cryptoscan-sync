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
            <Badge tone={Object.values(drift.baseline).some((arr: string[]) => arr.length > 0) ? "green" : ""}><span className="dot" /> {Object.values(drift.baseline).some((arr: string[]) => arr.length > 0) ? "BASELINE READY" : "NO BASELINE — RUN A SCAN"}</Badge>
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
            Baseline vs live comparison surfaces new devices, removed assets, firmware changes and
            crypto changes. The control plane flags anything outside a change ticket and re-scores
            the blast radius automatically — nothing waits for a human to notice.
          </p>
          <p className="dim" style={{ fontSize: 13, margin: 0 }}>
            Freeze a baseline after your first scan; drift events then appear here and in the live
            change feed.
          </p>
        </Panel>
        <Panel title="Next scan" sub="scheduled · read-only · evidence-backed">
          <div className="mono" style={{ fontSize: 12.5, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">window:</span> set during onboarding / maintenance window</div>
            <div><span className="faint">mode:</span> SAFE / READ_ONLY</div>
            <div><span className="faint">scope:</span> configure targets in Onboarding</div>
            <div><Badge tone="green">POLICY COMPLIANT</Badge></div>
          </div>
        </Panel>
      </div>
    </>
  );
}
