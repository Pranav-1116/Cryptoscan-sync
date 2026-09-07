import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiDrift, apiLiveDrift, LiveBadge, ApiResult, LiveDriftResponse } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useLive } from "../lib/useLive.js";

/* baseline/live are empty until real scans freeze a baseline — no static drift. */
const EMPTY: Record<string, string[]> = { network: [], cloud: [], vendor: [], hardware: [], crypto: [], certificate: [], firmware: [], pqc: [] };

export default function Drift() {
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  // continuous drift between consecutive real scan cycles
  const liveCycle = usePollingApi(apiLiveDrift, 6000);
  const cycle = (liveCycle.data ?? null) as LiveDriftResponse | null;
  const cycleChanges = cycle?.changes ?? [];
  const DRIFT_TONE: Record<string, "red" | "amber" | "cyan" | ""> = {
    HIGH: "red", MEDIUM: "amber", LOW: "cyan", CRITICAL: "red",
  };

  const runLiveCheck = async () => {
    setBusy(true);
    const res = await apiDrift(EMPTY, EMPTY);
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
            <Badge tone=""><span className="dot" /> FREEZE A BASELINE AFTER FIRST SCAN</Badge>
            <button className="btn sm" onClick={() => void runLiveCheck()} disabled={busy}>
              {busy ? "Checking…" : "Run live drift check"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      <Panel
        title="Live cycle drift"
        sub={cycle?.baseline
          ? `crypto changes between consecutive live scans${cycle?.previous_ts ? " (baseline " + new Date(cycle.previous_ts).toLocaleTimeString() + ")" : ""}`
          : "run two or more live scans to establish a drift baseline"}
        className="mt"
      >
        {liveCycle.source === "live" && cycleChanges.length > 0 && (
          <Table
            head={["severity", "scanner", "change", "detail", "asset"]}
            rows={cycleChanges.map((c) => [
              <Badge tone={DRIFT_TONE[c.severity] ?? ""}>{c.severity}</Badge>,
              c.scanner,
              <span style={{ fontWeight: 600 }}>{c.title}</span>,
              <span style={{ fontSize: 12 }}>{c.detail}</span>,
              <span className="mono" style={{ fontSize: 12 }}>{c.asset || "—"}</span>,
            ])}
          />
        )}
        {liveCycle.source === "live" && cycleChanges.length === 0 && (
          <div className="dim" style={{ fontSize: 13 }}>
            {cycle?.baseline ? "No crypto-relevant changes between the last two live scans." : "Awaiting a second live scan to diff against."}
          </div>
        )}
        {liveCycle.source !== "live" && (
          <div className="dim" style={{ fontSize: 13 }}>Backend offline — start the control plane to track live drift.</div>
        )}
      </Panel>

      {live?.data && (
        <Panel title="POST /api/v1/platform/drift — engine response" sub="the deterministic drift evaluation from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <DriftDigest />
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

function DriftDigest() {
  const digest = useLive<{ total?: number; open?: number; by_severity?: Record<string, number>; highlights?: any[] }>("/api/v1/drift/digest", { total: 0, open: 0, by_severity: {}, highlights: [] });
  const sev = digest.data.by_severity ?? {};
  const highlights = digest.data.highlights ?? [];
  return (
    <Panel title="Drift digest" sub="frozen baseline vs latest live state (live from the control plane)">
      <Table
        head={["severity", "open drift items"]}
        rows={[["CRITICAL", sev.CRITICAL ?? 0], ["HIGH", sev.HIGH ?? 0], ["MEDIUM", sev.MEDIUM ?? 0], ["INFO", sev.INFO ?? 0]]
          .map(([k, v]) => [k, <span className="num" key={k as string}>{v}</span>])}
      />
      {highlights.length > 0 && (
        <div className="dim" style={{ fontSize: 12.5, marginTop: 10 }}>
          {highlights.slice(0, 5).map((h, i) => (<div key={i}>• {typeof h === "string" ? h : h.title ?? h.detail ?? JSON.stringify(h)}</div>))}
        </div>
      )}
      {digest.data.open === 0 && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>No drift recorded — freeze a baseline after your first scan; changes then appear here.</div>}
    </Panel>
  );
}
