import React, { useState } from "react";
import { Panel, Badge, Table, Tabs, Code, PageHead } from "../components/ui.jsx";
import { apiBom, apiLiveBom, LiveBadge, ApiResult, LiveBomResponse } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";

const VIEWS = ["Overview", "Explorer", "Diff", "History", "Export"];

export default function Cbom() {
  const [tab, setTab] = useState(0);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  // live CBOM assembled from the scanner cycle (algorithms/libraries/packages)
  const liveBomRes = usePollingApi(apiLiveBom, 8000);
  const liveBom = (liveBomRes.data ?? null) as LiveBomResponse | null;
  const bomComponents: any[] = liveBom?.cbom.components ?? [];
  const bomDependencies: any[] = liveBom?.cbom.dependencies ?? [];
  const bomDiff = (liveBom?.cbom as any)?.diff ?? { added: [], removed: [], changed: [] };
  const bomHistory: any[] = liveBom?.cbom.history ?? liveBom?.versions ?? [];
  const cbomVersion = liveBom?.cbom.version ?? bomHistory.length;
  const liveCounts = liveBom?.cbom.counts ?? {};
  const Q_TONE: Record<string, "red" | "amber" | "green" | ""> = {
    vulnerable: "red", broken: "red", at_risk: "amber", safe: "green",
  };

  const fetchLive = async () => {
    setBusy(true);
    const res = await apiBom();
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="boms / cbom"
        title="CBOM"
        sub="Cryptographic Bill of Materials — CycloneDX 1.6 · live with every crypto change"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> v{cbomVersion} · LATEST</Badge>
            <button className="btn sm" onClick={() => void fetchLive()} disabled={busy}>
              {busy ? "Fetching…" : "Fetch live CBOM"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="GET /api/v1/platform/bom — engine response" sub="combined CycloneDX CBOM + HBOM produced by the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      {liveBomRes.source === "live" && (
        <Panel title="Live CBOM (from real scans)" sub={liveBom ? `generated ${liveBom.generated_at ? new Date(liveBom.generated_at).toLocaleString() : ""} · quantum verdicts from the universal classifier` : ""} className="mt">
          <div className="grid cols-4" style={{ marginBottom: 12 }}>
            {[["total", liveCounts.total ?? liveComponents.length], ["algorithms", liveCounts.algorithms ?? 0],
              ["libraries/packages", (liveCounts.libraries ?? 0) + (liveCounts.packages ?? 0)],
              ["quantum vulnerable", liveCounts.quantum_vulnerable ?? 0]].map(([k, v]) => (
              <div className="kpi" key={k as string}><span className="k">{k}</span>
                <span className="v" style={{ color: k === "quantum vulnerable" && Number(v) ? "var(--red)" : undefined }}>{v as number}</span></div>
            ))}
          </div>
          <Table
            head={["type", "component", "version", "source", "quantum status", "priority"]}
            rows={liveComponents.map((c) => [
              <Badge tone="cyan">{c.type}</Badge>,
              <span className="mono" style={{ fontWeight: 600 }}>{c.name}</span>,
              <span className="num">{c.version || "—"}</span>,
              c.source,
              c.quantum_status
                ? <Badge tone={Q_TONE[String(c.quantum_status).toLowerCase()] ?? ""}>{c.quantum_status}</Badge>
                : <span className="faint">{c.status || "unclassified"}</span>,
              <span>{c.migration_priority ?? "—"}</span>,
            ])}
          />
          {!liveComponents.length && (
            <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
              No crypto components yet — run runtime + universal/container scans in Operations → Realtime scanners.
            </div>
          )}
        </Panel>
      )}
      <Tabs tabs={VIEWS} active={tab} onChange={setTab} />

      {tab === 0 && (
        <div className="grid cols-2">
          <Panel title="CBOM overview" sub="components by type">
            {bomComponents.length ? (
            <Table
              head={["type", "components"]}
              rows={["cryptography", "library", "device", "application", "firmware", "certificate"]
                .map((t): [string, number] => [t, bomComponents.filter((c) => c.type === t).length])
                .filter(([, n]) => n > 0)
                .map(([k, v]) => [<Badge tone="cyan">{k}</Badge>, <span className="num">{v}</span>])}
            />
            ) : (
              <div className="dim" style={{ fontSize: 13 }}>No CBOM yet — run a scan to enumerate cryptographic components and dependencies.</div>
            )}
          </Panel>
          <Panel title="Change flow" sub="every crypto change bumps the version">
            <div className="tree">
              {bomHistory.length ? (
                <>
                  {bomHistory.slice(0, 4).map((h, i) => (
                    <React.Fragment key={h.version}>
                      {i === 0 ? "" : "  └── "}CBOM {h.version} · {h.note}<br />
                    </React.Fragment>
                  ))}
                </>
              ) : (
                <>No versions yet — the CBOM is created on the first scan.<br /></>
              )}
              <br />
              compare: <span className="faint">current vs previous · current vs baseline · date vs date · env vs env</span>
            </div>
          </Panel>
        </div>
      )}

      {tab === 1 && (
        <Panel title="CBOM explorer" sub="all components and their dependencies">
          <Table
            head={["type", "component", "ref"]}
            rows={bomComponents.map((c) => [<Badge tone="cyan">{c.type}</Badge>, c.name, <span className="mono">{c.ref}</span>])}
          />
          <h3 style={{ margin: "18px 0 8px" }}>Dependencies</h3>
          <Table
            head={["component", "depends on"]}
            rows={bomDependencies.map((d) => [<span className="mono">{d.ref}</span>, d.dependsOn.map((x) => <Badge key={x}>{x}</Badge>)])}
          />
        </Panel>
      )}

      {tab === 2 && (
        <Panel title="CBOM diff" sub="exactly what changed between versions">
          {bomDiff.added.length || bomDiff.removed.length || bomDiff.changed.length ? (
          <Table
            head={["change", "components"]}
            rows={[
              ["added", bomDiff.added.map((a) => <Badge key={a} tone="green">+ {a}</Badge>)],
              ["removed", bomDiff.removed.map((a) => <Badge key={a} tone="red">− {a}</Badge>)],
              ["changed", bomDiff.changed.map((a) => <Badge key={a} tone="amber">~ {a}</Badge>)],
            ]}
          />
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>No diff available — run scans to build version history, then compare current vs previous / baseline / date / environment.</div>
          )}
        </Panel>
      )}

      {tab === 3 && (
        <Panel title="CBOM history" sub="full version lineage — audit-safe">
          <Table
            head={["version", "time", "change", "by"]}
            rows={bomHistory.map((h) => [
              <span className="mono" style={{ fontWeight: 600 }}>{h.version}</span>,
              <span className="mono">{h.at}</span>,
              h.note,
              <span className="mono">{h.by}</span>,
            ])}
          />
        </Panel>
      )}

      {tab === 4 && (
        <Panel title="CBOM export" sub="CycloneDX 1.6 JSON — drop into any BOM toolchain">
          <Code>{`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": ${cbomVersion || 0},
  "components": [ ${bomComponents.length} components ],
  "dependencies": [ ${bomDependencies.length} edges ],
  "zelinx": {
    "generator": "deterministic engine v1.0 — no AI inference",
    "note": "populated after a scan; fetch the live CBOM for the full export"
  }
}`}</Code>
        </Panel>
      )}
    </>
  );
}
