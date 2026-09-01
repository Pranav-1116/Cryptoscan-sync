import React, { useState } from "react";
import { Panel, Badge, Table, Tabs, Code, PageHead } from "../components/ui.jsx";
import { bomComponents, bomDependencies, bomDiff, bomHistory, globalState } from "../data/demo.js";
import { apiBom, LiveBadge, ApiResult } from "../lib/api.js";

const VIEWS = ["Overview", "Explorer", "Diff", "History", "Export"];

export default function Cbom() {
  const [tab, setTab] = useState(0);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

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
            <Badge tone="green"><span className="dot" /> v{globalState.cbomVersion} · LATEST</Badge>
            <button className="btn sm" onClick={() => void fetchLive()} disabled={busy}>
              {busy ? "Fetching…" : "Fetch live CBOM"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE — DEMO"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="GET /api/v1/platform/bom — engine response" sub="combined CycloneDX CBOM + HBOM produced by the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <Tabs tabs={VIEWS} active={tab} onChange={setTab} />

      {tab === 0 && (
        <div className="grid cols-2">
          <Panel title="CBOM overview" sub="components by type">
            <Table
              head={["type", "components"]}
              rows={[
                ["cryptography", <span className="num">4</span>],
                ["library", <span className="num">3</span>],
                ["device", <span className="num">3</span>],
                ["application", <span className="num">2</span>],
                ["firmware", <span className="num">1</span>],
              ].map(([k, v]) => [<Badge tone="cyan">{k}</Badge>, v])}
            />
          </Panel>
          <Panel title="Change flow" sub="every crypto change bumps the version">
            <div className="tree">
              CBOM v1,842<br />
              {"  └── crypto change · 09:41:22 UTC"}<br />
              {"      └── CBOM v1,843"}<br />
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
        <Panel title="CBOM diff — v1842 → v1843" sub="exactly what changed">
          <Table
            head={["change", "components"]}
            rows={[
              ["added", bomDiff.added.map((a) => <Badge key={a} tone="green">+ {a}</Badge>)],
              ["removed", bomDiff.removed.map((a) => <Badge key={a} tone="red">− {a}</Badge>)],
              ["changed", bomDiff.changed.map((a) => <Badge key={a} tone="amber">~ {a}</Badge>)],
            ]}
          />
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
  "serialNumber": "urn:uuid:7f3a9c21-d8e4-4b06-f1a9-2c55be0d81aa",
  "version": ${globalState.cbomVersion},
  "components": [ 14 cryptography / library / device ],
  "dependencies": [ 8 edges ],
  "zelinx": {
    "accuracy": "F1 1.0 / 88 cases",
    "generator": "deterministic engine v1.0",
    "evidence": "ev-00921..ev-00930"
  }
}`}</Code>
        </Panel>
      )}
    </>
  );
}
