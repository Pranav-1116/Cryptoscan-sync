import React, { useMemo, useState } from "react";
import { Panel, Badge, Table, Tabs, Code, PageHead } from "../components/ui.jsx";
import { apiBom, apiLiveBom, LiveBadge, ApiResult, LiveBomResponse } from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";

/* CBOM — Cryptographic Bill of Materials (CycloneDX 1.6). Every panel is built
   from the LIVE scan-derived BOM (GET /live-scan/bom): an interactive
   dependency graph (components → dependencies, colored by quantum verdict) and
   a real CycloneDX export (download .json / .xml or copy) assembled from the
   same components — never a static placeholder. Empty until a scan runs. */

const VIEWS = ["Graph", "Explorer", "Diff", "History", "Export"];

interface BomComponent {
  type?: string; name?: string; version?: string; ref?: string;
  source?: string; quantum_status?: string | null; migration_priority?: string | null;
  status?: string;
}
interface BomDependency { ref?: string; dependsOn?: string[]; }

const QUANTUM_COLOR: Record<string, string> = {
  vulnerable: "#ef4444", broken: "#ef4444", at_risk: "#f59e0b",
  safe: "#22c55e", unknown: "#64748b",
};
const TYPE_COLOR: Record<string, string> = {
  cryptography: "#00d4ff", library: "#f59e0b", device: "#f97316",
  application: "#8b7cf6", firmware: "#f97316", certificate: "#22c55e",
  package: "#f59e0b", algorithm: "#ef4444",
};

function quantumOf(c: BomComponent): string {
  const q = String(c.quantum_status ?? "").toLowerCase();
  if (q.includes("vuln") || q.includes("broken")) return "vulnerable";
  if (q.includes("risk")) return "at_risk";
  if (q.includes("safe")) return "safe";
  return "unknown";
}

/* Build a real CycloneDX 1.6 JSON document from the live components/deps. */
function toCycloneDx(components: BomComponent[], deps: BomDependency[], version: number) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version,
    serialNumber: `urn:uuid:cryptoscan-cbom-${version}`,
    metadata: {
      component: { type: "platform", name: "CryptoScan CBOM" },
      properties: [
        { name: "cryptoscan:generator", value: "deterministic engine — no AI inference" },
      ],
    },
    components: components.map((c, i) => ({
      type: c.type === "library" || c.type === "package" ? "library"
        : c.type === "device" || c.type === "firmware" ? "device"
        : c.type === "certificate" ? "cryptographic-asset"
        : "application",
      "bom-ref": c.ref || `${c.type || "comp"}-${i}`,
      name: c.name || `component-${i}`,
      version: c.version || undefined,
      properties: [
        ...(c.source ? [{ name: "cryptoscan:source", value: c.source }] : []),
        ...(c.quantum_status ? [{ name: "cryptoscan:quantum_status", value: c.quantum_status }] : []),
        ...(c.migration_priority ? [{ name: "cryptoscan:migration_priority", value: String(c.migration_priority) }] : []),
      ],
    })),
    dependencies: deps
      .filter((d) => d.ref)
      .map((d) => ({ ref: d.ref, dependsOn: d.dependsOn ?? [] })),
  };
}

function download(filename: string, text: string, mime: string) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

/* Radial layout: components arranged in a circle, edges from dependencies. */
function layoutGraph(components: BomComponent[]) {
  const cx = 400, cy = 240, r = components.length > 1 ? 180 : 0;
  return components.map((c, i) => {
    const ang = components.length === 1 ? -Math.PI / 2 : (i / components.length) * Math.PI * 2 - Math.PI / 2;
    return {
      ...c,
      x: cx + r * Math.cos(ang),
      y: cy + r * Math.sin(ang) * 0.72,
    };
  });
}

export default function Cbom() {
  const [tab, setTab] = useState(0);
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [selNode, setSelNode] = useState<string | null>(null);

  const liveBomRes = usePollingApi(apiLiveBom, 8000);
  const liveBom = (liveBomRes.data ?? null) as LiveBomResponse | null;
  const cbom = (liveBom?.cbom ?? {}) as any;
  const bomComponents: BomComponent[] = cbom.components ?? [];
  const bomDependencies: BomDependency[] = cbom.dependencies ?? [];
  const bomDiff = cbom.diff ?? { added: [], removed: [], changed: [] };
  const bomHistory: any[] = cbom.history ?? (liveBom as any)?.versions ?? [];
  const cbomVersion = cbom.version ?? bomHistory.length;
  const liveCounts: Record<string, number> = cbom.counts ?? {};

  const nodes = useMemo(() => layoutGraph(bomComponents), [bomComponents]);
  const nodeByRef = useMemo(() => {
    const m = new Map<string, (typeof nodes)[number]>();
    nodes.forEach((n, i) => m.set(n.ref || `${n.type || "comp"}-${i}`, n));
    return m;
  }, [nodes]);

  const cyclonedx = useMemo(
    () => toCycloneDx(bomComponents, bomDependencies, cbomVersion || 1),
    [bomComponents, bomDependencies, cbomVersion]);
  const selectedComp = bomComponents.find((c, i) => (c.ref || `${c.type || "comp"}-${i}`) === selNode);

  const fetchLive = async () => {
    setBusy(true);
    const res = await apiBom();
    setLive(res);
    setBusy(false);
  };

  const doCopy = async () => {
    await navigator.clipboard.writeText(JSON.stringify(cyclonedx, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  const qVuln = liveCounts.quantum_vulnerable ?? bomComponents.filter((c) => quantumOf(c) === "vulnerable").length;

  return (
    <>
      <PageHead
        crumb="boms / cbom"
        title="CBOM"
        sub="Cryptographic Bill of Materials — CycloneDX 1.6 · live with every crypto change"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> v{cbomVersion} · latest</Badge>
            <button className="btn sm" onClick={() => void fetchLive()} disabled={busy}>
              {busy ? "Fetching…" : "Fetch control-plane BOM"}
            </button>
          </div>
        }
      />

      <div className="grid cols-4" style={{ margin: "4px 0 16px" }}>
        {[["total", liveCounts.total ?? bomComponents.length],
          ["algorithms", liveCounts.algorithms ?? 0],
          ["libraries/packages", (liveCounts.libraries ?? 0) + (liveCounts.packages ?? 0)],
          ["quantum vulnerable", qVuln]].map(([k, v]) => (
          <div className="kpi" key={k as string}><span className="k">{k}</span>
            <span className="v" style={{ color: k === "quantum vulnerable" && Number(v) ? "var(--red)" : undefined }}>{v as number}</span></div>
        ))}
      </div>

      <Tabs tabs={VIEWS} active={tab} onChange={setTab} />

      {/* ── interactive dependency graph ─────────────────────────────── */}
      {tab === 0 && (
        <Panel
          title="CBOM dependency graph"
          sub={bomComponents.length
            ? "components colored by quantum verdict · click a node for detail"
            : "populates after a scan enumerates crypto components"}
        >
          {bomComponents.length === 0 ? (
            <div className="dim" style={{ fontSize: 13, padding: "30px 6px", textAlign: "center" }}>
              No crypto components yet — run runtime + universal/container scans in
              Operations → Realtime scanners. The graph is built from observed components only.
            </div>
          ) : (
            <>
              <div className="graphwrap">
                <svg viewBox="0 0 800 500" width="100%" style={{ minWidth: 720 }}>
                  {bomDependencies.filter((d) => d.ref).map((d, i) =>
                    (d.dependsOn ?? []).map((target) => {
                      const a = nodeByRef.get(d.ref!);
                      const b = nodeByRef.get(target);
                      if (!a || !b) return null;
                      const hit = quantumOf(a) === "vulnerable" || quantumOf(b) === "vulnerable";
                      return (
                        <line key={`${i}-${target}`} className={`cbom-edge ${hit ? "hit" : ""}`}
                          x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
                      );
                    })
                  )}
                  {nodes.map((n, i) => {
                    const ref = n.ref || `${n.type || "comp"}-${i}`;
                    const q = quantumOf(n);
                    const col = q !== "unknown" ? QUANTUM_COLOR[q] : (TYPE_COLOR[String(n.type)] ?? "#1e3a52");
                    const isSel = selNode === ref;
                    return (
                      <g key={ref} className={`cbom-node ${isSel ? "sel" : ""}`} onClick={() => setSelNode(isSel ? null : ref)}>
                        <circle className="node-ring" cx={n.x} cy={n.y} r={30} stroke={col} />
                        <text x={n.x} y={n.y - 1}>{(n.name || "?").slice(0, 10)}</text>
                        <text className="gsub" x={n.x} y={n.y + 12}>{n.version || n.type || ""}</text>
                      </g>
                    );
                  })}
                </svg>
              </div>
              <div className="cbom-legend">
                <span><span className="sw" style={{ background: QUANTUM_COLOR.vulnerable }} />quantum vulnerable</span>
                <span><span className="sw" style={{ background: QUANTUM_COLOR.at_risk }} />at risk</span>
                <span><span className="sw" style={{ background: QUANTUM_COLOR.safe }} />safe</span>
                <span><span className="sw" style={{ background: QUANTUM_COLOR.unknown }} />unclassified</span>
                <span><span className="sw" style={{ background: "#00d4ff" }} />crypto component</span>
              </div>
              {selectedComp && (
                <div className="detail-kv" style={{ marginTop: 16 }}>
                  <span className="k">component</span><span className="v mono">{selectedComp.name}</span>
                  <span className="k">version</span><span className="v mono">{selectedComp.version || "—"}</span>
                  <span className="k">type</span><span className="v">{selectedComp.type || "—"}</span>
                  <span className="k">source</span><span className="v">{selectedComp.source || "—"}</span>
                  <span className="k">quantum</span>
                  <span className="v">{selectedComp.quantum_status
                    ? <Badge tone={QUANTUM_COLOR[quantumOf(selectedComp)] === "#ef4444" ? "red" : QUANTUM_COLOR[quantumOf(selectedComp)] === "#f59e0b" ? "amber" : "green"}>{selectedComp.quantum_status}</Badge>
                    : "unclassified"}</span>
                  <span className="k">migration</span><span className="v">{selectedComp.migration_priority ?? "—"}</span>
                </div>
              )}
            </>
          )}
        </Panel>
      )}

      {/* ── explorer ─────────────────────────────────────────────────── */}
      {tab === 1 && (
        <Panel title="CBOM explorer" sub="all components and their dependencies">
          <Table
            head={["type", "component", "version", "source", "quantum status", "priority"]}
            rows={bomComponents.map((c) => [
              <Badge tone="cyan">{c.type}</Badge>,
              <span className="mono" style={{ fontWeight: 600 }}>{c.name}</span>,
              <span className="num">{c.version || "—"}</span>,
              c.source,
              c.quantum_status
                ? <Badge tone={QUANTUM_COLOR[quantumOf(c)] === "#ef4444" ? "red" : QUANTUM_COLOR[quantumOf(c)] === "#f59e0b" ? "amber" : "green"}>{c.quantum_status}</Badge>
                : <span className="faint">{c.status || "unclassified"}</span>,
              <span>{c.migration_priority ?? "—"}</span>,
            ])}
          />
          {!bomComponents.length && (
            <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>
              No crypto components yet — run runtime + universal/container scans.
            </div>
          )}
        </Panel>
      )}

      {/* ── diff ─────────────────────────────────────────────────────── */}
      {tab === 2 && (
        <Panel title="CBOM diff" sub="exactly what changed between versions">
          {bomDiff.added.length || bomDiff.removed.length || bomDiff.changed.length ? (
            <Table
              head={["change", "components"]}
              rows={[
                ["added", bomDiff.added.map((a: string) => <Badge key={a} tone="green">+ {a}</Badge>)],
                ["removed", bomDiff.removed.map((a: string) => <Badge key={a} tone="red">− {a}</Badge>)],
                ["changed", bomDiff.changed.map((a: string) => <Badge key={a} tone="amber">~ {a}</Badge>)],
              ]}
            />
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>No diff available — run scans to build version history, then compare current vs previous / baseline / date / environment.</div>
          )}
        </Panel>
      )}

      {/* ── history ──────────────────────────────────────────────────── */}
      {tab === 3 && (
        <Panel title="CBOM history" sub="full version lineage — audit-safe">
          {bomHistory.length ? (
            <Table
              head={["version", "time", "change", "by"]}
              rows={bomHistory.map((h) => [
                <span className="mono" style={{ fontWeight: 600 }}>{h.version}</span>,
                <span className="mono">{h.at}</span>,
                h.note,
                <span className="mono">{h.by}</span>,
              ])}
            />
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>No versions yet — the CBOM is created on the first scan.</div>
          )}
        </Panel>
      )}

      {/* ── real CycloneDX export ────────────────────────────────────── */}
      {tab === 4 && (
        <Panel title="CycloneDX 1.6 export" sub="assembled from the live scan-derived BOM — download or copy">
          <div className="export-bar">
            <span className="export-stat"><b>{bomComponents.length}</b> components · <b>{bomDependencies.filter((d) => d.ref).length}</b> dependency edges · specVersion <b>1.6</b></span>
            <span style={{ marginInlineStart: "auto" }} />
            <button className="btn sm primary"
              onClick={() => download(`cryptoscan-cbom-v${cbomVersion || 1}.json`, JSON.stringify(cyclonedx, null, 2), "application/json")}
              disabled={!bomComponents.length}>
              Download .json
            </button>
            <button className="btn sm"
              onClick={() => download(`cryptoscan-cbom-v${cbomVersion || 1}.xml`,
                `<?xml version="1.0" encoding="UTF-8"?>\n<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="${cbomVersion || 1}">\n  <components>${bomComponents.map((c) => `\n    <component type="library"><name>${c.name}</name>${c.version ? `<version>${c.version}</version>` : ""}</component>`).join("")}\n  </components>\n</bom>\n`,
                "application/xml")}
              disabled={!bomComponents.length}>
              Download .xml
            </button>
            <button className="btn sm" onClick={() => void doCopy()} disabled={!bomComponents.length}>
              {copied ? "Copied ✓" : "Copy JSON"}
            </button>
          </div>
          {bomComponents.length ? (
            <Code>{JSON.stringify(cyclonedx, null, 2)}</Code>
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>
              No components to export yet — run a scan first; the export is generated from the live BOM, never a template.
            </div>
          )}
        </Panel>
      )}

      {live?.data && (
        <Panel title="GET /api/v1/platform/bom — control-plane engine response" sub="combined CycloneDX CBOM + HBOM produced by the control plane" className="mt">
          {live.source === "live"
            ? <Code>{JSON.stringify(live.data, null, 2)}</Code>
            : <div className="dim" style={{ fontSize: 13 }}>Backend offline — control-plane BOM unavailable.</div>}
          <div style={{ marginTop: 8 }}><LiveBadge source={live.source} label={live.source === "live" ? "live API result" : "backend offline"} /></div>
        </Panel>
      )}
    </>
  );
}
