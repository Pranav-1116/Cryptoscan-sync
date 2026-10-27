import React, { useEffect, useMemo, useState } from "react";
import { Badge, Panel, Table } from "./ui";
import { apiCbomPortfolio, PortfolioCbom } from "../lib/api";
import AuthenticatedDownload from "./AuthenticatedDownload";
import { CountUp } from "../lib/motion";

export type SystemRow = { ref: string; name: string; criticality: string; businessUnit: string; coverage: string; assets: number; dependsOn: string[]; dependents: string[] };

/** Pure: turn the estate CBOM's dependencies[] into one row per system (exported for tests). */
export function systemRows(bom: PortfolioCbom): SystemRow[] {
  const byRef = new Map(bom.components.map((c) => [c["bom-ref"], c]));
  const deps = new Map((bom.dependencies || []).map((d) => [d.ref, d.dependsOn]));
  const prop = (ref: string, key: string) => (byRef.get(ref)?.properties || []).find((p) => p.name === `cryptoscan:system:${key}`)?.value || "";
  const systems = bom.components.filter((c) => c["bom-ref"].startsWith("system:"));
  const dependents = new Map<string, string[]>();
  systems.forEach((s) => (deps.get(s["bom-ref"]) || []).filter((t) => t.startsWith("system:")).forEach((t) => dependents.set(t, [...(dependents.get(t) || []), s.name])));
  return systems.map((s) => {
    const targets = deps.get(s["bom-ref"]) || [];
    return {
      ref: s["bom-ref"], name: s.name,
      criticality: prop(s["bom-ref"], "criticality"), businessUnit: prop(s["bom-ref"], "business_unit"), coverage: prop(s["bom-ref"], "coverage_status"),
      assets: targets.filter((t) => !t.startsWith("system:")).length,
      dependsOn: targets.filter((t) => t.startsWith("system:")).map((t) => byRef.get(t)?.name || t.slice(7)),
      dependents: dependents.get(s["bom-ref"]) || [],
    };
  }).sort((a, b) => b.dependents.length - a.dependents.length || b.assets - a.assets || a.name.localeCompare(b.name));
}

const tone = (c: string) => (/critical/i.test(c) ? "red" : /high/i.test(c) ? "orange" : "green");

/** System-level dependency graph carried by the estate CBOM (GET /api/v1/cbom/portfolio). */
export default function PortfolioDependencyPanel() {
  const [bom, setBom] = useState<PortfolioCbom | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "offline">("loading");
  useEffect(() => {
    let alive = true;
    (async () => {
      const r = await apiCbomPortfolio();
      if (!alive) return;
      if (r.source === "live" && r.data) { setBom(r.data); setState("ready"); } else setState("offline");
    })();
    return () => { alive = false; };
  }, []);
  const rows = useMemo(() => (bom ? systemRows(bom) : []), [bom]);
  const edges = rows.reduce((n, r) => n + r.dependsOn.length, 0);
  return (
    <Panel title="Estate dependency graph (CycloneDX)" sub="Estate, systems and cryptographic asset dependencies — the same graph auditors receive in the signed export" className="mt">
      <div style={{ display: "flex", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <AuthenticatedDownload path="/api/v1/cbom/portfolio?signed=true" filename="crypto-portfolio.json" className="btn sm outline">Signed JSON</AuthenticatedDownload>
        <AuthenticatedDownload path="/api/v1/cbom/portfolio?fmt=xml" filename="crypto-portfolio.xml" className="btn sm outline">XML</AuthenticatedDownload>
        {state === "ready" && (
          <span style={{ fontSize: 12, color: "var(--dim)", alignSelf: "center" }}>
            <CountUp value={rows.length} /> systems · <CountUp value={edges} /> system→system edges
          </span>
        )}
      </div>
      {state === "offline" && <p style={{ color: "var(--dim)", fontSize: 13 }}>Backend offline.</p>}
      {state === "loading" && <p style={{ color: "var(--dim)", fontSize: 13 }}>Loading…</p>}
      {state === "ready" && rows.length === 0 && <p style={{ color: "var(--dim)", fontSize: 13 }}>No systems registered yet — import <code>cryptoscan-systems.yml</code> or register systems, then scan.</p>}
      {state === "ready" && rows.length > 0 && (
        <Table head={["System", "Criticality", "Business unit", "Coverage", "Crypto assets", "Depends on", "Depended on by"]}
          rows={rows.slice(0, 200).map((r) => [
            <span key="n" style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{r.name}</span>,
            r.criticality ? <Badge key="c" tone={tone(r.criticality)}>{r.criticality}</Badge> : "—",
            r.businessUnit || "—", r.coverage || "—", r.assets,
            r.dependsOn.length ? r.dependsOn.join(", ") : "—",
            r.dependents.length ? <span key="d" style={{ color: r.dependents.length > 2 ? "var(--red)" : undefined }}>{r.dependents.join(", ")}</span> : "—",
          ])} />
      )}
    </Panel>
  );
}
