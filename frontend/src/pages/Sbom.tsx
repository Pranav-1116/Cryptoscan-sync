import React, { useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import BomCrossNav from "../components/BomCrossNav";
import { CanonicalDetailLink } from "../components/AssetDetail";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring, Drawer } from "../components/ui";
import { usePollingApi, useApi } from "../lib/apiUi.jsx";
import {
  apiSbomOverview, apiSbomInventory, apiSbomComponentDetail, apiSbomDependencies,
  apiSbomLicenses, apiSbomVulnerabilities, apiSbomVersions, apiSbomContainers,
  apiSbomBinaries, apiSbomEvidence, apiSbomHistory, apiSbomExportStatus,
  type SbomInventoryRow, type SbomComponentDetail,
} from "../lib/api.js";
import { apiTechBomLive, apiTechBomSnapshot, fmtSnapshotId, TechBomState } from "../lib/api.js";
import { IconComponent, IconTarget, IconClock, IconSecurity, IconCrypto, IconHardware, IconInfo, IconCertificate, IconCloud } from "../components/icons";

const TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "SBOM Overview" },
  { id: "inventory", label: "Software Inventory" },
  { id: "components", label: "Package & Component Explorer" },
  { id: "dependencies", label: "Dependency Tree" },
  { id: "licenses", label: "License Intelligence" },
  { id: "vulnerabilities", label: "Vulnerability Intelligence" },
  { id: "versions", label: "Version & Lifecycle" },
  { id: "containers", label: "Container SBOM" },
  { id: "binaries", label: "Binary SBOM" },
  { id: "evidence", label: "SBOM Evidence" },
  { id: "history", label: "SBOM History" },
  { id: "export", label: "Export & Validation" },
];

/* A read that did not return is never an inventory of zero rows. */
function SectionState({ read, noun, children }: {
  read: { data: Record<string, unknown> | null; running: boolean; source: string; detail?: string | null };
  noun: string;
  children: React.ReactNode;
}) {
  if (read.running && !read.data) return <p className="faint" style={{ fontSize: 12 }}>Reading the {noun}…</p>;
  if (read.source !== "live" || read.data == null)
    return (
      <Panel title={`${noun} not read`} sub={read.source === "live" ? "the read returned nothing" : "the control plane did not answer"}>
        <p role="status" style={{ margin: 0, fontSize: 12, color: "var(--amber)" }}>
          {read.source === "live"
            ? `The ${noun} read returned nothing — nothing is claimed here.`
            : `The ${noun} could not be read${read.detail ? ` — ${read.detail}` : ""}. An unread inventory is not an empty one.`}
        </p>
      </Panel>
    );
  return <>{children}</>;
}

function RowTable({ head, rows, colSpan }: { head: string[]; rows: React.ReactNode[]; colSpan: number }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl" style={{ width: "100%" }}>
        <thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {rows.length ? rows : (
            <tr><td colSpan={colSpan} style={{ padding: 26, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>
              <div style={{ fontWeight: 600, color: "var(--text)" }}>Nothing stored yet</div>
              <div style={{ fontSize: 11.5, marginTop: 4 }}>Empty rows here mean no stored observations — not a healthy zero.</div>
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default function Sbom() {
  const [params, setParams] = useSearchParams();
  const active = TABS.some((t) => t.id === params.get("tab")) ? params.get("tab") as string : "overview";
  const live = usePollingApi(apiTechBomLive, 15000);
  // A read that did not return is not an SBOM of zero components.
  const readOk = live.source === "live" && live.data != null;
  const state = (live.data ?? null) as TechBomState | null;
  const sbomLayer = state?.layers?.sbom;
  const components = sbomLayer?.components ?? [];
  const total = sbomLayer?.count ?? (readOk ? components.length : null);
  const estateTotal = state?.total_components ?? null;
  const [snapshotMsg, setSnapshotMsg] = useState<string | null>(null);

  const supplierCounts = useMemo(() => {
    const m: Record<string, number> = {};
    components.forEach((c) => {
      const s = String(c.supplier || "unknown").trim() || "unknown";
      m[s] = (m[s] || 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [components]);
  // The list below shows the top five; the *count* is over every component,
  // otherwise an estate with 30 suppliers reported "5".
  const bySupplier = supplierCounts.slice(0, 5);
  const uniqueSuppliers = supplierCounts.length;
  // Breadth is a share of the components that named a supplier — not of an
  // invented target like "20 suppliers".
  const namedComponents = components.filter((c) => String(c.supplier || "").trim()).length;
  const namedShare = components.length ? namedComponents / components.length : null;
  const vendorCount = state?.components_by_layer?.vendor ?? null;
  // What the newest stored estate observation contributed to this BOM. It is a
  // separate, declared source: an imported bank estate has hardware, vendors and
  // dependency edges without a live agent ever touching it, and each count below
  // is only drawn when the backend reported it.
  const observation = (state?.scan?.estate_observation ?? null) as
    | { hardware?: number; vendors?: number; dependency_edges?: number; source?: string | null; note?: string }
    | null;
  const observationHardware = observation?.hardware ?? null;
  const observationVendors = observation?.vendors ?? null;
  const observationEdges = observation?.dependency_edges ?? null;
  const observationActive = Boolean(observation?.source)
    && [observationHardware, observationVendors, observationEdges].some((value) => (value ?? 0) > 0);
  const pctOfEstate = total && estateTotal ? total / estateTotal : null;
  const ringTone = total ? "violet" as const : "slate" as const;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <BomCrossNav current="SBOM" />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} /> BOMS · SBOM · SOFTWARE SUPPLY CHAIN
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--violet)", color: "#fff" }}><IconComponent size={18} /></span>
            Software Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Every <b style={{ color: "var(--text)" }}>software component</b> — packages, containers, dependencies — from the unified Technology BOM SBOM layer. <span style={{ color: "var(--violet)" }}>One asset model</span>, materialized for supply-chain transparency.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>CycloneDX · SPDX 2.3</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>CONTENT-ADDRESSED</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>snapshot {fmtSnapshotId(state?.snapshot_id).slice(0, 16)} · v{state?.state_version ?? 0}</span>
            {state?.dependency_count != null && (
              <>
                <span style={{ color: "var(--line-strong)" }}>·</span>
                <span style={{ fontSize: 11, color: "var(--dim)" }}>{state.dependency_count} dependency edges</span>
              </>
            )}
          </div>
          {observationActive && (
            <p data-testid="sbom-estate-observation" style={{ margin: "10px 0 0", fontSize: 11.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
              <Badge tone="amber">ESTATE OBSERVATION</Badge>{" "}
              {observationHardware ?? 0} hardware · {observationVendors ?? 0} vendor · {observationEdges ?? 0} dependency edges come from the{" "}
              {observation?.source} — declared/imported evidence, not agent fingerprints. {observation?.note}
            </p>
          )}
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={pctOfEstate ?? 0} label={readOk ? String(total) : "—"} sub="sbom" tone="violet" />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>SUPPLY CHAIN</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{!readOk ? "SBOM not read" : total ? `${pctOfEstate == null ? "estate total —" : `${Math.round(pctOfEstate*100)}% of estate`} · ${uniqueSuppliers} suppliers` : "No SBOM yet — scan to populate"}</div>
              <div style={{ marginTop: 6 }}><Bar value={pctOfEstate ?? 0} tone="violet" /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button className="btn primary" onClick={async () => {
              setSnapshotMsg(null);
              const r = await apiTechBomSnapshot();
              if (r.ok) { setSnapshotMsg("snapshot captured"); void live.run(); }
              else { setSnapshotMsg(`not captured: ${r.error || "the control plane did not confirm it"}`); }
            }} style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>Capture snapshot</button>
            {snapshotMsg && <span role="status" style={{ fontSize: 11, color: snapshotMsg.startsWith("snapshot") ? "var(--green)" : "var(--red)", textAlign: "center" }}>{snapshotMsg}</span>}
            <Link to="/live-asset-intelligence" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Technology BOM →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{state?.fingerprint ? `SHA ${state.fingerprint.slice(0,8)}…` : "no hash yet"}</span>
          </div>
        </div>
      </div>

      <div role="tablist" aria-label="SBOM sections" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "2px 0 16px" }}>
        {TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={active === t.id} title={t.label}
            onClick={() => setParams({ tab: t.id })}
            style={{
              fontSize: 11, padding: "6px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${active === t.id ? "var(--violet)" : "var(--line-strong)"}`,
              background: active === t.id ? "color-mix(in srgb, var(--violet) 14%, transparent)" : "var(--panel-2)",
              color: active === t.id ? "var(--violet)" : "var(--dim)", fontFamily: "var(--mono)", letterSpacing: ".03em",
            }}>{t.label}</button>
        ))}
      </div>

      {active === "overview" && (<>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconComponent size={12} /> SBOM COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: readOk ? "var(--text)" : "var(--slate)" }}>{readOk ? total : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{readOk ? "Software inventory" : "SBOM not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))", color: "var(--violet)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={pctOfEstate ?? 0} tone="violet" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{pctOfEstate == null ? "estate total —" : `${Math.round(pctOfEstate * 100)}% of ${estateTotal} total assets`}</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>UNIQUE SUPPLIERS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: readOk ? "var(--text)" : "var(--slate)" }}>{readOk ? uniqueSuppliers : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{readOk ? `Top supplier ${bySupplier[0]?.[0]?.slice(0,14) || "—"} · ${bySupplier[0]?.[1] ?? 0}` : "suppliers not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", color: "var(--accent)" }}><IconCloud size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={namedShare ?? 0} tone={namedShare == null ? "slate" : "cyan"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>
              {namedShare == null ? "not read" : `${Math.round(namedShare * 100)}% of components name a supplier`}
            </div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${vendorCount ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>LINKED VENDORS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: readOk ? "var(--text)" : "var(--slate)" }}>{readOk && vendorCount != null ? vendorCount : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Via VBOM mapping</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: vendorCount ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${vendorCount ? "var(--green)" : "var(--line)"} 35%, var(--line))`, color: vendorCount ? "var(--green)" : "var(--faint)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={vendorCount ? Math.min(1, vendorCount/20) : 0} tone={vendorCount ? "green" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Trace vendor → system → SBOM</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--slate)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>FINGERPRINT</div>
              <div style={{ fontSize: 13, fontWeight: 800, margin: "8px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{state?.fingerprint ? `${state.fingerprint.slice(0,12)}…` : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>v{state?.state_version ?? 0} · {state?.environment || "—"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--slate)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={pctOfEstate ?? 0} tone={total ? "violet" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{pctOfEstate == null ? "share of estate —" : "share of estate"} · HMAC-signed exports available</div>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Top suppliers" sub="by component count — who supplies your estate" style={{ padding: "14px 16px" }}>
          {bySupplier.length ? bySupplier.map(([s, n]) => (
            <div key={s} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ width: 130, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s}</span>
              <div style={{ flex: 1 }}><Bar value={total ? n / total : 0} tone="violet" /></div>
              <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 28, textAlign: "right" }}>{n}</span>
            </div>
          )) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No SBOM suppliers yet</div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>From SBOM layer · supplier field</div>
        </Panel>
        <Panel title="BOM coverage" sub="SBOM share of estate" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "2px solid var(--violet)", display: "grid", placeItems: "center", color: "var(--violet)", fontSize: 18, fontWeight: 800 }}>{pctOfEstate == null ? "—" : `${Math.round(pctOfEstate * 100)}%`}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Software footprint</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{readOk ? `${total ?? "—"} of ${estateTotal ?? "—"} in SBOM` : "not read"}</div>
              <div style={{ fontSize: 10, color: "var(--violet)", marginTop: 2 }}>{(state?.components_by_layer?.cbom ?? 0)} crypto · {(state?.components_by_layer?.hbom ?? 0)} hardware</div>
            </div>
          </div>
          <div style={{ height: 8, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${(pctOfEstate ?? 0) * 100}%`, background: "var(--violet)" }} />
            <div style={{ flex: 1, background: "var(--panel-2)" }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>● SBOM</span><span>● rest of estate</span></div>
        </Panel>
        <Panel title="Integrity" sub="snapshot + audit trail" style={{ padding: "14px 16px" }}>
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Snapshot</span><span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{fmtSnapshotId(state?.snapshot_id).slice(0, 20)}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Version</span><Badge tone="violet">v{state?.state_version ?? 0}</Badge></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Deps</span><span style={{ fontFamily: "var(--mono)" }}>{state?.dependency_count ?? "—"} edges</span></div>
            <div style={{ padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{state?.fingerprint || "— no fingerprint yet"}</div>
          </div>
        </Panel>
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--violet)" }} /> Software Inventory</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>SBOM layer · CycloneDX / SPDX · <span style={{ color: "var(--violet)" }}>every component is traceable to a vendor</span></p>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Badge tone="violet">{total} components</Badge>
            <Badge tone="slate">{uniqueSuppliers} suppliers</Badge>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead><tr><th>Component</th><th>Version</th><th>Supplier</th><th>BOM-Ref</th><th>Type</th></tr></thead>
            <tbody>
              {components.slice(0, 100).map((c) => (
                <tr key={c["bom-ref"] || c.name}>
                  <td><span style={{ fontWeight: 700, fontSize: 12 }}>{c.name || "—"}</span></td>
                  <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{c.version || "—"}</span></td>
                  <td><Badge tone="slate">{String(c.supplier || "—").slice(0, 24)}</Badge></td>
                  <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{(c["bom-ref"] || "—").slice(0, 20)}</span></td>
                  <td><Badge tone="violet">{String((c as any).type || "—")}</Badge></td>
                </tr>
              ))}
              {!components.length && <tr><td colSpan={5} style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>No SBOM yet</div><div style={{ fontSize: 12, marginTop: 4 }}>Run discovery + capture snapshot — empty is not fabricated</div></td></tr>}
              {components.length > 100 && <tr><td colSpan={5} style={{ padding: 12, textAlign: "center", color: "var(--faint)", fontSize: 11 }}>Showing 100 of {components.length} — export full SBOM via Technology BOM</td></tr>}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <Link to="/vendor" style={{ color: "var(--violet)" }}>VBOM → trace vendors</Link>
          <span>·</span>
          <Link to="/live-asset-intelligence" style={{ color: "var(--accent)" }}>Full Technology BOM →</Link>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>ONE asset model · four layers</span>
        </div>
      </div>
      </>)}
      {active === "inventory" && <SbomInventory />}
      {active === "components" && <SbomInventory explorer />}
      {active === "dependencies" && <SbomDependencies />}
      {active === "licenses" && <SbomLicenses />}
      {active === "vulnerabilities" && <SbomVulnerabilities />}
      {active === "versions" && <SbomVersions />}
      {active === "containers" && <SbomContainers />}
      {active === "binaries" && <SbomBinaries />}
      {active === "evidence" && <SbomEvidence />}
      {active === "history" && <SbomHistory />}
      {active === "export" && <SbomExport />}
    </div>
  );
}

/* ── sections (docs/boms/01_PRODUCT_SPEC.md §1 navigation) ──────────── */

function SbomInventory({ explorer = false }: { explorer?: boolean }) {
  const [q, setQ] = useState("");
  const read = useApi(() => apiSbomInventory(q || undefined), [q]);
  const rows = (read.data?.rows ?? []) as SbomInventoryRow[];
  const [selected, setSelected] = useState<SbomInventoryRow | null>(null);
  const detail = useApi(
    () => apiSbomComponentDetail(encodeURIComponent(selected?.coordinate ?? "")),
    [selected?.coordinate],
  );
  return (
    <>
      <Panel title={explorer ? "Package & Component Explorer" : "Software Inventory"}
        sub="every row is a stored scan record — click a component for identity, dependencies and evidence">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="search by component, coordinate or version"
            aria-label="search components"
            style={{ flex: 1, minWidth: 220, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--panel-2)", color: "var(--text)", fontSize: 12 }} />
          <Badge tone="slate">{read.data?.total ?? (read.source === "live" ? rows.length : "—")} components</Badge>
        </div>
        <SectionState read={read} noun="inventory">
          <RowTable
            head={["Component", "Version", "Ecosystem", "Application", "Source", "License", "Vulnerability", "Evidence", "Last observed"]}
            colSpan={9}
            rows={rows.map((r) => (
              <tr key={r.coordinate} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span>{r.purl && <div style={{ fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)" }}>{r.purl}</div>}</td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.version || "—"}</span></td>
                <td><Badge tone="slate">{r.ecosystem || "—"}</Badge></td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.application || "—"}</span></td>
                <td><Badge tone={r.source === "MANIFEST_DECLARED" ? "slate" : "violet"}>{r.source || "UNKNOWN"}</Badge></td>
                <td>{r.license ? <Badge tone="pass">{r.license}</Badge> : <Badge tone="slate">NOT_COLLECTED</Badge>}</td>
                <td>{r.vulnerability.count
                  ? <Badge tone={r.vulnerability.max_severity === "CRITICAL" || r.vulnerability.max_severity === "HIGH" ? "red" : "amber"}>{r.vulnerability.count} · {r.vulnerability.max_severity}</Badge>
                  : <span style={{ fontSize: 11, color: "var(--faint)" }}>none linked</span>}</td>
                <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{r.evidence.type || "—"}</span></td>
                <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{r.last_observed ? String(r.last_observed).slice(0, 19) : "—"}</span></td>
              </tr>
            ))}
          />
        </SectionState>
      </Panel>
      {selected && (
        <Drawer title={selected.name} sub={selected.coordinate} onClose={() => setSelected(null)}>
          <CanonicalDetailLink assetRef={selected.asset_ref} />
          {!detail.data ? <p className="faint" style={{ fontSize: 12 }}>{detail.running ? "Reading the component…" : "The component detail did not return."}</p> : (
            (() => {
              const d = detail.data as SbomComponentDetail;
              return (
                <div style={{ display: "grid", gap: 12 }}>
                  <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
                    <div><b>Identity</b> <span style={{ fontFamily: "var(--mono)" }}>{d.component.purl || d.component.coordinate}</span></div>
                    <div><b>Version</b> {d.component.version || "—"} · <b>Supplier</b> {d.supplier || <Badge tone="slate">NOT_COLLECTED</Badge>}</div>
                    <div><b>Source</b> {d.component.source || "—"}{d.manifests.length ? ` · declared in ${d.manifests.join(", ")}` : ""}</div>
                    <div><b>License</b> {d.component.license || <Badge tone="slate">NOT_COLLECTED</Badge>}</div>
                    <div><b>Last observed</b> {d.component.last_observed ? String(d.component.last_observed).slice(0, 19) : "—"}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>CRYPTOGRAPHIC USAGE — STATES ARE NOT EQUIVALENT</div>
                    {d.usage_states.length ? d.usage_states.map((u) => (
                      <div key={u.algorithm} style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6, fontSize: 12 }}>
                        <Badge tone={u.usage_state === "operation_observed" ? "green" : u.usage_state === "configuration_observed" ? "amber" : "slate"}>{u.usage_state}</Badge>
                        <span style={{ fontFamily: "var(--mono)" }}>{u.algorithm}</span>
                        <span style={{ fontSize: 10.5, color: "var(--faint)" }}>basis {u.basis}{u.runtime_evidence.length ? ` · ${u.runtime_evidence.length} runtime observation(s)` : ""}</span>
                      </div>
                    )) : <div style={{ fontSize: 11.5, color: "var(--dim)" }}>No cryptographic records name this component.</div>}
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>DEPENDENCIES</div>
                    {d.dependencies.direct.map((e, i) => (
                      <div key={i} style={{ fontSize: 11.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>→ {String(e.target)} <span style={{ color: "var(--faint)" }}>{String(e.type || "")}</span></div>
                    ))}
                    {d.dependencies.transitive.length > 0 && (
                      <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>+ {d.dependencies.transitive.length} transitive edge(s)</div>
                    )}
                    {!d.dependencies.direct.length && !d.dependencies.transitive.length && (
                      <div style={{ fontSize: 11.5, color: "var(--dim)" }}>{d.dependencies.unresolved_parent ? "Parent unresolved — no edges claimed." : "No resolved dependency edges."}</div>
                    )}
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>VULNERABILITY REFERENCES</div>
                    {d.vulnerabilities.length ? d.vulnerabilities.map((v, i) => (
                      <div key={i} style={{ fontSize: 11.5, marginBottom: 4 }}><Badge tone="red">{String(v.severity)}</Badge> <span style={{ fontFamily: "var(--mono)" }}>{String(v.cve)}</span> {String(v.summary ?? "")}</div>
                    )) : <div style={{ fontSize: 11.5, color: "var(--dim)" }}>None linked.</div>}
                  </div>
                  {(d.flags.declared_but_unused || d.flags.used_but_undeclared) && (
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {d.flags.declared_but_unused && <Badge tone="amber">DECLARED_BUT_UNUSED</Badge>}
                      {d.flags.used_but_undeclared && <Badge tone="red">USED_BUT_UNDECLARED</Badge>}
                    </div>
                  )}
                  {d.versions.length > 1 && (
                    <div style={{ fontSize: 11.5, color: "var(--dim)" }}>Versions seen: <span style={{ fontFamily: "var(--mono)" }}>{d.versions.join(", ")}</span></div>
                  )}
                </div>
              );
            })()
          )}
        </Drawer>
      )}
    </>
  );
}

function SbomDependencies() {
  const read = useApi(apiSbomDependencies);
  const edges = (read.data?.edges ?? []) as Array<Record<string, string>>;
  const roots = (read.data?.roots ?? []) as string[];
  return (
    <Panel title="Dependency Tree" sub="parent → child edges exist only where the lockfile stated the relationship">
      <SectionState read={read} noun="dependency tree">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <Badge tone="violet">{edges.length} resolved edges</Badge>
          <Badge tone="slate">{roots.length} root components</Badge>
          {Number(read.data?.unresolved ?? 0) > 0 && <Badge tone="amber">{String(read.data?.unresolved)} unresolved</Badge>}
        </div>
        <RowTable head={["Source", "Target", "Type"]} colSpan={3}
          rows={edges.slice(0, 300).map((e, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(e.source)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(e.target)}</span></td>
              <td><Badge tone="slate">{String(e.type || "declared_dependency")}</Badge></td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomLicenses() {
  const read = useApi(apiSbomLicenses);
  const counts = (read.data?.counts ?? {}) as Record<string, number>;
  const total = Number(read.data?.total ?? 0);
  return (
    <Panel title="License Intelligence" sub="a missing license is NOT_COLLECTED, never an assumed permissive one">
      <SectionState read={read} noun="license inventory">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <Badge tone="pass">{String(read.data?.collected ?? 0)} with license</Badge>
          <Badge tone="slate">{total - Number(read.data?.collected ?? 0)} NOT_COLLECTED</Badge>
        </div>
        {Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, n]) => (
          <div key={name} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
            <span style={{ width: 140, fontSize: 11, fontFamily: "var(--mono)", color: name === "NOT_COLLECTED" ? "var(--faint)" : "var(--text)" }}>{name}</span>
            <div style={{ flex: 1 }}><Bar value={total ? n / total : 0} tone={name === "NOT_COLLECTED" ? "slate" : "green"} /></div>
            <span style={{ fontSize: 11, fontFamily: "var(--mono)", minWidth: 28, textAlign: "right" }}>{n}</span>
          </div>
        ))}
      </SectionState>
    </Panel>
  );
}

function SbomVulnerabilities() {
  const read = useApi(apiSbomVulnerabilities);
  const matched = (read.data?.matched ?? []) as Array<Record<string, unknown>>;
  const unmatched = (read.data?.unmatched ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Vulnerability Intelligence" sub="records joined to stored components; unmatched records never land on a lookalike package">
      <SectionState read={read} noun="vulnerability inventory">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <Badge tone="red">{matched.length} matched</Badge>
          <Badge tone="amber">{unmatched.length} unmatched</Badge>
        </div>
        <RowTable head={["CVE", "Package", "Severity", "Summary"]} colSpan={4}
          rows={[...matched, ...unmatched].slice(0, 200).map((v, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(v.cve)}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{String(v.package)}{matched.includes(v) ? "" : <Badge tone="amber">UNMATCHED</Badge>}</span></td>
              <td><Badge tone={String(v.severity).toUpperCase() === "HIGH" || String(v.severity).toUpperCase() === "CRITICAL" ? "red" : "amber"}>{String(v.severity)}</Badge></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{String(v.summary ?? "")}</span></td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomVersions() {
  const read = useApi(apiSbomVersions);
  const multi = (read.data?.multi_version ?? []) as Array<Record<string, unknown>>;
  const drift = (read.data?.drift_signals ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Version & Lifecycle" sub="version sets and drift signals as the scan recorded them">
      <SectionState read={read} noun="version inventory">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <Badge tone="violet">{multi.length} multi-version</Badge>
          <Badge tone={drift.length ? "amber" : "slate"}>{drift.length} drift signals</Badge>
        </div>
        <RowTable head={["Component", "Versions", "Drift"]} colSpan={3}
          rows={[...multi.map((m): Record<string, unknown> => ({ ...m, drift: false })), ...drift.map((d): Record<string, unknown> => ({ ...d, drift: true }))].slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 11.5, fontWeight: 600 }}>{String(r.name)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{Array.isArray(r.versions) ? (r.versions as string[]).join(", ") : "—"}</span></td>
              <td>{r.drift
                ? <span style={{ display: "flex", gap: 6 }}>{r.declared_but_unused ? <Badge tone="amber">DECLARED_BUT_UNUSED</Badge> : null}{r.used_but_undeclared ? <Badge tone="red">USED_BUT_UNDECLARED</Badge> : null}</span>
                : <span style={{ fontSize: 11, color: "var(--faint)" }}>—</span>}</td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomContainers() {
  const read = useApi(apiSbomContainers);
  const rows = (read.data?.rows ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Container SBOM" sub="stored container scans — package and library counts as reported">
      <SectionState read={read} noun="container inventory">
        <RowTable head={["Target", "Packages", "Libraries", "Vulnerabilities", "Scanned"]} colSpan={5}
          rows={rows.slice(0, 100).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 11.5, fontWeight: 600 }}>{String(r.target)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.package_count ?? 0)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.library_count ?? 0)}</span></td>
              <td>{Number(r.vuln_count ?? 0) ? <Badge tone="red">{String(r.vuln_count)}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>0 reported</span>}</td>
              <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(r.created_at ?? "—").slice(0, 19)}</span></td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomBinaries() {
  const read = useApi(apiSbomBinaries);
  const rows = (read.data?.rows ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Binary SBOM" sub="binary scan artifacts — content-addressed, format as stored">
      <SectionState read={read} noun="binary inventory">
        <RowTable head={["Artifact", "Target", "Format", "SHA-256", "Status", "Files walked"]} colSpan={6}
          rows={rows.slice(0, 100).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.artifact_id).slice(0, 12)}…</span></td>
              <td><span style={{ fontSize: 11.5 }}>{String(r.target)}</span></td>
              <td><Badge tone="slate">{String(r.format)}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{String(r.sha256).slice(0, 16)}…</span></td>
              <td><Badge tone={String(r.status) === "COMPLETED" ? "pass" : "amber"}>{String(r.status)}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.files_walked ?? 0)}</span></td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomEvidence() {
  const read = useApi(apiSbomEvidence);
  const sources = (read.data?.component_evidence ?? {}) as Record<string, number>;
  const documents = (read.data?.documents ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="SBOM Evidence" sub="evidence references as the collector supplied them — never a guessed source">
      <SectionState read={read} noun="evidence inventory">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          {Object.entries(sources).map(([k, n]) => <Badge key={k} tone="slate">{k}: {n}</Badge>)}
          {!Object.keys(sources).length && <Badge tone="slate">no component evidence recorded</Badge>}
        </div>
        <RowTable head={["SBOM digest", "Artifact", "Components", "Unresolved", "Assertion", "Stored"]} colSpan={6}
          rows={documents.slice(0, 100).map((d, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(d.sbom_sha256).slice(0, 18)}…</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(d.sbom_artifact_id).slice(0, 12)}…</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(d.component_count)}</span></td>
              <td>{Number(d.unresolved_component_count ?? 0) ? <Badge tone="amber">{String(d.unresolved_component_count)}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>0</span>}</td>
              <td><Badge tone="slate">{String(d.assertion_source ?? "UNKNOWN")}</Badge></td>
              <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(d.created_at ?? "—").slice(0, 19)}</span></td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomHistory() {
  const read = useApi(apiSbomHistory);
  const snapshots = (read.data?.snapshots ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="SBOM History" sub="content-addressed technology-BOM snapshots; compare lives on the snapshot compare route">
      <SectionState read={read} noun="snapshot history">
        <RowTable head={["Snapshot", "Version", "Captured"]} colSpan={3}
          rows={snapshots.slice(0, 100).map((s, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(s.snapshot_id).slice(0, 20)}…</span></td>
              <td><Badge tone="violet">v{String(s.version)}</Badge></td>
              <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(s.created_at ?? "—").slice(0, 19)}</span></td>
            </tr>
          ))} />
      </SectionState>
    </Panel>
  );
}

function SbomExport() {
  const read = useApi(apiSbomExportStatus);
  const formats = (read.data?.formats ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Export & Validation" sub="validators run over the stored document; export writes authorized records only">
      <SectionState read={read} noun="export inventory">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <Badge tone="pass">{String(read.data?.stored_documents ?? 0)} stored documents</Badge>
          {Number(read.data?.unresolved_components ?? 0) > 0 && <Badge tone="amber">{String(read.data?.unresolved_components)} unresolved components</Badge>}
        </div>
        <RowTable head={["Format", "Validator", "State"]} colSpan={3}
          rows={formats.map((f, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{String(f.format)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{String(f.validator)}</span></td>
              <td><Badge tone="pass">{String(f.state)}</Badge></td>
            </tr>
          ))} />
        <div style={{ marginTop: 12, fontSize: 11.5, color: "var(--dim)" }}>
          Full-BOM export: <Link to="/live-asset-intelligence" style={{ color: "var(--accent)" }}>Technology BOM export →</Link>
        </div>
      </SectionState>
    </Panel>
  );
}
