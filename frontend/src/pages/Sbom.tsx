import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { usePollingApi } from "../lib/apiUi.jsx";
import { apiTechBomLive, apiTechBomSnapshot, fmtSnapshotId, TechBomState } from "../lib/api.js";
import { IconComponent, IconTarget, IconClock, IconSecurity, IconCrypto, IconHardware, IconInfo, IconCertificate, IconCloud } from "../components/icons";

export default function Sbom() {
  const live = usePollingApi(apiTechBomLive, 15000);
  const state = (live.data ?? null) as TechBomState | null;
  const sbomLayer = state?.layers?.sbom;
  const components = sbomLayer?.components ?? [];
  const total = sbomLayer?.count ?? components.length;
  const estateTotal = state?.total_components ?? 0;

  const bySupplier = useMemo(() => {
    const m: Record<string, number> = {};
    components.forEach((c) => {
      const s = String(c.supplier || "unknown").trim() || "unknown";
      m[s] = (m[s] || 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [components]);

  const uniqueSuppliers = bySupplier.length;
  const vendorCount = state?.components_by_layer?.vendor ?? 0;
  const pctOfEstate = estateTotal ? total / estateTotal : 0;
  const ringPct = estateTotal ? Math.min(1, total / Math.max(50, estateTotal * 0.6)) : Math.min(1, total / 80);
  const ringTone = total ? "violet" as const : "slate" as const;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid var(--violet)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: "0.06em" }}>
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
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={pctOfEstate} label={String(total)} sub="sbom" tone="violet" />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>SUPPLY CHAIN</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{total ? `${Math.round(pctOfEstate*100)}% of estate · ${uniqueSuppliers} suppliers` : "No SBOM yet — scan to populate"}</div>
              <div style={{ marginTop: 6 }}><Bar value={pctOfEstate} tone="violet" /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <button className="btn primary" onClick={async () => { const r = await apiTechBomSnapshot(); if (r.ok) live.run(); }} style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>Capture snapshot</button>
            <Link to="/live-asset-intelligence" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Technology BOM →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{state?.fingerprint ? `SHA ${state.fingerprint.slice(0,8)}…` : "no hash yet"}</span>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconComponent size={12} /> SBOM COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{total}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Software inventory</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)", color: "var(--violet)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={estateTotal ? total / estateTotal : 0} tone="violet" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{estateTotal ? `${Math.round((total/estateTotal)*100)}% of ${estateTotal} total assets` : "estate total —"}</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>UNIQUE SUPPLIERS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{uniqueSuppliers}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Top supplier {bySupplier[0]?.[0]?.slice(0,14) || "—"} · {bySupplier[0]?.[1] ?? 0}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconCloud size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={uniqueSuppliers ? Math.min(1, uniqueSuppliers/20) : 0} tone="cyan" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Supply-chain breadth</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${vendorCount ? "var(--green)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>LINKED VENDORS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{vendorCount}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Via VBOM mapping</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: vendorCount ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${vendorCount ? "var(--green)" : "var(--line)"}`, color: vendorCount ? "var(--green)" : "var(--faint)" }}><IconHardware size={16} /></span>
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
            <Bar value={ringPct} tone={total ? "violet" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>HMAC-signed exports available</div>
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
            <div style={{ width: 54, height: 54, borderRadius: 999, background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "2px solid var(--violet)", display: "grid", placeItems: "center", color: "var(--violet)", fontSize: 18, fontWeight: 800 }}>{Math.round(pctOfEstate*100)}%</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Software footprint</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{total} of {estateTotal || "—"} in SBOM</div>
              <div style={{ fontSize: 10, color: "var(--violet)", marginTop: 2 }}>{(state?.components_by_layer?.cbom ?? 0)} crypto · {(state?.components_by_layer?.hbom ?? 0)} hardware</div>
            </div>
          </div>
          <div style={{ height: 8, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${pctOfEstate*100}%`, background: "var(--violet)" }} />
            <div style={{ flex: 1, background: "var(--panel-2)" }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>● SBOM</span><span>● rest of estate</span></div>
        </Panel>
        <Panel title="Integrity" sub="snapshot + audit trail" style={{ padding: "14px 16px" }}>
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Snapshot</span><span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{fmtSnapshotId(state?.snapshot_id).slice(0, 20)}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Version</span><Badge tone="violet">v{state?.state_version ?? 0}</Badge></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Deps</span><span style={{ fontFamily: "var(--mono)" }}>{state?.dependency_count ?? 0} edges</span></div>
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
    </div>
  );
}
