import React, { useMemo, useState } from "react";
import BomCrossNav from "../components/BomCrossNav";
import { Link, useSearchParams } from "react-router-dom";
import { Panel, Badge, Bar, Ring, Drawer } from "../components/ui";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useApi } from "../lib/apiUi.jsx";
import {
  apiTechBomLive, apiTechBomVendor, TechBomState, TechBomVendorInventory,
  apiVbomWorkspaceOverview, apiVbomWorkspaceVendors, apiVbomWorkspaceVendorDetail,
  apiVbomWorkspaceProducts, apiVbomWorkspaceRelationships, apiVbomWorkspaceLifecycle,
  apiVbomWorkspaceSecurity, apiVbomWorkspaceCrypto, apiVbomWorkspacePqc,
  apiVbomWorkspaceExposure, apiVbomWorkspaceContracts, apiVbomWorkspaceEvidence,
  apiVbomWorkspaceHistory, apiVbomWorkspaceExport, type VbomVendorRow,
} from "../lib/api.js";
import { IconTarget, IconClock, IconSecurity, IconHardware, IconInfo, IconSearch, IconCertificate } from "../components/icons";
import { IconCrypto, IconComponent, IconCloud } from "../components/icons";

const VBOM_TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "VBOM Overview" },
  { id: "vendors", label: "Vendor Registry" },
  { id: "products", label: "Vendor Product Inventory" },
  { id: "relationships", label: "Supplier Relationships" },
  { id: "lifecycle", label: "Product & Version Lifecycle" },
  { id: "security", label: "Vendor Security Intelligence" },
  { id: "crypto", label: "Vendor Crypto Dependencies" },
  { id: "pqc", label: "Vendor PQC Roadmaps" },
  { id: "exposure", label: "Supply Chain Exposure" },
  { id: "contracts", label: "Contract & Support Metadata" },
  { id: "evidence", label: "Evidence & Provenance" },
  { id: "history", label: "VBOM History" },
  { id: "export", label: "Export & Validation" },
];

/* A read that did not return is never an inventory of zero records. */
function WsState({ read, noun, children }: {
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

function WsTable({ head, rows, colSpan }: { head: string[]; rows: React.ReactNode[]; colSpan: number }) {
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

function AssociationBadge({ state }: { state: string }) {
  const tone = state === "CONFIRMED" ? "pass" : state === "UNKNOWN" ? "slate" : "violet";
  return <Badge tone={tone}>{state}</Badge>;
}

function PqcBadge({ state }: { state: string }) {
  const tone = state === "CONFIRMED" ? "pass" : state === "REPORTED" ? "amber" : "slate";
  return <Badge tone={tone}>{state}</Badge>;
}

export default function Vbom() {
  const [wsParams, setWsParams] = useSearchParams();
  const active = VBOM_TABS.some((t) => t.id === wsParams.get("tab")) ? wsParams.get("tab") as string : "overview";
  const live = usePollingApi(apiTechBomLive, 15000);
  const vendorPoll = usePollingApi(apiTechBomVendor, 15000);
  const state = (live.data ?? null) as TechBomState | null;
  const vendorInv = (vendorPoll.data as TechBomVendorInventory | null) ?? null;
  // The vendor register is its own read: without it there is no vendor count,
  // not a vendor count of zero.
  const vendorRead = vendorPoll.source === "live" && vendorInv != null;
  const bomRead = live.source === "live" && state != null;
  const vendors = vendorInv?.vendors ?? [];
  const linkage = vendorInv?.linkage ?? [];
  const vendorCount = vendorInv?.vendor_count ?? state?.components_by_layer?.vendor ?? null;
  const vendorComponents = state?.layers?.vendor?.components ?? [];
  // Component count comes from the vendor layer; the register count is a
  // different measurement and is never substituted for it.
  const total = bomRead ? (state?.layers?.vendor?.count ?? vendorComponents.length) : null;
  const estateTotal = state?.total_components ?? null;
  const [q, setQ] = useState("");

  const filtered = useMemo(() => {
    if (!q.trim()) return vendors;
    const t = q.toLowerCase();
    return vendors.filter((v) =>
      v.name.toLowerCase().includes(t) || v.id.toLowerCase().includes(t) || String(v.vendor_type||"").toLowerCase().includes(t)
    );
  }, [vendors, q]);

  const criticalCount = vendors.filter((v) => String(v.criticality||"").toUpperCase()==="CRITICAL" || String(v.criticality||"").toUpperCase()==="HIGH").length;
  // Every bar below is a share of something that was actually measured, or it
  // is not drawn: the old ones scaled against invented denominators (30/40/80).
  const vendorShare = total != null && estateTotal ? total / estateTotal : null;
  const linkedShare = vendorRead && vendors.length ? linkage.length / vendors.length : null;
  const coveredSystems = new Set(linkage.map((l) => l.system_id || l.system)).size;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <BomCrossNav current="VBOM" />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--green) 12%, transparent)", border: "1px solid var(--green)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--green)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--green)" }} /> BOMS · VBOM · SUPPLY-CHAIN VENDORS
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--green)", color: "#fff" }}><IconCloud size={18} /></span>
            Vendor Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Every <b style={{ color: "var(--text)" }}>vendor + the systems they supply</b> — with criticality, linkage, and lifecycle. <span style={{ color: "var(--green)" }}>One asset model</span>, vendor-materialized for third-party risk.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>VENDOR → SYSTEM → COMPONENT</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>LINKED TO ESTATE</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{vendorRead ? `${linkage.length} links · ${coveredSystems} systems covered` : "vendor register not read"}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={vendorShare ?? 0} label={vendorRead ? String(vendorCount ?? 0) : "—"} sub="vendors" tone={vendorCount ? "green" : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>VENDOR FOOTPRINT</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{!vendorRead ? "vendor register not read" : vendorCount ? `${criticalCount} critical · ${linkage.length} links` : "No vendors registered"}</div>
              <div style={{ marginTop: 6 }}><Bar value={linkedShare ?? 0} tone={linkage.length ? "green" : "slate"} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Link to="/vendor" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Vendor workspace →</Link>
            <Link to="/live-asset-intelligence" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Technology BOM →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{total == null ? "vendor layer not read" : `${total} components`} · v{state?.state_version ?? 0}</span>
          </div>
        </div>
      </div>

      <div role="tablist" aria-label="VBOM sections" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "2px 0 16px" }}>
        {VBOM_TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={active === t.id} title={t.label}
            onClick={() => setWsParams({ tab: t.id })}
            style={{
              fontSize: 11, padding: "6px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${active === t.id ? "var(--green)" : "var(--line-strong)"}`,
              background: active === t.id ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)",
              color: active === t.id ? "var(--green)" : "var(--dim)", fontFamily: "var(--mono)", letterSpacing: ".03em",
            }}>{t.label}</button>
        ))}
      </div>

      {active === "overview" && (<>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--green)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCloud size={12} /> VENDORS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: vendorRead ? "var(--text)" : "var(--slate)" }}>{vendorRead ? vendorCount ?? 0 : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{vendorRead ? "In vendor inventory" : "register not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--green) 14%, transparent)", border: "1px solid var(--green)", color: "var(--green)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={linkedShare ?? 0} tone="green" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{vendorRead ? `${criticalCount} critical/high by registered criticality` : "criticality not read"}</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${linkage.length ? "var(--accent)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>VENDOR → SYSTEM LINKS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: vendorRead ? "var(--text)" : "var(--slate)" }}>{vendorRead ? linkage.length : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{coveredSystems} systems covered</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: linkage.length ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${linkage.length ? "var(--accent)" : "var(--line)"}`, color: linkage.length ? "var(--accent)" : "var(--faint)" }}><IconCrypto size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={linkedShare ?? 0} tone={linkage.length ? "cyan" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{linkedShare == null ? "links not read" : `${Math.round(linkedShare * 100)}% of registered vendors are linked to a system`}</div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Vendor supply graph</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>VBOM COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: bomRead ? "var(--text)" : "var(--slate)" }}>{bomRead ? total ?? 0 : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{bomRead ? "Materialized vendor layer" : "Technology BOM not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={vendorShare ?? 0} tone={vendorShare == null ? "slate" : "cyan"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>
              {vendorShare == null ? "share not measured" : `${Math.round(vendorShare * 100)}% of the estate's components are vendor-layer`}
            </div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--slate)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>CONTRACT POSTURE</div>
              <div style={{ fontSize: 13, fontWeight: 800, margin: "8px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{vendors.length ? "tracked" : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{vendors.filter(v=> v.contract_end_date).length} with end-date</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--slate)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={vendors.length ? vendors.filter(v=> String(v.criticality).toUpperCase()!=="LOW").length / vendors.length : 0} tone="slate" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Assessments · lifecycle</div>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Critical vendors" sub="by criticality — third-party concentration" style={{ padding: "14px 16px" }}>
          {(() => {
            const byCrit: Record<string, number> = {};
            vendors.forEach(v=> { const c= String(v.criticality||"unknown"); byCrit[c]=(byCrit[c]||0)+1; });
            const rows = Object.entries(byCrit).sort((a,b)=> b[1]-a[1]).slice(0,4);
            return rows.length ? rows.map(([c,n]) => (
              <div key={c} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <span style={{ width: 110, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{c}</span>
                <div style={{ flex: 1 }}><Bar value={vendors.length ? n/vendors.length : 0} tone={c.toUpperCase()==="CRITICAL"||c.toUpperCase()==="HIGH" ? "red" : c.toUpperCase()==="MEDIUM" ? "amber" : "green"} /></div>
                <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 28, textAlign: "right" }}>{n}</span>
              </div>
            )) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No vendor criticality yet</div>;
          })()}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Source: vendor inventory · CRITICAL/HIGH need diligence</div>
        </Panel>
        <Panel title="Supply coverage" sub="vendors → systems" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: linkage.length ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `2px solid ${linkage.length ? "var(--green)" : "var(--line)"}`, display: "grid", placeItems: "center", color: linkage.length ? "var(--green)" : "var(--faint)", fontSize: 18, fontWeight: 800 }}>{linkage.length}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Supply graph</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{vendorRead ? `${vendorCount ?? 0} vendors → ${coveredSystems} systems` : "not read"}</div>
              <div style={{ fontSize: 10, color: linkage.length ? "var(--green)" : "var(--faint)", marginTop: 2 }}>{linkage.length ? "linked" : "no links yet"}</div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800 }}>{vendorRead ? vendorCount ?? 0 : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>VENDORS</div></div>
            <div style={{ padding: "8px 6px", background: "color-mix(in srgb, var(--green) 8%, var(--panel-2))", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--green)" }}>{vendorRead ? linkage.length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>LINKS</div></div>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800 }}>{coveredSystems}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>SYSTEMS</div></div>
          </div>
        </Panel>
        <Panel title="Integrity" sub="snapshot + vendor posture" style={{ padding: "14px 16px" }}>
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Env</span><Badge tone="slate">{state?.environment || "—"}</Badge></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Vendors in VBOM layer</span><span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{total ?? "—"}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Fingerprint</span><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{state?.fingerprint ? `${state.fingerprint.slice(0,10)}…` : "—"}</span></div>
            <div style={{ padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11, color: "var(--dim)" }}>Deep dive: <Link to="/vendor-due-diligence" style={{ color: "var(--green)" }}>Due diligence →</Link> · <Link to="/vendor" style={{ color: "var(--accent)" }}>Vendors →</Link></div>
          </div>
        </Panel>
      </div>

      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--green)" }} /> Vendor Inventory</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>VBOM · <span style={{ color: "var(--green)" }}>every vendor linked to the systems they supply</span></p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "4px 8px" }}>
              <IconSearch size={12} style={{ color: "var(--faint)" }} />
              <input value={q} onChange={(e)=> setQ(e.target.value)} placeholder="filter vendors…" style={{ background: "transparent", border: 0, color: "var(--text)", fontSize: 12, outline: "none", width: 140 }} />
            </div>
            <Badge tone="green">{filtered.length} vendors</Badge>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead><tr><th>Vendor</th><th>Type</th><th>Criticality</th><th>Systems</th><th>Contract end</th><th>Supply count</th></tr></thead>
            <tbody>
              {filtered.slice(0, 60).map((v) => (
                <tr key={v.id}>
                  <td><span style={{ fontWeight: 700, fontSize: 12 }}>{v.name}</span><span style={{ fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)", marginLeft: 6 }}>{v.id.slice(0,8)}</span></td>
                  <td><Badge tone="slate">{v.vendor_type || "—"}</Badge></td>
                  <td><Badge tone={String(v.criticality).toUpperCase()==="CRITICAL"||String(v.criticality).toUpperCase()==="HIGH" ? "red" : String(v.criticality).toUpperCase()==="MEDIUM" ? "amber" : "green"}>{v.criticality || "—"}</Badge></td>
                  <td><span style={{ fontSize: 11 }}>{v.system_count} · {(v.systems||[]).slice(0,2).join(", ")}{v.system_count>2?"…":""}</span></td>
                  <td><span style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{v.contract_end_date ? new Date(v.contract_end_date).toLocaleDateString() : "—"}</span></td>
                  <td><Bar value={Math.min(1, (v.system_count||0)/8)} tone={String(v.criticality).toUpperCase()==="CRITICAL" ? "red" : "green"} /></td>
                </tr>
              ))}
              {!filtered.length && <tr><td colSpan={6} style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>No VBOM yet</div><div style={{ fontSize: 12, marginTop: 4 }}>Add vendors in Discovery → Vendors, then scan to link them</div></td></tr>}
            </tbody>
          </table>
        </div>
        {filtered.length > 60 && <div style={{ padding: "8px 16px", fontSize: 11, color: "var(--faint)", textAlign: "center", background: "var(--bg-2)", borderTop: "1px solid var(--line)" }}>Showing 60 of {filtered.length} — full list in vendor workspace</div>}
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <Link to="/live-asset-intelligence" style={{ color: "var(--accent)" }}>Technology BOM →</Link>
          <span>·</span>
          <span>{vendorRead ? `${linkage.length} vendor→system links` : "vendor links not read"}</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>ONE asset model · four layers</span>
        </div>
      </div>
      </>)}
      {active === "vendors" && <VbomVendors />}
      {active === "products" && <VbomProducts />}
      {active === "relationships" && <VbomRelationships />}
      {active === "lifecycle" && <VbomLifecycle />}
      {active === "security" && <VbomSecurity />}
      {active === "crypto" && <VbomCrypto />}
      {active === "pqc" && <VbomPqc />}
      {active === "exposure" && <VbomExposure />}
      {active === "contracts" && <VbomContracts />}
      {active === "evidence" && <VbomEvidence />}
      {active === "history" && <VbomHistory />}
      {active === "export" && <VbomExport />}
    </div>
  );
}

/* ── workspace sections (docs/boms/01_PRODUCT_SPEC.md §5 navigation) ─── */

function VbomVendors() {
  const [q, setQ] = useState("");
  const read = useApi(() => apiVbomWorkspaceVendors(q || undefined), [q]);
  const rows = (read.data?.rows ?? []) as VbomVendorRow[];
  const [selected, setSelected] = useState<VbomVendorRow | null>(null);
  const detail = useApi(
    () => apiVbomWorkspaceVendorDetail(selected?.vendor_id ?? ""),
    [selected?.vendor_id],
  );
  return (
    <>
      <Panel title="Vendor Registry" sub="relationship states stay apart — a public association never becomes bank use; bank assets count verified links only">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="search by vendor or product"
            aria-label="search vendors"
            style={{ flex: 1, minWidth: 220, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--panel-2)", color: "var(--text)", fontSize: 12 }} />
          <Badge tone="slate">{read.data?.total ?? (read.source === "live" ? rows.length : "—")} rows</Badge>
        </div>
        <WsState read={read} noun="vendor registry">
          <WsTable
            head={["Vendor", "Product", "Version", "Category", "Bank assets", "Support lifecycle", "Crypto dependency", "PQC roadmap", "Evidence", "Last reviewed"]}
            colSpan={10}
            rows={rows.map((r, i) => (
              <tr key={`${r.vendor_id}-${r.product ?? "none"}-${i}`} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <td>
                  <span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span>
                  <div style={{ marginTop: 2 }}><AssociationBadge state={r.association_state} /></div>
                </td>
                <td><span style={{ fontSize: 11.5 }}>{r.product || <span style={{ color: "var(--faint)" }}>NOT_COLLECTED</span>}</span></td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.version || "—"}</span></td>
                <td><Badge tone="slate">{r.category}</Badge></td>
                <td>{r.bank_assets
                  ? <Badge tone="pass">{r.bank_assets} verified</Badge>
                  : <span style={{ fontSize: 11, color: "var(--faint)" }}>0 verified</span>}</td>
                <td><Badge tone={r.support_lifecycle === "END_OF_LIFE" ? "red" : r.support_lifecycle === "SUPPORTED" ? "pass" : "slate"}>{r.support_lifecycle}</Badge></td>
                <td><span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--dim)" }}>{r.crypto_dependency}</span></td>
                <td><PqcBadge state={r.pqc_roadmap} /></td>
                <td><Badge tone={r.evidence.freshness === "CURRENT" ? "pass" : "slate"}>{r.evidence.freshness}</Badge></td>
                <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(r.last_reviewed ?? "—").slice(0, 10)}</span></td>
              </tr>
            ))}
          />
        </WsState>
      </Panel>
      {selected && (
        <Drawer title={selected.vendor} sub={`${selected.product || "vendor"} · ${selected.category}`} onClose={() => setSelected(null)}>
          {!detail.data ? <p className="faint" style={{ fontSize: 12 }}>{detail.running ? "Reading the vendor…" : "The vendor detail did not return."}</p> : (
            (() => {
              const d = detail.data as Record<string, any>;
              return (
                <div style={{ display: "grid", gap: 12 }}>
                  <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
                    <div><b>Legal name</b> {String(d.vendor?.legal_name ?? "NOT_COLLECTED")} · <b>Display</b> {String(d.vendor?.display_name ?? d.vendor?.name ?? "")}</div>
                    <div><b>Category</b> {String(d.vendor?.vendor_type ?? "UNKNOWN")} · <b>Criticality</b> {String(d.vendor?.criticality ?? "UNKNOWN")}</div>
                    <div><b>Relationship</b> <AssociationBadge state={String(d.association_state)} /> <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{String(d.association_basis)}</span></div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>BANK ASSETS — VERIFIED LINKS ONLY</div>
                    {(d.bank_assets ?? []).length ? (d.bank_assets ?? []).map((x: Record<string, unknown>, i: number) => (
                      <div key={i} style={{ fontSize: 11.5, color: "var(--dim)" }}>{String(x.system_name ?? x.system_id)} · {String(x.dependency_type ?? "—")}</div>
                    )) : <div style={{ fontSize: 11.5, color: "var(--dim)" }}>No verified links. A public association is not bank use.</div>}
                  </div>
                  {(d.products ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>PRODUCT & VERSION CATALOGUE</div>
                      {(d.products ?? []).map((c: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ fontSize: 11.5, color: "var(--dim)" }}>{String(c.name)} {String(c.version ?? "")} · {String(c.support_level ?? "support not collected")}{c.eol_date ? ` · EOL ${String(c.eol_date)}` : ""}</div>
                      ))}
                    </div>
                  )}
                  {(d.contracts ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>CONTRACT METADATA</div>
                      {(d.contracts ?? []).map((c: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ fontSize: 11.5, color: "var(--dim)" }}>{String(c.contract_id ?? "—")} · {String(c.contract_type ?? "—")}{c.end_date ? ` · ends ${String(c.end_date)}` : ""}</div>
                      ))}
                    </div>
                  )}
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>PQC ROADMAP</div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <PqcBadge state={String(d.pqc_roadmap?.state ?? "UNKNOWN")} />
                      <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{String(d.pqc_roadmap?.basis ?? "")}</span>
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>SUPPLY CHAIN EXPOSURE</div>
                    <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
                      {(d.supply_chain_exposure?.sub_vendors ?? []).length} sub-vendor(s) · {(d.supply_chain_exposure?.integration_points ?? []).length} integration point(s)
                      {d.supply_chain_exposure?.single_point_of_failure ? " · single point of failure flagged" : ""}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>EVIDENCE & APPROVAL HISTORY</div>
                    {(d.evidence ?? []).slice(0, 5).map((e: Record<string, unknown>, i: number) => (
                      <div key={i} style={{ fontSize: 11, color: "var(--dim)" }}>{String(e.evidence_type ?? "—")} · {String(e.status ?? "—")} · {String(e.captured_at ?? "—").slice(0, 10)}</div>
                    ))}
                    {(d.approval_history ?? []).slice(0, 3).map((h: Record<string, unknown>, i: number) => (
                      <div key={i} style={{ fontSize: 11, color: "var(--faint)" }}>rev {String(h.revision)} · {String(h.status)} · {String(h.source)}{h.reviewed_by ? ` · reviewed by ${String(h.reviewed_by)}` : ""}</div>
                    ))}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--faint)" }}>{String(d.links?._note ?? "")}</div>
                </div>
              );
            })()
          )}
        </Drawer>
      )}
    </>
  );
}

function VbomProducts() {
  const read = useApi(apiVbomWorkspaceProducts);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Vendor Product Inventory" sub="product and version catalogue as recorded in the vendor profiles">
      <WsState read={read} noun="product inventory">
        <WsTable head={["Vendor", "Product", "Version", "Type", "License", "Support", "EOL", "Replacement"]} colSpan={8}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.name || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.version || "—"}</span></td>
              <td><Badge tone="slate">{r.component_type || "—"}</Badge></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.license_model || "—"}</span></td>
              <td>{r.support_level ? <Badge tone="pass">{r.support_level}</Badge> : <Badge tone="slate">UNKNOWN</Badge>}</td>
              <td>{r.eol_date ? <Badge tone="red">{String(r.eol_date).slice(0, 10)}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>none recorded</span>}</td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.replacement_product || "—"}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomRelationships() {
  const read = useApi(apiVbomWorkspaceRelationships);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Supplier Relationships" sub="every row carries its relationship state — confirmed links and public association are not the same fact">
      <WsState read={read} noun="relationship inventory">
        <WsTable head={["Vendor", "System", "Dependency", "Association state", "Basis"]} colSpan={5}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.system_name || <span style={{ color: "var(--faint)" }}>no verified system</span>}</span></td>
              <td><Badge tone="slate">{r.dependency_type || "—"}</Badge></td>
              <td><AssociationBadge state={r.association_state} /></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.association_basis}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomLifecycle() {
  const read = useApi(apiVbomWorkspaceLifecycle);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Product & Version Lifecycle" sub="an unrecorded support level is UNKNOWN, never assumed supported">
      <WsState read={read} noun="lifecycle inventory">
        <WsTable head={["Vendor", "Product", "Version", "Support level", "EOL date", "Replacement", "Lifecycle"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.product || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.version || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.support_level || <span style={{ color: "var(--faint)" }}>NOT_COLLECTED</span>}</span></td>
              <td>{r.eol_date ? <Badge tone="red">{String(r.eol_date).slice(0, 10)}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>none recorded</span>}</td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.replacement_product || "—"}</span></td>
              <td><Badge tone={r.lifecycle === "END_OF_LIFE" ? "red" : r.lifecycle === "SUPPORTED" ? "pass" : "slate"}>{r.lifecycle}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomSecurity() {
  const read = useApi(apiVbomWorkspaceSecurity);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Vendor Security Intelligence" sub="assessments, certifications and incidents as the profile recorded them">
      <WsState read={read} noun="security inventory">
        <WsTable head={["Vendor", "Assessments", "Certifications", "Incidents", "Latest risk rating"]} colSpan={5}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.assessments ?? []).length}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.certifications ?? []).length}</span></td>
              <td>{(r.incidents ?? []).length ? <Badge tone="red">{(r.incidents ?? []).length}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>0 recorded</span>}</td>
              <td><Badge tone="slate">{String((r.assessments ?? [])[0]?.risk_rating ?? "UNKNOWN")}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomCrypto() {
  const read = useApi(apiVbomWorkspaceCrypto);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Vendor Crypto Dependencies" sub="vendor crypto inventory as recorded — a vendor claim is evidence about the vendor, not about bank use">
      <WsState read={read} noun="crypto dependency inventory">
        <WsTable head={["Vendor", "Algorithm", "Key size", "Mode", "Use case", "PQC ready", "Discovery", "Verified"]} colSpan={8}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.algorithm || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.key_size ? `${r.key_size}` : "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.mode || "—"}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.crypto_use_case || "—"}</span></td>
              <td>{r.pqc_ready ? <Badge tone="violet">pqc-ready claim</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>no claim</span>}</td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.discovery_method || "—"}</span></td>
              <td>{r.verified ? <Badge tone="pass">verified</Badge> : <Badge tone="slate">not verified</Badge>}</td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomPqc() {
  const read = useApi(apiVbomWorkspacePqc);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Vendor PQC Roadmaps" sub="a vendor PQC claim is REPORTED until the bank verifies it — confirmed, reported and unknown stay apart">
      <WsState read={read} noun="PQC roadmap inventory">
        <WsTable head={["Vendor", "PQC roadmap", "Basis", "Claims", "Verified claims"]} colSpan={5}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><PqcBadge state={r.pqc_roadmap} /></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.basis}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.claims}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.verified_claims}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomExposure() {
  const read = useApi(apiVbomWorkspaceExposure);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Supply Chain Exposure" sub="sub-vendors, integration points and concentration flags from the stored dependency profile">
      <WsState read={read} noun="exposure inventory">
        <WsTable head={["Vendor", "Sub-vendors", "Integration points", "Concentration flags"]} colSpan={4}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.sub_vendors ?? []).length}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.integration_points ?? []).length}</span></td>
              <td>
                <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {r.concentration_flags?.critical_dependency ? <Badge tone="amber">critical dependency</Badge> : null}
                  {r.concentration_flags?.single_point_of_failure ? <Badge tone="red">single point of failure</Badge> : null}
                  {r.concentration_flags?.concentration_risk ? <Badge tone="amber">concentration risk</Badge> : null}
                  {!r.concentration_flags?.critical_dependency && !r.concentration_flags?.single_point_of_failure && !r.concentration_flags?.concentration_risk
                    ? <span style={{ fontSize: 11, color: "var(--faint)" }}>none recorded</span> : null}
                </span>
              </td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomContracts() {
  const read = useApi(apiVbomWorkspaceContracts);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Contract & Support Metadata" sub="contract and SLA records as the profile recorded them">
      <WsState read={read} noun="contract inventory">
        <WsTable head={["Vendor", "Contracts", "SLAs", "Contract end"]} colSpan={4}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td>
                {(r.contracts ?? []).length ? (r.contracts ?? []).map((c: Record<string, unknown>, j: number) => (
                  <div key={j} style={{ fontSize: 11, color: "var(--dim)" }}>{String(c.contract_id ?? "—")} · {String(c.contract_type ?? "—")}</div>
                )) : <span style={{ fontSize: 11, color: "var(--faint)" }}>NOT_COLLECTED</span>}
              </td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.service_level_agreements ?? []).length}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.contract_end_date ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomEvidence() {
  const read = useApi(apiVbomWorkspaceEvidence);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Evidence & Provenance" sub="evidence source, collection method and freshness as recorded">
      <WsState read={read} noun="evidence inventory">
        <WsTable head={["Vendor", "Type", "Reference", "Status", "Source", "Method", "Captured", "Freshness"]} colSpan={8}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><Badge tone="slate">{r.evidence_type || "—"}</Badge></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.evidence_reference || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.status || "—"}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.source_system || "—"}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.collection_method || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.captured_at ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomHistory() {
  const read = useApi(apiVbomWorkspaceHistory);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="VBOM History" sub="profile revisions as stored — who captured them, who reviewed them">
      <WsState read={read} noun="history">
        <WsTable head={["Vendor", "Revision", "Status", "Source", "Captured", "Reviewed by"]} colSpan={6}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.vendor}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>rev {r.revision}</span></td>
              <td><Badge tone={r.status === "APPROVED" ? "pass" : "amber"}>{r.status}</Badge></td>
              <td><Badge tone="slate">{r.source}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.captured_at ?? "—").slice(0, 10)}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.reviewed_by || "—"}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function VbomExport() {
  const read = useApi(apiVbomWorkspaceExport);
  const formats = (read.data?.formats ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Export & Validation" sub="the export keeps the stored relationship states as recorded — publicly reported stays publicly reported in the document too">
      <WsState read={read} noun="export inventory">
        <WsTable head={["Format", "Path", "State"]} colSpan={3}
          rows={formats.map((f, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{String(f.format)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{String(f.path)}</span></td>
              <td><Badge tone="pass">{String(f.state)}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}
