import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { usePollingApi } from "../lib/apiUi.jsx";
import { apiTechBomLive, apiTechBomVendor, TechBomState, TechBomVendorInventory } from "../lib/api.js";
import { IconTarget, IconClock, IconSecurity, IconHardware, IconInfo, IconSearch, IconCertificate } from "../components/icons";
import { IconCrypto, IconComponent, IconCloud } from "../components/icons";

export default function Vbom() {
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
    </div>
  );
}
