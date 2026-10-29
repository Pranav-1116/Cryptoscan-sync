import React, { useEffect, useState, useMemo } from "react";
import PrivateScope from "../components/PrivateScope";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { IconComponent, IconTarget, IconClock, IconSecurity, IconCloud } from "../components/icons";
import {
  apiBankingOverview, apiBankingHndl, apiBankingRoadmap, apiBankingHsm,
  apiBankingJurisdictions, apiBankingSwiftCsp, apiBankingActionPlanJurisdiction, tenantFetch,
} from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";

export default function BankingRegulatory() {
  return <PrivateScope><BankingRegulatoryPage /></PrivateScope>;
}

function BankingRegulatoryPage() {
  const [loading, setLoading] = useState(true);
  const [overview, setOverview] = useState<any>(null);
  const [hndl, setHndl] = useState<any>(null);
  const [roadmap, setRoadmap] = useState<any>(null);
  const [hsmFleet, setHsmFleet] = useState<any>(null);
  const [swiftCsp, setSwiftCsp] = useState<any>(null);
  const [jurisdictions, setJurisdictions] = useState<any[]>([]);
  const [jurisdictionsKnown, setJurisdictionsKnown] = useState(false);
  const [selectedJurisdiction, setSelectedJurisdiction] = useState<string>("eu");
  const [actionPlan, setActionPlan] = useState<any>(null);
  const [isoInput, setIsoInput] = useState<string>(
`<?xml version="1.0" encoding="UTF-8"?>
<head.001.001.01 xmlns="urn:iso:std:iso:20022:tech:xsd:head.001.001.01">
  <BizMsgIdr>BMSG-2026-CH-00912</BizMsgIdr>
  <CreDt>2026-09-19T10:00:00Z</CreDt>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <Reference URI="">
        <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </Reference>
    </SignedInfo>
    <KeyInfo>
      <X509Data>
        <X509Certificate>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0+m193...</X509Certificate>
      </X509Data>
    </KeyInfo>
  </Signature>
</head.001.001.01>`
  );
  const [isoResult, setIsoResult] = useState<any>(null);
  const [isoLoading, setIsoLoading] = useState(false);

  useEffect(() => {
    let alive = true;
    async function loadData() {
      setLoading(true);
      try {
        const [ovRes, hndlRes, rmRes, hsmRes, jRes, swiftRes] = await Promise.all([
          apiBankingOverview(), apiBankingHndl(5), apiBankingRoadmap(),
          apiBankingHsm(), apiBankingJurisdictions(), apiBankingSwiftCsp(),
        ]);
        if (alive) {
          if (ovRes.source === "live" && ovRes.data) setOverview(ovRes.data);
          if (hndlRes.source === "live" && hndlRes.data) setHndl(hndlRes.data);
          if (rmRes.source === "live" && rmRes.data) setRoadmap(rmRes.data);
          if (hsmRes.source === "live" && hsmRes.data) setHsmFleet(hsmRes.data);
          if (jRes.source === "live" && jRes.data && Array.isArray((jRes.data as any).jurisdictions)) { setJurisdictions((jRes.data as any).jurisdictions); setJurisdictionsKnown(true); }
          if (swiftRes.source === "live" && swiftRes.data) setSwiftCsp(swiftRes.data);
        }
      } catch (err) { console.error("Banking regulatory fetch error:", err); }
      finally { if (alive) setLoading(false); }
    }
    loadData();
    return () => { alive = false; };
  }, []);

  useEffect(() => {
    if (!selectedJurisdiction) return;
    let alive = true;
    apiBankingActionPlanJurisdiction(selectedJurisdiction).then((r) => {
      if (alive && r.source === "live" && r.data) setActionPlan(r.data);
    }).catch(() => {});
    return () => { alive = false; };
  }, [selectedJurisdiction]);

  const runIsoParse = async () => {
    setIsoLoading(true);
    try {
      const resp = await tenantFetch("/api/v1/banking/iso20022/parse", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ xml_payload: isoInput }),
      });
      if (resp.ok) { const data = await resp.json(); setIsoResult(data); }
    } catch (err) { console.error("ISO 20022 parse error:", err); }
    finally { setIsoLoading(false); }
  };

  const hsmTotal = hsmFleet?.fleet?.total ?? 0;
  const hsmReady = hsmFleet?.fleet?.pqc_ready ?? 0;
  const hsmPct = hsmTotal ? hsmReady / hsmTotal : 0;
  const hndlAtRisk = hndl?.at_risk === true;
  const swiftReady = !!swiftCsp?.cscf?.attestation_ready;
  const swiftGaps = swiftCsp?.cscf?.gaps ?? "—";
  const swiftUnknown = swiftCsp?.cscf?.unknown ?? "—";
  const controls: any[] = swiftCsp?.cscf?.controls ?? [];
  const milestones: any[] = actionPlan?.milestones ?? [];

  // Hero ring: HSM readiness dominates banking posture
  const heroPct = hsmTotal ? hsmPct : 0;
  const heroTone = hndlAtRisk ? "red" as const : hsmTotal && hsmPct >= 0.6 ? "green" as const : "amber" as const;
  const heroLabel = loading ? "…" : hndlAtRisk ? "RISK" : hsmTotal ? `${Math.round(hsmPct*100)}%` : "—";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* ── Hero ── */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 500px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--cyan) 12%, transparent)", border: "1px solid var(--cyan)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: ".06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--cyan)" }} /> REGULATION · BANKING & SWIFT · HNDL · CSCF
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--cyan)", color: "#fff" }}><IconSecurity size={18} /></span>
            Banking & Regulatory Cryptography
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 640 }}>
            <b style={{ color: "var(--text)" }}>Evidence screening for review</b> — HNDL exposure, HSM fleet posture, SWIFT CSP crosswalk & ISO 20022 metadata. <span style={{ color: "var(--cyan)" }}>Bank acceptance and regulatory approval are never inferred.</span>
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap", alignItems: "center" }}>
            <span className="kicker" style={{ fontSize: 10 }}>SWIFT CSCF 2025 · HNDL 5Y · NIST IR 8547</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{jurisdictionsKnown ? `${jurisdictions.length} jurisdictions mapped` : "jurisdictions —"}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 168, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={heroPct} label={heroLabel} sub={hndlAtRisk ? "hndl risk" : "hsm pqc"} tone={heroTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>BANKING POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 140, lineHeight: 1.4 }}>{loading ? "Loading evidence…" : hndlAtRisk ? "Confidential records at risk — triage" : hsmTotal ? `${hsmReady}/${hsmTotal} HSMs verified PQC-ready` : "HSM declarations are not verified PQC readiness"}</div>
              <div style={{ marginTop: 6 }}><Bar value={heroPct} tone={heroTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <AuthenticatedDownload path="/api/v1/banking/action-plan/export?format=html&framework=ecb" filename="ecb-supervisory-pack.html" className="btn outline" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" } as any}>Export ECB Supervisory Pack</AuthenticatedDownload>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{loading ? "…" : hsmFleet?.fleet ? `fleet ${hsmFleet.fleet.total} · ${hsmFleet.fleet.pqc_ready ?? 0} pqc` : "fleet unavailable"}</span>
          </div>
        </div>
      </div>

      {/* ── 4 KPIs ── */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${hndlAtRisk ? "var(--red)" : "var(--amber)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconTarget size={12} /> HNDL EXPOSURE</div>
              <div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: hndlAtRisk ? "var(--red)" : "var(--text)" }}>{loading ? "…" : hndl?.total ?? "—"}</div>
              <div style={{ fontSize: 12, color: hndlAtRisk ? "var(--red)" : "var(--dim)" }}>{loading ? "Loading…" : !hndl ? "HNDL evidence unavailable — not zero risk." : hndlAtRisk ? "Confidential records at risk" : hndl.at_risk === null ? "HNDL risk unknown — unresolved or unclassified evidence." : hndl.total === 0 ? "No HNDL candidates in returned scope — not proof of completeness." : "No HNDL exposure identified in returned scope — not proof of completeness."}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: hndlAtRisk ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `1px solid ${hndlAtRisk ? "var(--red)" : "var(--amber)"}`, color: hndlAtRisk ? "var(--red)" : "var(--amber)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={hndlAtRisk ? 1 : 0} tone={hndlAtRisk ? "red" : "amber"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Harvest-Now-Decrypt-Later window</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${hsmPct >= 0.6 ? "var(--green)" : hsmPct > 0 ? "var(--amber)" : "var(--slate)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>HSM FLEET — PQC READINESS</div>
              <div style={{ fontSize: 22, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : hsmFleet?.fleet ? `${hsmReady}/${hsmFleet.fleet.total}` : "—"}</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>HSM declarations are not verified PQC readiness</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: hsmPct >= 0.6 ? "color-mix(in srgb, var(--green) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${hsmPct >= 0.6 ? "var(--green)" : "var(--line)"}`, color: hsmPct >= 0.6 ? "var(--green)" : "var(--faint)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={hsmPct} tone={hsmPct >= 0.6 ? "green" : hsmPct > 0 ? "amber" : "slate"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{hsmTotal ? `${Math.round(hsmPct*100)}% verified · declarations not proof` : "No fleet returned"}</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${swiftReady ? "var(--green)" : "var(--amber)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SWIFT CSP CONTROLS</div>
              <div style={{ fontSize: 14, fontWeight: 800, margin: "8px 0 2px", lineHeight: 1 }}>{loading ? "…" : swiftReady ? "Mapped — review required" : "Review Required"}</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>gaps {swiftGaps} · unknown {swiftUnknown}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: swiftReady ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `1px solid ${swiftReady ? "var(--green)" : "var(--amber)"}`, color: swiftReady ? "var(--green)" : "var(--amber)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><Bar value={controls.length ? controls.filter((c: any) => c.status === "satisfied").length / controls.length : 0} tone={swiftReady ? "green" : "amber"} /><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{controls.length ? `${controls.filter((c:any)=>c.status==="satisfied").length}/${controls.length} satisfied` : "No CSCF evaluation yet"}</div></div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>Jurisdiction mappings returned</div>
              <div style={{ fontSize: 30, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : jurisdictionsKnown ? jurisdictions.length : "Unavailable"}</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>presence ≠ regulatory approval</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--cyan) 14%, transparent)", border: "1px solid var(--cyan)", color: "var(--cyan)" }}><IconCloud size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}><div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Mappings returned are not regulatory approval</div></div>
        </div>
      </div>

      {/* ── SWIFT + ISO20022 ── */}
      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: 14, marginBottom: 18 }}>
        <Panel title="SWIFT CSP Control Evidence" sub="Evidence crosswalk for review — not a SWIFT or regulator attestation" style={{ padding: "14px 16px" }}>
          {controls.length ? (
            <div style={{ display: "grid", gap: 10 }}>
              {controls.map((c: any, idx: number) => (
                <div key={idx} style={{ padding: "12px 14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", display: "flex", flexDirection: "column", gap: 6 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: 13, fontWeight: 700 }}>{c.theme}</span>
                    <Badge variant={c.status === "satisfied" ? "success" : c.status === "gap" ? "danger" : "neutral"}>{String(c.status ?? "unknown").toUpperCase()}</Badge>
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text)" }}>{c.evidence}</div>
                  <div style={{ fontSize: 11, color: "var(--dim)" }}>{c.detail}</div>
                  <Bar value={c.status === "satisfied" ? 1 : c.status === "gap" ? 0.35 : 0.55} tone={c.status === "satisfied" ? "green" : c.status === "gap" ? "red" : "slate"} />
                </div>
              ))}
            </div>
          ) : (
            <div style={{ padding: 24, textAlign: "center", color: "var(--faint)", fontSize: 13, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>
              <div style={{ fontWeight: 700, color: "var(--text)" }}>No SWIFT CSP controls evaluated yet</div>
              <div style={{ fontSize: 12, marginTop: 4 }}>Evidence crosswalk populates from live platform state — empty is not a pass</div>
            </div>
          )}
        </Panel>

        <Panel title="ISO 20022 Signature Metadata" sub="Inspect BAH / xmldsig metadata only — validity, trust & PQC not established" style={{ padding: "14px 16px" }}>
          <textarea value={isoInput} onChange={(e) => setIsoInput(e.target.value)} style={{ width: "100%", height: 150, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 11, boxSizing: "border-box", resize: "vertical", marginBottom: 10 }} />
          <button onClick={runIsoParse} disabled={isoLoading} style={{ width: "100%", padding: "9px 12px", borderRadius: "var(--r)", background: "var(--cyan)", color: "#fff", border: "1px solid var(--cyan)", fontWeight: 700, fontSize: 12, cursor: isoLoading ? "not-allowed" : "pointer", opacity: isoLoading ? 0.6 : 1 }}>{isoLoading ? "Analyzing XML Signature…" : "Inspect & Verify Signature"}</button>
          {isoResult && (
            <div style={{ marginTop: 12, padding: 12, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                <span style={{ fontSize: 12.5, fontWeight: 700 }}>{isoResult.business_message_identifier || isoResult.message_type}</span>
                <Badge variant={isoResult.compliance_status === "PASS" ? "success" : "danger"}>{String(isoResult.compliance_status ?? "—")}</Badge>
              </div>
              <div style={{ fontSize: 12, color: "var(--dim)", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                <div>Algorithm: <span style={{ color: "var(--text)", fontFamily: "var(--mono)" }}>{String(isoResult.signature_algorithm ?? "—").split("#").pop()}</span></div>
                <div>Key Type: <span style={{ color: "var(--text)" }}>{isoResult.key_type} ({isoResult.key_size_bits || "?"} bits)</span></div>
                <div>Screening: <span style={{ color: isoResult.pqc_ready ? "var(--green)" : "var(--amber)" }}>{isoResult.pqc_ready ? "PQC name detected — not verified" : "No PQC name — not proof of absence"}</span></div>
                <div>Quantum Vulnerable: <span style={{ color: isoResult.quantum_vulnerable ? "var(--red)" : "var(--green)" }}>{isoResult.quantum_vulnerable ? "YES" : "NO"}</span></div>
              </div>
              {isoResult.findings?.length > 0 && (
                <div style={{ marginTop: 10, paddingTop: 8, borderTop: "1px dashed var(--line)", fontSize: 11.5, color: "var(--red)" }}>
                  {isoResult.findings.map((f: string, i: number) => <div key={i}>• {f}</div>)}
                </div>
              )}
            </div>
          )}
          <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Payloads never establish cryptographic validity — metadata inspection only</div>
        </Panel>
      </div>

      {/* ── Jurisdiction action plans ── */}
      <Panel title="Cross-Border Supervisory Frameworks" sub="Regulatory action plans harmonized for global banking authorities — NIST IR 8547 baseline" style={{ padding: "14px 16px" }}>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 14 }}>
          {jurisdictions.map((j) => (
            <button key={j.code} onClick={() => setSelectedJurisdiction(j.code)} style={{ padding: "6px 12px", borderRadius: "var(--r)", fontSize: 12, cursor: "pointer", background: selectedJurisdiction === j.code ? "var(--cyan)" : "var(--bg-2)", color: selectedJurisdiction === j.code ? "#fff" : "var(--text)", border: `1px solid ${selectedJurisdiction === j.code ? "var(--cyan)" : "var(--line)"}`, fontWeight: selectedJurisdiction === j.code ? 700 : 500 }}>
              {j.code.toUpperCase()} ({String(j.region).split(" ")[0]})
            </button>
          ))}
          {!jurisdictions.length && !loading && <span style={{ fontSize: 12, color: "var(--dim)" }}>{jurisdictionsKnown ? "No jurisdictions returned — mapping presence is not regulatory approval." : "Jurisdiction mapping unavailable — coverage is unknown."}</span>}
        </div>
        {actionPlan ? (
          <div style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 14 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 800 }}>{actionPlan.framework_title || `${selectedJurisdiction.toUpperCase()} Supervisory Framework`}</span>
              <Badge tone="cyan">NIST IR 8547 Baseline</Badge>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 12 }}>
              {(milestones ?? []).map((m: any, idx: number) => (
                <div key={idx} style={{ padding: 12, background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", borderLeft: `3px solid ${idx === 0 ? "var(--red)" : idx === 1 ? "var(--amber)" : "var(--green)"}` }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: "var(--cyan)", letterSpacing: ".04em" }}>PHASE {idx + 1}: {String(m.title || m.phase).toUpperCase()}</div>
                  <div style={{ fontSize: 12, color: "var(--text)", margin: "6px 0" }}>{m.requirement || m.description}</div>
                  <div style={{ fontSize: 11, color: "var(--dim)", display: "flex", alignItems: "center", gap: 6 }}><IconClock size={11} /> Deadline: {m.deadline || "Post-2030"}</div>
                  <div style={{ marginTop: 8 }}><Bar value={idx === 0 ? 0.3 : idx === 1 ? 0.6 : 0.9} tone={idx === 0 ? "red" : idx === 1 ? "amber" : "green"} /></div>
                </div>
              ))}
              {!milestones.length && <div style={{ fontSize: 12, color: "var(--dim)", gridColumn: "1/-1", padding: 12, textAlign: "center" }}>No milestones returned for this jurisdiction — framework not yet mapped.</div>}
            </div>
          </div>
        ) : (
          <div style={{ padding: 16, textAlign: "center", color: "var(--faint)", fontSize: 13, background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)" }}>Select a jurisdiction to load its supervisory framework — evidence, not attestation.</div>
        )}
      </Panel>
    </div>
  );
}
