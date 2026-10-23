import React, { useEffect, useState } from "react";
import PrivateScope from "../components/PrivateScope";
import { Badge, Button } from "../components/ui";
import {
  apiBankingOverview,
  apiBankingHndl,
  apiBankingRoadmap,
  apiBankingHsm,
  apiBankingJurisdictions,
  apiBankingSwiftCsp,
  apiBankingActionPlanJurisdiction,
  tenantFetch,
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

  // ISO 20022 Test State
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
          apiBankingOverview(),
          apiBankingHndl(5),
          apiBankingRoadmap(),
          apiBankingHsm(),
          apiBankingJurisdictions(),
          apiBankingSwiftCsp(),
        ]);

        if (alive) {
          if (ovRes.source === "live" && ovRes.data) setOverview(ovRes.data);
          if (hndlRes.source === "live" && hndlRes.data) setHndl(hndlRes.data);
          if (rmRes.source === "live" && rmRes.data) setRoadmap(rmRes.data);
          if (hsmRes.source === "live" && hsmRes.data) setHsmFleet(hsmRes.data);
          if (jRes.source === "live" && jRes.data && Array.isArray((jRes.data as any).jurisdictions)) { setJurisdictions((jRes.data as any).jurisdictions); setJurisdictionsKnown(true); }
          if (swiftRes.source === "live" && swiftRes.data) setSwiftCsp(swiftRes.data);
        }
      } catch (err) {
        console.error("Banking regulatory fetch error:", err);
      } finally {
        if (alive) setLoading(false);
      }
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
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ xml_payload: isoInput }),
      });
      if (resp.ok) {
        const data = await resp.json();
        setIsoResult(data);
      }
    } catch (err) {
      console.error("ISO 20022 parse error:", err);
    } finally {
      setIsoLoading(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Regulated Financial Sector
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Banking & Regulatory Cryptography</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Evidence screening for review. Bank acceptance, regulatory approval and discovery completeness are not established by this view.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/banking/action-plan/export?format=html&framework=ecb"
            filename="ecb-supervisory-pack.html"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            Export ECB Supervisory Pack
          </AuthenticatedDownload>
        </div>
      </div>

      {/* Top Stat Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11.5px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            HNDL Exposure
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: hndl?.at_risk ? "var(--red)" : "var(--text)", margin: "4px 0" }}>
            {loading ? "..." : (hndl?.total ?? "Unknown")}
          </div>
          <div style={{ fontSize: "12px", color: hndl?.at_risk === true ? "var(--red)" : "var(--dim)" }}>
            {loading ? "Loading HNDL evidence…" : !hndl ? "HNDL evidence unavailable — not zero risk." : hndl.at_risk === true ? "Confidential records at risk" : hndl.at_risk !== false || hndl.assessment_complete !== true ? "HNDL risk unknown — unresolved or unclassified evidence." : "No HNDL candidates in returned scope — not proof of completeness."}
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11.5px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            HSM Fleet — verification status
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : hsmFleet?.fleet ? `${hsmFleet.fleet.pqc_ready ?? 0} verified / ${hsmFleet.fleet.total ?? "unknown"} returned` : "Unavailable"}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            HSM declarations are not verified PQC readiness. Exact module FIPS validation is not established by family names.
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11.5px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            SWIFT CSP Controls
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, color: swiftCsp?.cscf?.attestation_ready ? "var(--green)" : "var(--amber)", margin: "4px 0" }}>
            {loading ? "..." : (swiftCsp?.cscf?.attestation_ready ? "Mapped assertions — review required" : "Review Required")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Gaps: {swiftCsp?.cscf?.gaps ?? "Unknown"} · Unknown: {swiftCsp?.cscf?.unknown ?? "Unknown"}
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11.5px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            Jurisdiction mappings returned
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : (jurisdictionsKnown ? jurisdictions.length : "Unavailable")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Mapping presence is not regulatory approval.
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1.2fr 1fr", gap: "20px", marginBottom: "24px" }}>
        {/* SWIFT CSP & Regulatory Crosswalk */}
        <div className="panel" style={{ padding: "20px" }}>
          <h3 style={{ margin: "0 0 6px", fontSize: "16px", fontWeight: 600 }}>SWIFT CSP Control Evidence</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Evidence crosswalk for review; not a SWIFT or regulator attestation.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {(swiftCsp?.cscf?.controls || []).map((c: any, idx: number) => (
              <div
                key={idx}
                style={{
                  padding: "12px 14px",
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--r)",
                  display: "flex",
                  flexDirection: "column",
                  gap: "6px"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "13px", fontWeight: 600 }}>{c.theme}</span>
                  <Badge variant={c.status === "satisfied" ? "success" : c.status === "gap" ? "danger" : "neutral"}>
                    {c.status.toUpperCase()}
                  </Badge>
                </div>
                <div style={{ fontSize: "12px", color: "var(--text)" }}>{c.evidence}</div>
                <div style={{ fontSize: "11px", color: "var(--dim)" }}>{c.detail}</div>
              </div>
            ))}
            {(!swiftCsp?.cscf?.controls || swiftCsp.cscf.controls.length === 0) && !loading && (
              <div style={{ padding: "16px", textAlign: "center", color: "var(--faint)", fontSize: "13px" }}>
                No SWIFT CSP controls evaluated yet.
              </div>
            )}
          </div>
        </div>

        {/* ISO 20022 Signature Metadata Testbench */}
        <div className="panel" style={{ padding: "20px" }}>
          <h3 style={{ margin: "0 0 6px", fontSize: "16px", fontWeight: 600 }}>ISO 20022 Signature Metadata</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Inspect BAH/xmldsig metadata only; cryptographic signature validity, trust and PQC readiness are not established.
          </p>

          <textarea
            value={isoInput}
            onChange={(e) => setIsoInput(e.target.value)}
            style={{
              width: "100%",
              height: "170px",
              background: "var(--bg-2)",
              border: "1px solid var(--line)",
              borderRadius: "var(--r)",
              padding: "10px",
              color: "var(--text)",
              fontFamily: "var(--mono)",
              fontSize: "11.5px",
              boxSizing: "border-box",
              resize: "vertical",
              marginBottom: "12px"
            }}
          />

          <Button variant="primary" onClick={runIsoParse} disabled={isoLoading} style={{ width: "100%" }}>
            {isoLoading ? "Analyzing XML Signature..." : "Inspect & Verify Signature"}
          </Button>

          {isoResult && (
            <div style={{ marginTop: "16px", padding: "14px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                <span style={{ fontSize: "12.5px", fontWeight: 600 }}>{isoResult.business_message_identifier || isoResult.message_type}</span>
                <Badge variant={isoResult.compliance_status === "PASS" ? "success" : "danger"}>
                  {isoResult.compliance_status}
                </Badge>
              </div>
              <div style={{ fontSize: "12px", color: "var(--dim)", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
                <div>Algorithm: <span style={{ color: "var(--text)" }}>{isoResult.signature_algorithm?.split("#")[1] || isoResult.signature_algorithm}</span></div>
                <div>Key Type: <span style={{ color: "var(--text)" }}>{isoResult.key_type} ({isoResult.key_size_bits || "?"} bits)</span></div>
                <div>Algorithm screening: <span style={{ color: isoResult.pqc_ready ? "var(--green)" : "var(--amber)" }}>{isoResult.pqc_ready ? "PQC name detected — not verified" : "No PQC name detected — not proof of absence"}</span></div>
                <div>Quantum Vulnerable: <span style={{ color: isoResult.quantum_vulnerable ? "var(--red)" : "var(--green)" }}>{isoResult.quantum_vulnerable ? "YES" : "NO"}</span></div>
              </div>
              {isoResult.findings && isoResult.findings.length > 0 && (
                <div style={{ marginTop: "10px", paddingTop: "8px", borderTop: "1px dashed var(--line)", fontSize: "11.5px", color: "var(--red)" }}>
                  {isoResult.findings.map((f: string, i: number) => (
                    <div key={i}>• {f}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Jurisdiction Action Plans */}
      <div className="panel" style={{ padding: "20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "10px" }}>
          <div>
            <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Cross-Border Supervisory Frameworks</h3>
            <p style={{ margin: 0, fontSize: "12px", color: "var(--dim)" }}>
              Regulatory action plans harmonized for global banking authorities.
            </p>
          </div>

          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {jurisdictions.map((j) => (
              <button
                key={j.code}
                onClick={() => setSelectedJurisdiction(j.code)}
                style={{
                  padding: "6px 12px",
                  borderRadius: "var(--r)",
                  fontSize: "12px",
                  cursor: "pointer",
                  background: selectedJurisdiction === j.code ? "var(--cyan)" : "var(--bg-2)",
                  color: selectedJurisdiction === j.code ? "var(--on-accent)" : "var(--text)",
                  border: "1px solid var(--line)",
                  fontWeight: selectedJurisdiction === j.code ? 700 : 500,
                }}
              >
                {j.code.toUpperCase()} ({j.region.split(" ")[0]})
              </button>
            ))}
          </div>
        </div>

        {actionPlan && (
          <div style={{ background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "16px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <span style={{ fontSize: "14px", fontWeight: 700 }}>
                {actionPlan.framework_title || `${selectedJurisdiction.toUpperCase()} Supervisory Framework`}
              </span>
              <Badge variant="info">NIST IR 8547 Baseline</Badge>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "14px" }}>
              {(actionPlan.milestones || []).map((m: any, idx: number) => (
                <div key={idx} style={{ padding: "12px", background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                  <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--cyan)", marginBottom: "4px" }}>
                    Phase {idx + 1}: {m.title || m.phase}
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--text)", marginBottom: "4px" }}>{m.requirement || m.description}</div>
                  <div style={{ fontSize: "11px", color: "var(--dim)" }}>Deadline: {m.deadline || "Post-2030"}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
