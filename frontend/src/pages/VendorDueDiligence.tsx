import React, { useEffect, useMemo, useState } from "react";
import { Badge, Bar, Panel, PageHead, Table } from "../components/ui.jsx";
import { LiveBadge, useApi } from "../lib/apiUi.jsx";
import {
  apiVendorProfile,
  apiVendorProfileEvidence,
  apiVendorProfilePut,
  apiVendorProfileValidate,
  apiVendorRisk,
  apiVendorCreate,
  apiVendors,
} from "../lib/api.js";
import type { VendorProfileCompleteness, VendorProfileResponse, VendorRecord, VendorRiskResponse } from "../lib/api.js";

const CONTROL_STYLE: React.CSSProperties = {
  color: "var(--text)", background: "var(--bg)", border: "1px solid var(--line)",
  borderRadius: "var(--r)", padding: "8px 10px",
};

const SECTIONS: Array<[string, string]> = [
  ["identity", "Identity & ownership"],
  ["contacts", "Contacts & escalation"],
  ["components", "Components & services"],
  ["contracts", "Contracts, SLAs & legal"],
  ["security_compliance", "Security & compliance"],
  ["data_privacy", "Data, privacy & sovereignty"],
  ["financial_stability", "Financial stability & continuity"],
  ["incident_history", "Incidents & response"],
  ["dependencies", "Dependencies & concentration"],
  ["access_permissions", "Access & personnel"],
  ["exit_strategy", "Exit & migration"],
  ["evidence", "Evidence & provenance"],
];

function emptyResult<T>() { return { source: "offline" as const, data: null as T | null }; }

export default function VendorDueDiligence() {
  const vendorsRes = useApi(() => apiVendors(), []);
  const vendors = vendorsRes.data?.vendors ?? [];
  const vendorTotal = Number((vendorsRes.data as any)?.total_count ?? vendors.length) || vendors.length;
  const [selectedId, setSelectedId] = useState<string>("");
  const profileRes = useApi<VendorProfileResponse>(
    () => selectedId ? apiVendorProfile(selectedId) : Promise.resolve(emptyResult<VendorProfileResponse>()),
    [selectedId],
  );
  const riskRes = useApi<VendorRiskResponse>(
    () => selectedId ? apiVendorRisk(selectedId) : Promise.resolve(emptyResult<VendorRiskResponse>()),
    [selectedId],
  );
  const [raw, setRaw] = useState("");
  const [sectionDrafts, setSectionDrafts] = useState<Record<string, string>>({});
  const [view, setView] = useState<"sections" | "json">("sections");
  const [message, setMessage] = useState("");
  const [evidenceRef, setEvidenceRef] = useState("");
  const [evidenceType, setEvidenceType] = useState("OTHER");
  const [newVendorName, setNewVendorName] = useState("");
  const [newVendorType, setNewVendorType] = useState("OTHER");
  const [newVendorCriticality, setNewVendorCriticality] = useState("medium");

  useEffect(() => {
    if (profileRes.data?.profile) {
      const profile = profileRes.data.profile;
      setRaw(JSON.stringify(profile, null, 2));
      const drafts: Record<string, string> = {};
      Object.entries(profile).forEach(([key, value]) => {
        if (key !== "schema") drafts[key] = JSON.stringify(value, null, 2);
      });
      setSectionDrafts(drafts);
    }
  }, [profileRes.data]);

  const selected: VendorRecord | undefined = useMemo(
    () => vendors.find((vendor) => vendor.id === selectedId),
    [vendors, selectedId],
  );
  const completeness: VendorProfileCompleteness | null = profileRes.data?.completeness ?? null;
  const sections = completeness?.sections ?? {};
  const dueRisk = riskRes.data?.due_diligence;
  const sectionKeys = Object.keys(profileRes.data?.profile || {}).filter((key) => key !== "schema");

  const chooseVendor = (id: string) => {
    setSelectedId(id);
    setMessage("");
  };

  const createVendor = async () => {
    if (!newVendorName.trim()) return;
    const result = await apiVendorCreate({ name: newVendorName.trim(), vendor_type: newVendorType, criticality: newVendorCriticality });
    if (result.data) {
      setNewVendorName("");
      setMessage(`Created vendor ${result.data.name}; select it to start the profile.`);
      await vendorsRes.run();
      chooseVendor(result.data.id);
    } else setMessage(result.error || "Vendor creation failed");
  };

  const validate = async () => {
    if (!selectedId) return;
    try {
      const profile = JSON.parse(raw) as Record<string, unknown>;
      const result = await apiVendorProfileValidate(selectedId, { profile, status: "DRAFT" });
      setMessage(result.data
        ? `${result.data.valid ? "Valid" : "Invalid"} · ${result.data.completeness.score}% complete · ${result.data.content_sha256.slice(0, 12)}`
        : result.error || "Validation failed");
    } catch (error) {
      setMessage(`JSON error: ${String(error)}`);
    }
  };

  const applySectionChanges = () => {
    try {
      const profile = JSON.parse(raw) as Record<string, unknown>;
      for (const key of sectionKeys) {
        if (sectionDrafts[key] !== undefined) profile[key] = JSON.parse(sectionDrafts[key]);
      }
      setRaw(JSON.stringify(profile, null, 2));
      setMessage("Section changes assembled into the profile document; validate before saving.");
    } catch (error) {
      setMessage(`Section JSON error: ${String(error)}`);
    }
  };

  const save = async () => {
    if (!selectedId) return;
    try {
      const profile = JSON.parse(raw) as Record<string, unknown>;
      const result = await apiVendorProfilePut(selectedId, { profile, status: "DRAFT", source: "console" });
      setMessage(result.data
        ? `Saved revision ${result.data.revision} · ${result.data.completeness.score}% complete`
        : result.error || "Save failed");
      if (result.data) await profileRes.run();
    } catch (error) {
      setMessage(`JSON error: ${String(error)}`);
    }
  };

  const appendEvidence = async () => {
    if (!selectedId || !evidenceRef.trim()) return;
    const result = await apiVendorProfileEvidence(selectedId, {
      evidence_id: `${evidenceType.toLowerCase()}-${Date.now()}`,
      evidence_type: evidenceType,
      evidence_reference: evidenceRef.trim(),
      status: "UNVERIFIED",
      limitations: ["Reference metadata only; no artifact or credential is uploaded by this console."],
    });
    setMessage(result.data ? `Evidence appended as revision ${result.data.revision}` : result.error || "Evidence append failed");
    if (result.data) {
      setEvidenceRef("");
      await profileRes.run();
    }
  };

  return (
    <>
      <PageHead
        crumb="governance / vendor due diligence"
        title="Vendor due diligence"
        sub="Ten-section operational vendor profiles with explicit unknowns, evidence provenance and immutable revisions"
        right={<><LiveBadge source={vendorsRes.source} /><Badge tone="violet">{vendors.length === vendorTotal ? `${vendorTotal} vendor${vendorTotal === 1 ? "" : "s"}` : `${vendors.length} of ${vendorTotal} vendors`}</Badge></>}
      />

      <Panel title="Add operational vendor" sub="Creates only the vendor record; due diligence remains explicitly incomplete until evidence is collected">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input value={newVendorName} onChange={(event) => setNewVendorName(event.target.value)} placeholder="legal vendor name" style={{ ...CONTROL_STYLE, minWidth: 240 }} />
          <select value={newVendorType} onChange={(event) => setNewVendorType(event.target.value)} style={CONTROL_STYLE}><option>OTHER</option><option>OEM</option><option>ISV</option><option>MSP</option><option>CSP</option><option>SAAS</option></select>
          <select value={newVendorCriticality} onChange={(event) => setNewVendorCriticality(event.target.value)} style={CONTROL_STYLE}><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
          <button className="btn" onClick={() => void createVendor()} disabled={!newVendorName.trim()}>Create vendor</button>
        </div>
      </Panel>

      {!vendors.length ? (
        <Panel title="No operational vendors" sub="Use the form above to create the first tenant-scoped vendor, then collect its due-diligence profile here">
          <div className="dim"><span title={"No vendor records were returned by the live tenant. This screen never creates demo vendors."}>{"No vendor records were returned by the live tenant."}</span></div>
        </Panel>
      ) : (
        <>
          <Panel title="Vendor register" sub="Select a tenant-scoped vendor; missing profiles remain visibly incomplete">
            <Table
              head={["vendor", "type", "criticality", "profile status", "completeness"]}
              clickable
              selected={vendors.findIndex((vendor) => vendor.id === selectedId)}
              onSelect={(index) => chooseVendor(vendors[index].id)}
              rows={vendors.map((vendor) => [
                <span className="mono">{vendor.name}</span>,
                vendor.vendor_type || <Badge tone="slate">unknown</Badge>,
                vendor.criticality || <Badge tone="slate">unknown</Badge>,
                <Badge tone={vendor.vendor_profile?.status === "APPROVED" ? "green" : "amber"}>{vendor.vendor_profile?.status || "DRAFT"}</Badge>,
                `${vendor.vendor_profile?.completeness?.score ?? 0}%`,
              ])}
            />
          </Panel>

          {selectedId && (
            <>
              <div className="grid-4 mt" style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12 }}>
                <div className="panel stat frame"><div className="label">Vendor</div><div className="value grad-text">{selected?.name || selectedId}</div><div className="delta mono">{selectedId}</div></div>
                <div className="panel stat frame"><div className="label">Profile status</div><div className="value grad-text">{profileRes.data?.status || "DRAFT"}</div><div className="delta">unknown is not pass</div></div>
                <div className="panel stat frame"><div className="label">Completeness</div><div className="value grad-text">{completeness?.score ?? 0}%</div><Bar value={(completeness?.score ?? 0) / 100} tone={completeness?.status === "COMPLETE" ? "green" : "amber"} /></div>
                <div className="panel stat frame"><div className="label">Revision</div><div className="value grad-text">{profileRes.data?.revision ?? "—"}</div><div className="delta">append-only history</div></div>
                <div className="panel stat frame"><div className="label">Due-diligence risk</div><div className="value grad-text">{dueRisk ? `${dueRisk.risk_score} · ${dueRisk.risk_rating}` : "—"}</div><div className="delta">{dueRisk?.status || "not evaluated"}</div></div>
              </div>

              <Panel title="Section readiness" sub="Every section stays visible; blank and unverified values are not green" className="mt">
                <div className="vendor-grid">
                  {SECTIONS.map(([key, label]) => {
                    const section = sections[key];
                    const score = section?.score ?? (key === "evidence" && profileRes.data?.profile?.evidence ? 100 : 0);
                    return <div className="vendor-card" key={key}>
                      <div className="v-name">{label}</div>
                      <div className="v-stats"><div className="v-stat"><span className="n">{score}%</span><div className="l">complete</div></div><Badge tone={section?.status === "COMPLETE" ? "green" : "amber"}>{section?.status || "INCOMPLETE"}</Badge></div>
                      <Bar value={score / 100} tone={section?.status === "COMPLETE" ? "green" : "amber"} />
                      {section?.missing?.slice(0, 2).map((path) => <div className="faint" style={{ fontSize: 11 }} key={path}>{path}</div>)}
                    </div>;
                  })}
                </div>
              </Panel>

              <Panel title="Structured profile editor" sub="Each section is independently editable and assembled into one validated profile. Arrays and repeated records use JSON for exact preservation." className="mt">
                <div className="row" style={{ gap: 8, marginBottom: 12 }}>
                  <button className={`btn ${view === "sections" ? "primary" : ""}`} onClick={() => setView("sections")}>Sections</button>
                  <button className={`btn ${view === "json" ? "primary" : ""}`} onClick={() => setView("json")}>Full JSON</button>
                  {view === "sections" && <button className="btn" onClick={applySectionChanges}>Assemble section changes</button>}
                </div>
                {view === "sections" ? (
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 12 }}>
                    {sectionKeys.map((key) => <details key={key} open={key === "identity" || key === "contacts"} className="panel" style={{ padding: 12 }}>
                      <summary style={{ cursor: "pointer", color: "var(--cyan)", fontWeight: 600 }}>{SECTIONS.find(([candidate]) => candidate === key)?.[1] || key}</summary>
                      <textarea value={sectionDrafts[key] || "{}"} onChange={(event) => setSectionDrafts((previous) => ({ ...previous, [key]: event.target.value }))} spellCheck={false} style={{ width: "100%", minHeight: 180, marginTop: 10, fontFamily: "var(--mono)", fontSize: 11, color: "var(--text)", background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 10 }} />
                    </details>)}
                  </div>
                ) : (
                  <textarea value={raw} onChange={(event) => setRaw(event.target.value)} spellCheck={false} style={{ width: "100%", minHeight: 420, fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)", background: "var(--bg)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: 12 }} />
                )}
                <div className="row" style={{ gap: 8, marginTop: 12, alignItems: "center" }}>
                  <button className="btn" onClick={() => void validate()} disabled={profileRes.running}>Validate without saving</button>
                  <button className="btn primary" onClick={() => void save()} disabled={profileRes.running}>Save draft revision</button>
                  {message && <span className="dim" style={{ fontSize: 12 }}>{message}</span>}
                </div>
              </Panel>

              <Panel title="Evidence metadata" sub="References and hashes only; upload credentials, tokens and private keys nowhere" className="mt">
                <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <select value={evidenceType} onChange={(event) => setEvidenceType(event.target.value)} style={CONTROL_STYLE}><option>OTHER</option><option>CONTRACT</option><option>ASSESSMENT</option><option>CERTIFICATION</option><option>QUESTIONNAIRE</option><option>OBSERVED_SCAN</option><option>ATTESTATION</option></select>
                  <input value={evidenceRef} onChange={(event) => setEvidenceRef(event.target.value)} placeholder="ticket, document URI, or SHA-256 reference" style={{ ...CONTROL_STYLE, minWidth: 320 }} />
                  <button className="btn" onClick={() => void appendEvidence()} disabled={!evidenceRef.trim()}>Append unverified evidence</button>
                </div>
              </Panel>
            </>
          )}
        </>
      )}
    </>
  );
}
