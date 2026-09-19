import React, { useState } from "react";
import { PageHead, Panel, Badge, Row, Col } from "../components/ui";
import { useEnterprise } from "../components/EnterpriseContext";

export default function Onboarding() {
  const { org, setOrg, env, setEnv } = useEnterprise();
  const [step, setStep] = useState(1);
  const [orgName, setOrgName] = useState(org.name || "ABC Financial Group");
  const [industry, setIndustry] = useState("Financial Services");
  const [region, setRegion] = useState(org.region || "UAE");
  const [environments, setEnvironments] = useState({
    production: true,
    staging: true,
    dr: false,
    testing: false,
  });
  const [adminEmail, setAdminEmail] = useState("security@company.com");
  const [initialRole, setInitialRole] = useState("Security Administrator");
  const [monitoringProfile, setMonitoringProfile] = useState("Continuous Line-Rate");

  const handleComplete = () => {
    setOrg({
      id: region.toLowerCase().includes("uae") ? "uae" : region.toLowerCase().includes("saudi") ? "saudi" : "europe",
      name: orgName,
      region: region,
      subsidiary: `${orgName} (${industry})`,
    });
    alert("Enterprise Organization Onboarding successfully committed to WORM audit log!");
    window.location.hash = "#/command-center";
  };

  return (
    <div className="page" style={{ maxWidth: "880px", margin: "0 auto", padding: "30px 20px" }}>
      <PageHead
        crumb="Enterprise / Setup"
        title="Welcome to ZELNX"
        sub="Let's configure your cryptographic estate organization, sovereign boundaries, and continuous monitoring policy."
      />

      {/* Progress Steps (Section 51) */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          background: "var(--bg-2)",
          padding: "16px 20px",
          borderRadius: "8px",
          border: "1px solid var(--line)",
          marginBottom: "24px",
        }}
      >
        {[
          { num: 1, label: "Organization" },
          { num: 2, label: "Environment" },
          { num: 3, label: "Access & Roles" },
          { num: 4, label: "Monitoring" },
          { num: 5, label: "Complete" },
        ].map((s) => (
          <div
            key={s.num}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              fontWeight: step === s.num ? 700 : 500,
              fontSize: "12.5px",
              color: step === s.num ? "var(--cyan)" : step > s.num ? "var(--green)" : "var(--faint)",
            }}
          >
            <span
              style={{
                width: "22px",
                height: "22px",
                borderRadius: "50%",
                background: step === s.num ? "var(--cyan)" : step > s.num ? "var(--green)" : "var(--bg-1)",
                color: step >= s.num ? "#000" : "var(--faint)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "11px",
                fontWeight: 700,
              }}
            >
              {step > s.num ? "✓" : s.num}
            </span>
            <span>{s.label}</span>
          </div>
        ))}
      </div>

      {/* Step 1: Organization */}
      {step === 1 && (
        <Panel title="1 ─ Organization Profile" sub="Do not collect unnecessary information. Specify legal boundary and sovereign location.">
          <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "8px" }}>
            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Organization Name</label>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="ABC Financial Group"
                style={{ width: "100%", padding: "10px 14px", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }}
              />
            </div>

            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Industry</label>
              <select
                value={industry}
                onChange={(e) => setIndustry(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }}
              >
                <option value="Financial Services">Financial Services (PCI-DSS 4.0 / DORA / NESA)</option>
                <option value="Telecom & 5G Carrier">Telecom & 5G Carrier (3GPP TS 33.501)</option>
                <option value="Critical Infrastructure & Energy">Critical Infrastructure & Energy (IEC 62443)</option>
                <option value="Government & Defense">Government & Defense (NIST SP 800-207 / FIPS 203)</option>
                <option value="Healthcare & Life Sciences">Healthcare & Life Sciences (HIPAA / HITECH)</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Primary Sovereign Region</label>
              <select
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }}
              >
                <option value="UAE">United Arab Emirates (UAE Sovereign Cloud · me-central-1)</option>
                <option value="Saudi Arabia">Saudi Arabia (KSA · me-south-1)</option>
                <option value="European Union">European Union (EU Sovereign · Frankfurt / Paris)</option>
                <option value="Singapore">Singapore (APAC Sovereign · ap-southeast-1)</option>
              </select>
            </div>

            <div style={{ display: "flex", justifyContent: "flex-end", marginTop: "12px" }}>
              <button onClick={() => setStep(2)} className="btn primary">Continue: Environment ➔</button>
            </div>
          </div>
        </Panel>
      )}

      {/* Step 2: Environment */}
      {step === 2 && (
        <Panel title="2 ─ Environments Topology" sub="Define the isolated scopes for cryptographic asset discovery, CBOM generation, and policy drift.">
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginTop: "8px" }}>
            <p style={{ fontSize: "13px", color: "var(--dim)", margin: 0 }}>
              Select environments to provision with zero cross-tenant contamination:
            </p>

            {[
              { key: "production", label: "Production", desc: "Live transaction gateways, core databases, and customer-facing TLS endpoints.", tone: "red" },
              { key: "staging", label: "Staging / Pre-Release", desc: "Pre-production validation gates and staging testbeds.", tone: "amber" },
              { key: "dr", label: "Disaster Recovery (DR)", desc: "Warm standby and sovereign failover infrastructure.", tone: "cyan" },
              { key: "testing", label: "Testing / CI Sandbox", desc: "Automated regression pipelines and ephemeral scanners.", tone: "slate" },
            ].map((e) => (
              <label
                key={e.key}
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  padding: "12px 16px",
                  background: "var(--bg-1)",
                  border: "1px solid var(--line)",
                  borderRadius: "8px",
                  cursor: "pointer",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                  <input
                    type="checkbox"
                    checked={(environments as any)[e.key]}
                    onChange={(ev) => setEnvironments({ ...environments, [e.key]: ev.target.checked })}
                    style={{ width: "16px", height: "16px", accentColor: "var(--cyan)" }}
                  />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: "13.5px", color: "var(--text)" }}>{e.label}</div>
                    <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>{e.desc}</div>
                  </div>
                </div>
                <Badge tone={e.tone as any}>{e.label.toUpperCase()}</Badge>
              </label>
            ))}

            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "12px" }}>
              <button onClick={() => setStep(1)} className="btn">← Back</button>
              <button onClick={() => setStep(3)} className="btn primary">Continue: Access & Roles ➔</button>
            </div>
          </div>
        </Panel>
      )}

      {/* Step 3: Access & Roles */}
      {step === 3 && (
        <Panel title="3 ─ Access & RBAC Controls" sub="Configure administrator credentials and default role enforcement.">
          <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "8px" }}>
            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Primary Security Officer Email</label>
              <input
                type="email"
                value={adminEmail}
                onChange={(e) => setAdminEmail(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }}
              />
            </div>

            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Default Administrative Role</label>
              <select
                value={initialRole}
                onChange={(e) => setInitialRole(e.target.value)}
                style={{ width: "100%", padding: "10px 14px", background: "var(--bg-1)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }}
              >
                <option value="Security Administrator">Security Administrator (Full Policy & Asset Scopes)</option>
                <option value="Security Engineer">Security Engineer (Discovery & Investigation)</option>
                <option value="Auditor">Auditor (Read-Only Immutable Evidence & WORM Proofs)</option>
              </select>
            </div>

            <div style={{ padding: "12px 14px", background: "rgba(0, 212, 255, 0.06)", border: "1px solid var(--cyan)", borderRadius: "6px" }}>
              <div style={{ fontWeight: 600, fontSize: "12.5px", color: "var(--cyan)" }}>Mandatory MFA Enforcement</div>
              <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>
                ZELNX enforces FIPS 140-3 Level 3 TOTP / FIDO2 MFA for all privileged organization roles.
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "12px" }}>
              <button onClick={() => setStep(2)} className="btn">← Back</button>
              <button onClick={() => setStep(4)} className="btn primary">Continue: Monitoring Policy ➔</button>
            </div>
          </div>
        </Panel>
      )}

      {/* Step 4: Monitoring */}
      {step === 4 && (
        <Panel title="4 ─ Continuous Cryptographic Observation" sub="Select frequency and scanning engine profiles.">
          <div style={{ display: "flex", flexDirection: "column", gap: "14px", marginTop: "8px" }}>
            {[
              { id: "Continuous Line-Rate", title: "24/7 Continuous Observation (Recommended)", desc: "Live event bus SSE, TimescaleDB EWMA drift detection, real-time alert dispatch." },
              { id: "Scheduled Daily", title: "Daily Batch Scan & Diff", desc: "Automated nightly AST scan, git repo crawl, and daily baseline snapshot." },
              { id: "On-Demand Only", title: "On-Demand & CI/CD Gate Only", desc: "Triggered strictly via pull-request webhook or manual SecOps command." },
            ].map((m) => (
              <div
                key={m.id}
                onClick={() => setMonitoringProfile(m.id)}
                style={{
                  padding: "14px",
                  background: monitoringProfile === m.id ? "rgba(0, 212, 255, 0.08)" : "var(--bg-1)",
                  border: monitoringProfile === m.id ? "1px solid var(--cyan)" : "1px solid var(--line)",
                  borderRadius: "8px",
                  cursor: "pointer",
                }}
              >
                <div style={{ fontWeight: 600, fontSize: "13.5px", color: monitoringProfile === m.id ? "var(--cyan)" : "var(--text)" }}>
                  {m.title}
                </div>
                <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "2px" }}>
                  {m.desc}
                </div>
              </div>
            ))}

            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "12px" }}>
              <button onClick={() => setStep(3)} className="btn">← Back</button>
              <button onClick={() => setStep(5)} className="btn primary">Review & Finalize ➔</button>
            </div>
          </div>
        </Panel>
      )}

      {/* Step 5: Complete */}
      {step === 5 && (
        <Panel title="5 ─ Complete Enterprise Onboarding" sub="Review configuration before committing immutable organization records.">
          <div style={{ display: "flex", flexDirection: "column", gap: "16px", marginTop: "8px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <div style={{ padding: "12px", background: "var(--bg-1)", borderRadius: "6px" }}>
                <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Organization</div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text)", marginTop: "2px" }}>{orgName}</div>
              </div>
              <div style={{ padding: "12px", background: "var(--bg-1)", borderRadius: "6px" }}>
                <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Jurisdiction / Region</div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--cyan)", marginTop: "2px" }}>{region}</div>
              </div>
              <div style={{ padding: "12px", background: "var(--bg-1)", borderRadius: "6px" }}>
                <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Security Officer</div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--text)", marginTop: "2px" }}>{adminEmail}</div>
              </div>
              <div style={{ padding: "12px", background: "var(--bg-1)", borderRadius: "6px" }}>
                <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Monitoring Engine</div>
                <div style={{ fontSize: "14px", fontWeight: 600, color: "var(--green)", marginTop: "2px" }}>{monitoringProfile}</div>
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", marginTop: "12px" }}>
              <button onClick={() => setStep(4)} className="btn">← Back</button>
              <button onClick={handleComplete} className="btn primary">
                ✓ Launch Enterprise Estate
              </button>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
