import React, { useState } from "react";
import { PageHead, Panel, Badge, Row, Col } from "../components/ui";
import { useEnterprise } from "../components/EnterpriseContext";
import { EnterpriseAdminDrawer } from "../components/EnterpriseAdminDrawer";

export default function Organization() {
  const { org, env, role } = useEnterprise();
  const [activeTab, setActiveTab] = useState<
    "general" | "security" | "members" | "teams" | "roles" | "environments" | "integrations" | "api" | "billing" | "retention"
  >("general");
  const [showDrawer, setShowDrawer] = useState(false);
  const [drawerTab, setDrawerTab] = useState<any>("organization");

  const openDrawer = (tabName: string) => {
    setDrawerTab(tabName);
    setShowDrawer(true);
  };

  return (
    <div className="page">
      <PageHead
        crumb="Administration / Organization"
        title="Organization Control Plane"
        sub="Multi-tenant boundaries, teams, environments, RBAC roles, and sovereign data residency configuration."
        right={
          <div style={{ display: "flex", gap: "8px" }}>
            <button onClick={() => openDrawer("onboarding")} className="btn sm">
              🚀 Onboarding Wizard
            </button>
            <button onClick={() => openDrawer("invitations")} className="btn sm primary">
              ✉ Invite Members
            </button>
          </div>
        }
      />

      {/* Top Organization Summary Cards */}
      <Row>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Active Entity</div>
            <div style={{ fontSize: "16px", fontWeight: 700, color: "var(--text)", marginTop: "4px" }}>{org.name}</div>
            <div style={{ fontSize: "11px", color: "var(--cyan)", marginTop: "2px" }}>{org.subsidiary}</div>
          </div>
        </Col>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Sovereign Residency</div>
            <div style={{ fontSize: "16px", fontWeight: 700, color: "var(--green)", marginTop: "4px" }}>{org.region}</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>Compliance: NESA / CyberSecure L2</div>
          </div>
        </Col>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Audit & WORM Chain</div>
            <div style={{ fontSize: "16px", fontWeight: 700, color: "var(--text)", marginTop: "4px" }}>7 Years Lock</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>Immutable Merkle Append-Only</div>
          </div>
        </Col>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Current Environment</div>
            <div style={{ fontSize: "16px", fontWeight: 700, color: "var(--red)", marginTop: "4px" }}>{env}</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>Live Audited Discovery</div>
          </div>
        </Col>
      </Row>

      {/* Navigation Sub-Tabs (Section 52: General, Security, Members, Teams, Roles, Environments, Integrations, API Access, Billing, Audit) */}
      <div style={{ display: "flex", gap: "6px", borderBottom: "1px solid var(--line)", paddingBottom: "10px", margin: "16px 0", flexWrap: "wrap" }}>
        {[
          { id: "general", label: "General" },
          { id: "security", label: "Security & MFA" },
          { id: "members", label: "Members & Users" },
          { id: "teams", label: "Teams & Ownership" },
          { id: "roles", label: "RBAC Matrix" },
          { id: "environments", label: "Environments" },
          { id: "integrations", label: "Integrations" },
          { id: "api", label: "API Credentials" },
          { id: "billing", label: "Plan & Billing" },
          { id: "retention", label: "Data Retention" },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            className="btn sm"
            style={{
              background: activeTab === t.id ? "rgba(0, 212, 255, 0.12)" : "transparent",
              color: activeTab === t.id ? "var(--cyan)" : "var(--dim)",
              borderColor: activeTab === t.id ? "var(--cyan)" : "transparent",
              fontWeight: activeTab === t.id ? 600 : 400,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab: General */}
      {activeTab === "general" && (
        <Panel title="General Organization Profile" sub="Primary organization attributes and sovereign parameters.">
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Organization Legal Name</label>
              <input disabled value={org.name} style={{ width: "100%", padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }} />
            </div>
            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Sovereign Territory</label>
              <input disabled value={org.region} style={{ width: "100%", padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }} />
            </div>
            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Enterprise Subsidiary</label>
              <input disabled value={org.subsidiary} style={{ width: "100%", padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }} />
            </div>
            <div>
              <label style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Primary Security Contact</label>
              <input defaultValue="ciso-office@zelnx.internal" style={{ width: "100%", padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "6px", color: "var(--text)", marginTop: "4px" }} />
            </div>
          </div>
        </Panel>
      )}

      {/* Tab: Security */}
      {activeTab === "security" && (
        <Panel title="Organization Security & Authentication Settings" sub="Enforce multi-factor, session maximums, and SSO identity provider federation.">
          <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 14px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div>
                <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13.5px" }}>Mandatory Two-Factor (MFA / TOTP)</div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>Require RFC 6238 TOTP or FIDO2 hardware passkeys for all organization users.</div>
              </div>
              <Badge tone="green">ENFORCED</Badge>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 14px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div>
                <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13.5px" }}>Concurrent Session Limit</div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>Maximum concurrent active sessions per user account: 3 devices.</div>
              </div>
              <Badge tone="cyan">LIMIT 3</Badge>
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 14px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div>
                <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13.5px" }}>SAML 2.0 / OIDC Enterprise Single Sign-On</div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>Okta, Azure AD, PingFederate, and Google Workspace SAML connectors.</div>
              </div>
              <button onClick={() => openDrawer("security_center")} className="btn sm">
                Configure SSO
              </button>
            </div>
          </div>
        </Panel>
      )}

      {/* Tab: Members */}
      {activeTab === "members" && (
        <Panel
          title="Organization Members"
          sub="Enterprise team members with assigned RBAC roles and activity telemetry."
          action={<button onClick={() => openDrawer("invitations")} className="btn sm primary">+ Invite</button>}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
            {[
              { name: "Vikram R.", email: "security@company.com", role: "Security Administrator", team: "Security", status: "Active" },
              { name: "Elena Rostova", email: "elena.r@company.com", role: "Security Engineer", team: "Cloud", status: "Active" },
              { name: "David Chen", email: "d.chen@company.com", role: "Auditor", team: "Audit", status: "Active" },
              { name: "Sarah Al-Mansoor", email: "s.mansoor@company.com", role: "Compliance Officer", team: "Compliance", status: "Active" },
            ].map((m, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 14px", background: "var(--bg-2)", borderRadius: "6px" }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px", color: "var(--text)" }}>{m.name}</div>
                  <div style={{ fontSize: "11px", color: "var(--dim)" }}>{m.email} · Team: {m.team}</div>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <Badge tone="cyan">{m.role}</Badge>
                  <button onClick={() => openDrawer("user_management")} className="btn sm" style={{ padding: "2px 8px", fontSize: "11px" }}>Manage</button>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Tab: Teams */}
      {activeTab === "teams" && (
        <Panel
          title="Teams & Finding Ownership (Section 55)"
          sub="Finding assignment hierarchy: Team → Owner → Individual engineer."
          action={<button onClick={() => openDrawer("teams")} className="btn sm">Manage All Teams</button>}
        >
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            {[
              { name: "Security", members: 14, focus: "Estate Vulnerability & PQC Migration" },
              { name: "Infrastructure", members: 22, focus: "HSM, Cloud KMS & Edge Silicon" },
              { name: "Payments", members: 9, focus: "PCI-DSS 4.0 HSM Quorum & POS" },
              { name: "Cloud", members: 18, focus: "AWS/Azure/GCP IAM & CMEK Residency" },
            ].map((t, idx) => (
              <div key={idx} style={{ padding: "12px", background: "var(--bg-2)", borderRadius: "6px", border: "1px solid var(--line)" }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ fontWeight: 600, color: "var(--text)", fontSize: "13.5px" }}>{t.name}</span>
                  <Badge tone="cyan">{t.members} Members</Badge>
                </div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "4px" }}>{t.focus}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Tab: Roles */}
      {activeTab === "roles" && (
        <Panel
          title="Permission Matrix (Section 56)"
          sub="Fine-grained permissions matrix enforced deterministically across backend endpoints."
          action={<button onClick={() => openDrawer("role_matrix")} className="btn sm primary">Open RBAC Matrix</button>}
        >
          <div style={{ fontSize: "13px", color: "var(--dim)" }}>
            ZELNX provides 6 enterprise role profiles: <b>Admin</b>, <b>Security Administrator</b>, <b>Security Engineer</b>, <b>Auditor</b>, <b>Compliance Officer</b>, and <b>Viewer</b>. Click below to inspect exact capabilities and assignments.
          </div>
          <button onClick={() => openDrawer("role_matrix")} className="btn sm" style={{ marginTop: "12px" }}>
            View Full Permission Matrix
          </button>
        </Panel>
      )}

      {/* Tab: Environments */}
      {activeTab === "environments" && (
        <Panel title="Environment Scopes" sub="Physical and logical boundaries isolating discovery telemetry.">
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {[
              { name: "Production", status: "Active", tone: "red", desc: "Live regulated payment gateways and customer vaults." },
              { name: "Staging", status: "Active", tone: "amber", desc: "Pre-production test clusters and release validation gates." },
              { name: "Disaster Recovery (DR)", status: "Active", tone: "cyan", desc: "Warm standby replica sites and failover clusters." },
            ].map((e, idx) => (
              <div key={idx} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 14px", background: "var(--bg-2)", borderRadius: "6px" }}>
                <div>
                  <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13.5px" }}>{e.name}</div>
                  <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>{e.desc}</div>
                </div>
                <Badge tone={e.tone as any}>{e.status}</Badge>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Tab: API */}
      {activeTab === "api" && (
        <Panel
          title="Machine API Credentials & Service Accounts (Sections 67, 68, 69)"
          sub="Non-human machine tokens for CI/CD scanners and Kubernetes daemonsets."
          action={<button onClick={() => openDrawer("api_keys")} className="btn sm primary">+ Create API Key</button>}
        >
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <div style={{ padding: "12px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13px" }}>Production CI/CD Scanner</div>
              <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>Permissions: Read Assets, Read Evidence, Trigger Scan · Expires in 90 days</div>
            </div>
            <div style={{ padding: "12px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13px" }}>SIEM QRadar Forwarder</div>
              <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>Permissions: Read Evidence, Read Audit · Expiring Soon</div>
            </div>
          </div>
        </Panel>
      )}

      {/* Tab: Billing */}
      {activeTab === "billing" && (
        <Panel title="Plan & Enterprise Tier" sub="Cryptographic discovery capacity and sovereign SLA commitments.">
          <div style={{ padding: "16px", background: "var(--bg-2)", borderRadius: "8px", border: "1px solid var(--cyan)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: "16px", fontWeight: 700, color: "var(--cyan)" }}>ZELNX Sovereign Enterprise Tier</div>
                <div style={{ fontSize: "12px", color: "var(--dim)", marginTop: "4px" }}>
                  Unlimited Assets · S3 Object Lock 7y WORM · Hardware QRNG Entropy · Sub-second p99 SLA
                </div>
              </div>
              <Badge tone="green">ENTERPRISE ACTIVE</Badge>
            </div>
          </div>
        </Panel>
      )}

      {/* Tab: Retention */}
      {activeTab === "retention" && (
        <Panel
          title="Data Retention & Residency (Sections 70 & 71)"
          sub="Legal hold, compliance WORM storage, and geographic sovereign boundaries."
          action={<button onClick={() => openDrawer("data_retention")} className="btn sm">Retention Settings</button>}
        >
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
            <div style={{ padding: "12px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13px" }}>Evidence Retention</div>
              <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>S3 Object Lock 7 Years (Non-reducible)</div>
              <Badge tone="green" style={{ marginTop: "6px" }}>WORM ENFORCED</Badge>
            </div>
            <div style={{ padding: "12px", background: "var(--bg-2)", borderRadius: "6px" }}>
              <div style={{ fontWeight: 600, color: "var(--text)", fontSize: "13px" }}>Data Residency Territory</div>
              <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>United Arab Emirates (me-central-1)</div>
              <Badge tone="cyan" style={{ marginTop: "6px" }}>UAE SOVEREIGN</Badge>
            </div>
          </div>
        </Panel>
      )}

      {/* Drawer */}
      <EnterpriseAdminDrawer
        isOpen={showDrawer}
        onClose={() => setShowDrawer(false)}
        initialTab={drawerTab}
      />
    </div>
  );
}
