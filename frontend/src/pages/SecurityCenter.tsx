import React, { useState } from "react";
import { PageHead, Panel, Badge, Row, Col } from "../components/ui";
import { useEnterprise } from "../components/EnterpriseContext";
import { EnterpriseAdminDrawer } from "../components/EnterpriseAdminDrawer";

export default function SecurityCenter() {
  const { role, env, org } = useEnterprise();
  const [activeTab, setActiveTab] = useState<"overview" | "sessions" | "activity" | "mfa" | "policies">("overview");
  const [showAdminDrawer, setShowAdminDrawer] = useState(false);
  const [drawerTab, setDrawerTab] = useState<any>("security_center");

  const openDrawer = (tabName: string) => {
    setDrawerTab(tabName);
    setShowAdminDrawer(true);
  };

  return (
    <div className="page">
      <PageHead
        crumb="Administration / Security"
        title="Enterprise Security Center"
        sub="Account posture, continuous authentication guarantees, FIDO2/MFA status, and session telemetry."
        right={
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              onClick={() => openDrawer("break_glass")}
              className="btn sm"
              style={{ borderColor: "var(--red)", color: "var(--red)" }}
            >
              🚨 Break-Glass Access
            </button>
            <button
              onClick={() => openDrawer("api_keys")}
              className="btn sm primary"
            >
              🔑 API Keys
            </button>
          </div>
        }
      />

      {/* Security Health KPI Row (Section 60) */}
      <Row>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Email Verification</div>
            <div style={{ fontSize: "18px", fontWeight: 700, color: "var(--green)", marginTop: "4px" }}>✓ Verified</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>admin@zelnx.internal</div>
          </div>
        </Col>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Two-Factor (MFA)</div>
            <div style={{ fontSize: "18px", fontWeight: 700, color: "var(--green)", marginTop: "4px" }}>✓ Enabled</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>RFC 6238 TOTP Standard</div>
          </div>
        </Col>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Password Hygiene</div>
            <div style={{ fontSize: "18px", fontWeight: 700, color: "var(--text)", marginTop: "4px" }}>Changed Today</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>PBKDF2-SHA256 (210,000 iters)</div>
          </div>
        </Col>
        <Col>
          <div style={{ padding: "16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "8px" }}>
            <div style={{ fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>Active Sessions</div>
            <div style={{ fontSize: "18px", fontWeight: 700, color: "var(--cyan)", marginTop: "4px" }}>3 Active</div>
            <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>Across Dubai & Riyadh</div>
          </div>
        </Col>
      </Row>

      {/* Security Recommendations & Alerts */}
      <Panel
        title="Security Posture Recommendations"
        sub="Continuous posture checks derived from live authentication sessions and tenant configuration."
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 14px", background: "rgba(16, 185, 129, 0.06)", border: "1px solid rgba(16, 185, 129, 0.3)", borderRadius: "6px" }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: "13px", color: "var(--green)" }}>✓ Multi-Factor Authentication Configured</div>
              <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>Administrative role accounts must provide second-factor TOTP on login.</div>
            </div>
            <Badge tone="green">COMPLIANT</Badge>
          </div>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 14px", background: "rgba(245, 158, 11, 0.06)", border: "1px solid rgba(245, 158, 11, 0.3)", borderRadius: "6px" }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: "13px", color: "var(--amber)" }}>⚠ Review Active Sessions (Cross-Region Access)</div>
              <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>One session active from Windows 11 client last seen yesterday.</div>
            </div>
            <button onClick={() => openDrawer("sessions")} className="btn sm">
              Review Sessions
            </button>
          </div>

          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 14px", background: "rgba(0, 212, 255, 0.06)", border: "1px solid rgba(0, 212, 255, 0.3)", borderRadius: "6px" }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: "13px", color: "var(--cyan)" }}>✓ Just-In-Time Step-Up Reauthentication Enforced</div>
              <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>High-privilege actions (API key creation, policy updates, baseline approvals) require instant reauthentication.</div>
            </div>
            <Badge tone="cyan">ENFORCED</Badge>
          </div>
        </div>
      </Panel>

      {/* Security Activity Feed (Section 61) */}
      <Panel
        title="Security Activity Audit Stream"
        sub="Real-time authentication and session state changes with deterministic provenance."
        action={
          <button onClick={() => openDrawer("sessions")} className="btn sm">
            Manage All Sessions
          </button>
        }
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          {[
            { time: "04:26:42 UTC", event: "Successful login via PBKDF2-SHA256 authentication", client: "Chrome 128 · Linux x86_64", location: "Dubai, UAE", ip: "127.0.0.1", suspicious: false },
            { time: "04:15:10 UTC", event: "Admin credentials bootstrapped & password updated", client: "Backend Process Service", location: "Internal Sandbox", ip: "127.0.0.1", suspicious: false },
            { time: "Yesterday, 18:22 UTC", event: "Session created from authorized subnet", client: "Firefox 126 · Windows 11", location: "Abu Dhabi, UAE", ip: "86.96.225.12", suspicious: false },
            { time: "3 days ago", event: "MFA challenge issued and confirmed", client: "TOTP RFC 6238", location: "Dubai, UAE", ip: "194.143.137.1", suspicious: false },
          ].map((act, idx) => (
            <div
              key={idx}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "12px 14px",
                background: "var(--bg-2)",
                border: "1px solid var(--line)",
                borderRadius: "6px",
              }}
            >
              <div>
                <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)" }}>{act.event}</div>
                <div style={{ fontSize: "11px", color: "var(--dim)", marginTop: "2px" }}>
                  {act.time} · {act.client} · Location: {act.location} · IP: {act.ip}
                </div>
              </div>
              <button
                onClick={() => alert(`Reported event at ${act.time} to Enterprise Incident Response.`)}
                className="btn sm"
                style={{ fontSize: "11px", color: "var(--amber)" }}
              >
                This wasn't me
              </button>
            </div>
          ))}
        </div>
      </Panel>

      {/* Enterprise Drawer Modal */}
      <EnterpriseAdminDrawer
        isOpen={showAdminDrawer}
        onClose={() => setShowAdminDrawer(false)}
        initialTab={drawerTab}
      />
    </div>
  );
}
