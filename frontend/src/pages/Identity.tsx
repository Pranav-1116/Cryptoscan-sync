import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiAuthMeDetails, apiMfaEnroll, apiMfaEnable, apiMfaDisable, tenantFetch } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { ICON_MD, IconOk } from "../components/icons";

export default function Identity() {
  const [loading, setLoading] = useState(true);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [roles, setRoles] = useState<any[]>([]);
  const [mfaSecretData, setMfaSecretData] = useState<any>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaDisablePassword, setMfaDisablePassword] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [mfaSubmitting, setMfaSubmitting] = useState(false);
  const [message, setMessage] = useState<{ text: string; error?: boolean } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const liveJson = async (path: string): Promise<unknown> => {
        const response = await tenantFetch(path, {
          signal: AbortSignal.timeout(8000),
          credentials: "include",
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      };
      const [meRes, usersRes, rolesRes] = await Promise.all([
        apiAuthMeDetails(),
        liveJson("/api/v1/auth/users"),
        liveJson("/api/v1/auth/roles"),
      ]);

      if (meRes.source === "live" && meRes.data) {
        setCurrentUser(meRes.data);
      } else {
        throw new Error(meRes.error || "authenticated identity is unavailable");
      }
      if (Array.isArray(usersRes)) setUsers(usersRes);
      if (Array.isArray(rolesRes)) setRoles(rolesRes);
    } catch (err) {
      setCurrentUser(null);
      setUsers([]);
      setRoles([]);
      setMessage({ text: `Identity data unavailable: ${String(err)}`, error: true });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleStartEnroll = async () => {
    setMfaSubmitting(true);
    setMessage(null);
    try {
      const res = await apiMfaEnroll();
      if (res.source === "live" && res.data) {
        setMfaSecretData(res.data);
      } else {
        setMessage({ text: res.error || "MFA enrollment failed", error: true });
      }
    } catch (e) {
      setMessage({ text: String(e), error: true });
    } finally {
      setMfaSubmitting(false);
    }
  };

  const handleConfirmEnable = async () => {
    if (!mfaCode || mfaCode.length !== 6) {
      setMessage({ text: "Please enter a valid 6-digit TOTP code.", error: true });
      return;
    }
    setMfaSubmitting(true);
    setMessage(null);
    try {
      const res = await apiMfaEnable(mfaCode);
      if (res.source === "live" && res.data) {
        setRecoveryCodes(res.data.recovery_codes || []);
        setMessage({ text: "MFA successfully activated! Save your recovery codes safely." });
        setMfaSecretData(null);
        setMfaCode("");
        loadData();
      } else {
        setMessage({ text: res.error || "Invalid verification code", error: true });
      }
    } catch (e) {
      setMessage({ text: String(e), error: true });
    } finally {
      setMfaSubmitting(false);
    }
  };

  const handleDisableMfa = async () => {
    if (!mfaDisablePassword) {
      setMessage({ text: "Password is required to disable MFA.", error: true });
      return;
    }
    setMfaSubmitting(true);
    setMessage(null);
    try {
      const res = await apiMfaDisable(mfaDisablePassword);
      if (res.source === "live" && res.data) {
        setMessage({ text: "MFA has been disabled." });
        setMfaDisablePassword("");
        loadData();
      } else {
        setMessage({ text: res.error || "Incorrect password", error: true });
      }
    } catch (e) {
      setMessage({ text: String(e), error: true });
    } finally {
      setMfaSubmitting(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Enterprise Access & Authentication
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Identity & Access Governance</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            RBAC role-based access, SCIM 2.0 provisioning lifecycle, and FIPS 140-3 hardware MFA enforcement.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/scim/v2/ServiceProviderConfig"
            filename="scim-service-provider-config.json"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            SCIM 2.0 Config
          </AuthenticatedDownload>
          <AuthenticatedDownload
            path="/api/v1/auth/saml/metadata"
            filename="saml-metadata.xml"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            SAML Metadata
          </AuthenticatedDownload>
        </div>
      </div>

      {message && (
        <div
          className="panel"
          style={{
            padding: "12px 16px",
            marginBottom: "20px",
            background: message.error ? "color-mix(in srgb, var(--red) 8%, transparent)" : "color-mix(in srgb, var(--green) 8%, transparent)",
            border: `1px solid ${message.error ? "color-mix(in srgb, var(--red) 30%, transparent)" : "color-mix(in srgb, var(--green) 30%, transparent)"}`,
            color: message.error ? "var(--red)" : "var(--green)",
            fontSize: "13px"
          }}
        >
          {message.text}
        </div>
      )}

      {/* Top Stat Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "24px" }}>
        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Current Authenticated User
          </div>
          <div style={{ fontSize: "22px", fontWeight: 700, margin: "6px 0", color: "var(--cyan)" }}>
            {loading ? "..." : (currentUser?.username || "Anonymous")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Roles: {currentUser?.roles?.join(", ") || "None"}
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            MFA / Hardware Token Posture
          </div>
          <div style={{ fontSize: "22px", fontWeight: 700, color: currentUser?.mfa_enabled ? "var(--green)" : "var(--amber)", margin: "6px 0" }}>
            {loading ? "..." : (currentUser?.mfa_enabled ? "Enforced (Active)" : "Not Enforced")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            RFC 6238 / FIDO2 Token
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Enterprise Directory Users
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : users.length}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Local & SCIM synchronized
          </div>
        </div>

        <div className="panel" style={{ padding: "18px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Active Login Sessions
          </div>
          <div style={{ fontSize: "28px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : (currentUser?.active_sessions ?? 1)}
          </div>
          <div style={{ fontSize: "12px", color: "var(--green)" }}>
            24h sliding rotation window
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "24px" }}>
        {/* Hardware Token & MFA Enrolment Panel */}
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>FIPS 140-3 Hardware Token & MFA</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Enforce time-based one-time passwords (TOTP) or hardware security key authentication for your account.
          </p>

          {!currentUser?.mfa_enabled ? (
            <div>
              {!mfaSecretData ? (
                <div>
                  <p style={{ fontSize: "13px", color: "var(--text)", marginBottom: "16px" }}>
                    Multi-factor authentication is currently <b>disabled</b> for this account. Tier-1 financial institutions mandate MFA for all privileged roles.
                  </p>
                  <Button variant="primary" onClick={handleStartEnroll} disabled={mfaSubmitting}>
                    {mfaSubmitting ? "Generating Secret..." : "Enroll Hardware Authenticator"}
                  </Button>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  <div style={{ fontSize: "12px", color: "var(--dim)" }}>
                    1. Add this secret to your Authenticator (or YubiKey TOTP slot):
                  </div>
                  <div style={{ padding: "10px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontFamily: "var(--mono)", fontSize: "13px", color: "var(--cyan)", textAlign: "center", letterSpacing: "0.1em" }}>
                    {mfaSecretData.secret}
                  </div>
                  <div style={{ fontSize: "12px", color: "var(--dim)" }}>
                    2. Enter the 6-digit confirmation code generated by your device:
                  </div>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <input
                      type="text"
                      maxLength={6}
                      placeholder="000000"
                      value={mfaCode}
                      onChange={(e) => setMfaCode(e.target.value.trim())}
                      className="inp"
                      style={{ width: "120px", fontSize: "15px", fontFamily: "var(--mono)", textAlign: "center" }}
                    />
                    <Button variant="primary" onClick={handleConfirmEnable} disabled={mfaSubmitting}>
                      {mfaSubmitting ? "Activating..." : "Verify & Enforce MFA"}
                    </Button>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--green)", fontSize: "13.5px", fontWeight: 600 }}>
                <IconOk className="ico" size={ICON_MD} /> <span>MFA is actively enforced on your session</span>
              </div>
              <p style={{ margin: 0, fontSize: "12.5px", color: "var(--dim)" }}>
                To disable MFA, enter your current account password. This will terminate all other active enterprise sessions.
              </p>
              <div style={{ display: "flex", gap: "8px" }}>
                <input
                  type="password"
                  placeholder="Enter current password"
                  value={mfaDisablePassword}
                  onChange={(e) => setMfaDisablePassword(e.target.value)}
                  className="inp"
                  style={{ flex: 1, fontSize: "12.5px" }}
                />
                <Button variant="danger" onClick={handleDisableMfa} disabled={mfaSubmitting}>
                  Disable MFA
                </Button>
              </div>
            </div>
          )}

          {recoveryCodes.length > 0 && (
            <div style={{ marginTop: "20px", padding: "14px", background: "color-mix(in srgb, var(--accent) 5%, transparent)", border: "1px solid var(--cyan)", borderRadius: "var(--r)" }}>
              <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--cyan)", marginBottom: "6px" }}>
                Emergency Recovery Codes (Save These Now)
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", fontFamily: "var(--mono)", fontSize: "12px", color: "var(--text)" }}>
                {recoveryCodes.map((code, idx) => (
                  <div key={idx}>• {code}</div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Enterprise Directory & SCIM Provisioning Panel */}
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Directory Synchronization & SCIM 2.0</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            Automated user lifecycle, role mapping, and instantaneous deprovisioning.
          </p>

          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "280px", overflowY: "auto" }}>
            {users.map((u: any, idx: number) => (
              <div
                key={u.id || idx}
                style={{
                  padding: "10px 12px",
                  background: "var(--bg-2)",
                  border: "1px solid var(--line)",
                  borderRadius: "var(--r)",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center"
                }}
              >
                <div>
                  <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text)" }}>
                    {u.username} {u.display_name ? `(${u.display_name})` : ""}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--dim)" }}>
                    {u.email || "Directory bind"} · MFA: {u.mfa_enabled ? "Enabled" : "Off"}
                  </div>
                </div>
                <div style={{ display: "flex", gap: "4px" }}>
                  {(u.roles || []).map((r: string) => (
                    <Badge key={r} variant="neutral">{r}</Badge>
                  ))}
                </div>
              </div>
            ))}
            {users.length === 0 && !loading && (
              <div style={{ textAlign: "center", padding: "24px", color: "var(--dim)", fontSize: "12.5px" }}>
                No directory users found.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
