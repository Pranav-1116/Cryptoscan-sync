import React, { useEffect, useState } from "react";
import { Badge, Button } from "../components/ui";
import { apiAuthMeDetails, apiSsoStatus, apiMfaEnroll, apiMfaEnable, apiMfaDisable, tenantFetch } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { ICON_MD, IconOk } from "../components/icons";

export default function Identity() {
  const [loading, setLoading] = useState(true);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [users, setUsers] = useState<any[]>([]);
  const [roles, setRoles] = useState<any[]>([]);
  const [sourceErrors, setSourceErrors] = useState<{ users?: string; roles?: string }>({});
  const [samlEnabled, setSamlEnabled] = useState<boolean | null>(null);
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

      // Each source is read independently: one refused endpoint must not blank
      // the other two. Anything not read stays empty and is reported as such.
      const [meRes, usersRes, rolesRes, ssoRes] = await Promise.allSettled([
        apiAuthMeDetails(),
        liveJson("/api/v1/auth/users"),
        liveJson("/api/v1/auth/roles"),
        apiSsoStatus(),
      ]);

      let failure: string | null = null;
      if (meRes.status === "fulfilled" && meRes.value.source === "live" && meRes.value.data) {
        setCurrentUser(meRes.value.data);
      } else {
        setCurrentUser(null);
        failure = meRes.status === "fulfilled"
          ? (meRes.value.error || "authenticated identity is unavailable")
          : String(meRes.reason);
      }

      const nextErrors: { users?: string; roles?: string } = {};
      if (usersRes.status === "fulfilled" && Array.isArray(usersRes.value)) {
        setUsers(usersRes.value as any[]);
      } else {
        setUsers([]);
        nextErrors.users = usersRes.status === "fulfilled"
          ? "unexpected payload — no user array returned"
          : String(usersRes.reason);
      }
      // The role catalogue is a name -> description map on the wire; it is
      // normalised here rather than rendered raw (an object is not a list).
      if (rolesRes.status === "fulfilled" && rolesRes.value && typeof rolesRes.value === "object") {
        const raw = rolesRes.value as any;
        const source = raw.roles ?? raw;
        const list = Array.isArray(source)
          ? source.map((r: any) => (typeof r === "string" ? { name: r, description: "" } : { name: r.name ?? r.id, description: r.description ?? "" }))
          : Object.entries(source).map(([name, description]) => ({ name, description: String(description ?? "") }));
        setRoles(list.filter((r) => r.name));
        if (list.length === 0) nextErrors.roles = "role catalogue returned no roles";
      } else {
        setRoles([]);
        nextErrors.roles = rolesRes.status === "fulfilled"
          ? "unexpected payload — no role catalogue returned"
          : String(rolesRes.reason);
      }
      setSourceErrors(nextErrors);

      if (ssoRes.status === "fulfilled" && ssoRes.value.source === "live" && ssoRes.value.data) {
        setSamlEnabled(!!(ssoRes.value.data as { saml_enabled?: boolean }).saml_enabled);
      } else {
        setSamlEnabled(null);
      }

      setMessage(failure ? { text: `Authenticated identity unavailable: ${failure}`, error: true } : null);
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
            RBAC role-based access, the SCIM 2.0 provisioning lifecycle, and TOTP (RFC 6238) multi-factor enrolment.
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
          {samlEnabled === true ? (
            <AuthenticatedDownload
              path="/api/v1/auth/saml/metadata"
              filename="saml-metadata.xml"
              className="btn outline"
              style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
            >
              SAML Metadata
            </AuthenticatedDownload>
          ) : (
            <span
              className="btn outline"
              aria-disabled="true"
              title={samlEnabled === null
                ? "SSO status not read — SP metadata is only served when SAML is configured"
                : "SAML is not configured on this deployment (SAML_ENABLED / SAML_IDP_ENTITY_ID unset) — the platform returns 404 rather than emitting unsigned SP metadata"}
              style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)", opacity: 0.55, cursor: "not-allowed" }}
            >
              SAML Metadata
            </span>
          )}
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
            MFA posture
          </div>
          <div style={{ fontSize: "22px", fontWeight: 700, color: currentUser?.mfa_enabled ? "var(--green)" : "var(--amber)", margin: "6px 0" }}>
            {loading ? "..." : (currentUser?.mfa_enabled ? "Enforced (Active)" : "Not Enforced")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            RFC 6238 TOTP · hardware keys not implemented
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
            {loading ? "..." : (currentUser?.active_sessions ?? "—")}
          </div>
          <div style={{ fontSize: "12px", color: "var(--green)" }}>
            24h sliding rotation window
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "20px", marginBottom: "24px" }}>
        {/* Hardware Token & MFA Enrolment Panel */}
        <div className="panel" style={{ padding: "24px" }}>
          <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>Multi-Factor Authentication (TOTP)</h3>
          <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
            <span title={"Enrol a time-based one-time password (TOTP, RFC 6238) authenticator for your account. Hardware security keys (FIDO2/WebAuthn) are not implemented in this build — the platform does not claim them."}>{"Enrol a time-based one-time password (TOTP, RFC 6238) authenticator for your account."}</span>
          </p>

          {!currentUser?.mfa_enabled ? (
            <div>
              {!mfaSecretData ? (
                <div>
                  <p style={{ fontSize: "13px", color: "var(--text)", marginBottom: "16px" }}>
                    Multi-factor authentication is currently <b>disabled</b> for this account. Tier-1 financial institutions mandate MFA for all privileged roles.
                  </p>
                  <Button variant="primary" onClick={handleStartEnroll} disabled={mfaSubmitting}>
                    {mfaSubmitting ? "Generating Secret..." : "Enroll TOTP Authenticator"}
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
                <span title={"To disable MFA, enter your current account password. This will terminate all other active enterprise sessions."}>{"To disable MFA, enter your current account password."}</span>
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
              <div style={{ textAlign: "center", padding: "24px", color: sourceErrors.users ? "var(--amber)" : "var(--dim)", fontSize: "12.5px" }}>
                {sourceErrors.users
                  ? `User list not read — ${sourceErrors.users}. An empty list here is an unread list, not an empty directory.`
                  : "The user endpoint returned no rows."}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* RBAC catalogue — read from /auth/roles, never a client-side constant */}
      <div className="panel" style={{ padding: "24px" }}>
        <h3 style={{ margin: "0 0 4px", fontSize: "16px", fontWeight: 600 }}>RBAC Role Catalogue</h3>
        <p style={{ margin: "0 0 16px", fontSize: "12px", color: "var(--dim)" }}>
          <span title={"The roles the platform actually enforces, with the server's own description of each. Permissions are evaluated server-side on every request; this table grants nothing."}>{"The roles the platform actually enforces, with the server's own description of each."}</span>
        </p>
        {sourceErrors.roles ? (
          <div role="alert" style={{ padding: "12px", fontSize: "12.5px", color: "var(--amber)", background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)" }}>
            Role catalogue not read — {sourceErrors.roles}. No roles are shown rather than a guessed list.
          </div>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "8px" }}>
            {roles.map((r: any) => (
              <div key={r.name} style={{ padding: "10px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                <div style={{ fontFamily: "var(--mono)", fontSize: "12.5px", fontWeight: 700, color: "var(--cyan)" }}>{r.name}</div>
                <div style={{ fontSize: "11.5px", color: "var(--dim)", marginTop: "2px" }}>{r.description || "no description returned"}</div>
              </div>
            ))}
            {roles.length === 0 && !loading && (
              <div style={{ fontSize: "12.5px", color: "var(--dim)" }}>Role catalogue loaded but empty.</div>
            )}
            {loading && <div style={{ fontSize: "12.5px", color: "var(--dim)" }}>Reading role catalogue…</div>}
          </div>
        )}
      </div>
    </div>
  );
}
