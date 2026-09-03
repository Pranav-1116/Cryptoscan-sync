import React, { useState } from "react";
import { apiRegister, isBackendLive } from "../lib/api.js";
import { Corners, Kicker } from "../components/ui.jsx";

/* The 8-role catalog — mirrors services/api/api/security/rbac.py
   ROLE_CATALOG so registration is meaningful offline too. */
const ROLE_CATALOG: Array<{ role: string; desc: string; adminOnly?: boolean }> = [
  { role: "superadmin", desc: "Full access (platform configuration)", adminOnly: true },
  { role: "ciso", desc: "All compliance, policy and exceptions" },
  { role: "security_analyst", desc: "View findings, create exceptions" },
  { role: "developer", desc: "View findings for own systems" },
  { role: "auditor", desc: "Read-only access to all reports" },
  { role: "business_owner", desc: "View findings for owned systems" },
  { role: "scanner", desc: "API-only (scan job submission)" },
  { role: "readonly", desc: "Dashboard view only" },
];

const inputStyle: React.CSSProperties = {
  background: "rgba(8,12,24,.8)", border: "1px solid var(--line-strong)", borderRadius: 10,
  color: "var(--text)", fontFamily: "var(--mono)", fontSize: 14, padding: "11px 14px",
  outline: "none", width: "100%",
};

/* Register — self-service account creation against the control plane
   (POST /api/v1/auth/register). The caller picks ONE of the 8 RBAC roles;
   superadmin is the platform-owner role and is admin-assigned only. */

export default function Register() {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [role, setRole] = useState("readonly");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);

  React.useEffect(() => {
    void isBackendLive().then(setBackendUp);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const uname = username.trim();
    if (uname.length < 2) return setError("username must be at least 2 characters");
    if (password.length < 8) return setError("password must be at least 8 characters");
    if (password !== confirm) return setError("passwords do not match");
    setBusy(true);
    const res = await apiRegister({ username: uname, password, role, display_name: displayName.trim() || undefined, email: email.trim() || undefined });
    setBusy(false);
    if (res.ok) {
      window.location.hash = `#/login?u=${encodeURIComponent(uname)}&r=${encodeURIComponent(role)}`;
    } else {
      setError(res.error || "registration failed");
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
      <div className="frame" style={{ width: "min(560px, 100%)", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 16, padding: "34px 32px", backdropFilter: "blur(12px)" }}>
        <Corners />
        <div style={{ textAlign: "center", marginBottom: 20 }}>
          <div style={{ width: 52, height: 52, borderRadius: 12, display: "grid", placeItems: "center", margin: "0 auto 14px", background: "var(--grad)", color: "#fff", fontFamily: "var(--sans)", fontWeight: 800, fontSize: 26 }}>Z</div>
          <Kicker>ZELNX console</Kicker>
          <h1 style={{ fontSize: 24, margin: "10px 0 4px" }}>Create account</h1>
          <p className="dim" style={{ fontSize: 13, margin: 0 }}>
            {backendUp === null ? "probing control plane…" : backendUp ? "control plane reachable — accounts are created live" : "control plane offline — registration will be unavailable"}
          </p>
        </div>

        <form onSubmit={(e) => void submit(e)} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" style={inputStyle} />
          <input placeholder="display name (optional)" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" style={inputStyle} />
          <input placeholder="email (optional)" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" style={inputStyle} />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
            <input type="password" placeholder="password (min 8)" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" style={inputStyle} />
            <input type="password" placeholder="confirm password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" style={inputStyle} />
          </div>

          <div style={{ marginTop: 8 }}>
            <div className="dim" style={{ fontSize: 11.5, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 8 }}>Assign role — the 8-role catalog</div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
              {ROLE_CATALOG.map(({ role: r, desc, adminOnly }) => {
                const selected = role === r;
                const disabled = !!adminOnly;
                return (
                  <button
                    key={r}
                    type="button"
                    disabled={disabled}
                    onClick={() => setRole(r)}
                    title={disabled ? "superadmin is the platform-owner role — assigned by an admin (the seeded admin account holds it)" : desc}
                    style={{
                      textAlign: "left", cursor: disabled ? "not-allowed" : "pointer", padding: "10px 12px",
                      borderRadius: 10, fontFamily: "var(--mono)", fontSize: 12.5, lineHeight: 1.45,
                      background: disabled ? "rgba(8,12,24,.4)" : selected ? "rgba(34,211,238,.12)" : "rgba(8,12,24,.8)",
                      border: selected ? "1px solid var(--cyan)" : "1px solid var(--line-strong)",
                      color: disabled ? "var(--dim)" : "var(--text)", opacity: disabled ? 0.65 : 1,
                    }}
                  >
                    <div style={{ fontWeight: 700, color: selected ? "var(--cyan)" : disabled ? "var(--dim)" : "var(--text)" }}>
                      {r} {adminOnly && <span style={{ fontSize: 10, color: "var(--amber)", fontWeight: 400 }}>🔒 admin-assigned</span>}
                    </div>
                    <div style={{ fontWeight: 400, color: "var(--dim)", fontSize: 11 }}>{desc}</div>
                  </button>
                );
              })}
            </div>
          </div>

          {error && <div style={{ color: "var(--red)", fontFamily: "var(--mono)", fontSize: 12 }}>✕ {error}</div>}
          <button className="btn primary" type="submit" disabled={busy} style={{ width: "100%", padding: 12, marginTop: 6 }}>
            {busy ? "Creating account…" : "Create account →"}
          </button>
        </form>

        <div style={{ marginTop: 14, textAlign: "center", fontSize: 12.5 }}>
          already have an account? <a href="#/login" className="mono" style={{ color: "var(--cyan)" }}>sign in →</a>
        </div>
      </div>
    </div>
  );
}
