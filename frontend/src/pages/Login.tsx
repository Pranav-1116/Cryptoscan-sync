import React, { useState } from "react";
import { apiLogin, isBackendLive, getToken, getRoles } from "../lib/api.js";
import { Corners, Kicker } from "../components/ui.jsx";

const ROLE_CATALOG: Array<{ role: string; desc: string }> = [
  { role: "superadmin", desc: "Full access (platform configuration)" },
  { role: "ciso", desc: "All compliance, policy and exceptions" },
  { role: "security_analyst", desc: "View findings, create exceptions" },
  { role: "developer", desc: "View findings for own systems" },
  { role: "auditor", desc: "Read-only access to all reports" },
  { role: "business_owner", desc: "View findings for owned systems" },
  { role: "scanner", desc: "API-only (scan job submission)" },
  { role: "readonly", desc: "Dashboard view only" },
];

/* Login — the console authenticates against the control plane API
   (POST /api/v1/auth/login) and stores the session token. When the
   backend is offline the console falls back to demo mode without auth. */

export default function Login() {
  const params = new URLSearchParams(window.location.hash.split("?")[1] || "");
  const registered = params.get("u") || "";
  const registeredRole = params.get("r") || "";
  const [username, setUsername] = useState(registered || "admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(
    registered ? `account created — sign in as ${registered} (${registeredRole})` : null,
  );
  const [busy, setBusy] = useState(false);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const roles = getRoles();
  const token = getToken();

  React.useEffect(() => {
    void isBackendLive().then(setBackendUp);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    const res = await apiLogin(username, password);
    setBusy(false);
    if (res.ok) {
      window.location.hash = "#/";
    } else {
      setError(res.error || "login failed");
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "grid", placeItems: "center", padding: 24 }}>
      <div className="frame" style={{ width: "min(440px, 100%)", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 16, padding: "34px 32px", backdropFilter: "blur(12px)" }}>
        <Corners />
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ width: 52, height: 52, borderRadius: 14, display: "grid", placeItems: "center", margin: "0 auto 14px", background: "var(--grad)", color: "#03121a", fontFamily: "var(--mono)", fontWeight: 700, fontSize: 26, boxShadow: "0 0 26px rgba(34,211,238,.5)" }}>Z</div>
          <Kicker>ZELNX console</Kicker>
          <h1 style={{ fontSize: 24, margin: "10px 0 4px" }}>Sign in</h1>
          <p className="dim" style={{ fontSize: 13, margin: 0 }}>
            {backendUp === null ? "probing control plane…" : backendUp ? "control plane reachable — authenticate to stream live data" : "control plane offline — you can explore in demo mode"}
          </p>
        </div>

        {notice && <div style={{ color: "var(--green)", fontFamily: "var(--mono)", fontSize: 12, marginBottom: 12, padding: "8px 12px", border: "1px solid rgba(52,211,153,.35)", borderRadius: 8, background: "rgba(52,211,153,.07)" }}>✓ {notice}</div>}

        <form onSubmit={(e) => void submit(e)} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <input
            placeholder="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            style={{ background: "rgba(8,12,24,.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 14, padding: "11px 14px", outline: "none" }}
          />
          <input
            type="password"
            placeholder="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            style={{ background: "rgba(8,12,24,.8)", border: "1px solid var(--line-strong)", borderRadius: 10, color: "var(--text)", fontFamily: "var(--mono)", fontSize: 14, padding: "11px 14px", outline: "none" }}
          />
          {error && <div style={{ color: "var(--red)", fontFamily: "var(--mono)", fontSize: 12 }}>✕ {error}</div>}
          <button className="btn primary" type="submit" disabled={busy} style={{ width: "100%", padding: "12px" }}>
            {busy ? "Signing in…" : "Sign in →"}
          </button>
        </form>

        <div style={{ marginTop: 12, display: "flex", gap: 10, alignItems: "center", justifyContent: "center", fontSize: 12.5 }}>
          <a href="#/register" className="mono" style={{ color: "var(--cyan)" }}>create account →</a>
          <span style={{ color: "var(--dim)" }}>·</span>
          <a href="#/" className="mono" style={{ color: "var(--dim)" }}>continue in demo mode</a>
        </div>

        {/* the 8-role catalog */}
        <div style={{ marginTop: 18, borderTop: "1px solid var(--line)", paddingTop: 14 }}>
          <div className="dim" style={{ fontSize: 11, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 8 }}>
            the 8-role catalog
          </div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {ROLE_CATALOG.map(({ role, desc }) => (
              <span
                key={role}
                title={desc}
                style={{
                  fontFamily: "var(--mono)", fontSize: 10.5, padding: "4px 8px", borderRadius: 6,
                  border: "1px solid var(--line-strong)", color: roles.includes(role) ? "var(--cyan)" : "var(--dim)",
                  background: roles.includes(role) ? "rgba(34,211,238,.1)" : "transparent",
                }}
              >
                {role}
              </span>
            ))}
          </div>
        </div>

        {/* superadmin hint + signed-in state */}
        {token && roles.length > 0 ? (
          <div style={{ marginTop: 14, textAlign: "center", fontSize: 12 }}>
            <span style={{ color: "var(--green)" }}>● signed in as <b>{username}</b></span>{" "}
            <span className="dim">— roles: {roles.join(", ")}</span>
            <div style={{ marginTop: 6 }}>
              <a href="#/" className="mono" style={{ color: "var(--green)" }}>enter console →</a>
            </div>
          </div>
        ) : (
          <div style={{ marginTop: 14, padding: "10px 12px", border: "1px solid rgba(251,191,36,.3)", borderRadius: 8, background: "rgba(251,191,36,.06)", fontSize: 11.5, color: "var(--amber)", fontFamily: "var(--mono)", lineHeight: 1.6 }}>
            superadmin = full platform access. Seeded bootstrap account: <b>admin / cryptoscan</b> (alias admin → superadmin). Other roles are assignable at registration or by an admin.
          </div>
        )}
      </div>
    </div>
  );
}
