import React, { useState } from "react";
import { apiRegister, isBackendLive } from "../lib/api.js";

/* The 8-role catalog — mirrors services/api/api/security/rbac.py */
const ROLE_CATALOG: Array<{ role: string; desc: string; adminOnly?: boolean }> = [
  { role: "ciso", desc: "All compliance, policy and exceptions" },
  { role: "security_analyst", desc: "View findings, create exceptions" },
  { role: "auditor", desc: "Read-only access to all reports" },
  { role: "developer", desc: "View findings for own systems" },
  { role: "business_owner", desc: "View findings for owned systems" },
  { role: "scanner", desc: "API-only scan job submission" },
  { role: "readonly", desc: "Dashboard view only" },
  { role: "superadmin", desc: "Full platform access", adminOnly: true },
];

/* ── left brand / trust panel (matches sign-in) ────────────────────── */
function BrandPanel() {
  return (
    <aside className="auth-brand">
      <div className="auth-logo">
        <span className="mark">Z</span>
        <span>
          ZELNX
          <span className="tagline">CRYPTO INTELLIGENCE PLATFORM</span>
        </span>
      </div>

      <div className="auth-hero">
        <h2>Request access to the crypto control plane.</h2>
        <p>
          Accounts are scoped by role and constrained by hierarchical
          Region → BU → Environment → Asset policy. You will only ever see the
          assets your role is granted.
        </p>
        <ul className="auth-feats">
          <li>
            <span className="ic">◈</span>
            <span>
              <b>Role-based least privilege</b>
              <span>Eight defined roles, from read-only auditor to platform owner.</span>
            </span>
          </li>
          <li>
            <span className="ic">▤</span>
            <span>
              <b>Every account action audited</b>
              <span>Registrations, grants and changes enter the hash-chained audit log.</span>
            </span>
          </li>
          <li>
            <span className="ic">⬡</span>
            <span>
              <b>Superadmin is assigned, not self-selected</b>
              <span>The platform-owner role is provisioned by an administrator only.</span>
            </span>
          </li>
        </ul>
      </div>

      <div className="auth-trust">
        <span className="lbl">Governed under</span>
        <span className="badge cyan"><span className="dot" />FIPS 140-3</span>
        <span className="badge cyan"><span className="dot" />NIST SP 800-131A</span>
        <span className="badge cyan"><span className="dot" />SOC 2</span>
        <span className="badge cyan"><span className="dot" />ISO 27001</span>
      </div>
    </aside>
  );
}

/* Register — self-service account creation (POST /api/v1/auth/register).
   The caller picks one of 8 RBAC roles; superadmin is admin-assigned only. */
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
    if (uname.length < 2) return setError("Username must be at least 2 characters.");
    if (password.length < 8) return setError("Password must be at least 8 characters.");
    if (password !== confirm) return setError("Passwords do not match.");
    setBusy(true);
    const res = await apiRegister({
      username: uname,
      password,
      role,
      display_name: displayName.trim() || undefined,
      email: email.trim() || undefined,
    });
    setBusy(false);
    if (res.ok) {
      window.location.hash = `#/login?u=${encodeURIComponent(uname)}&r=${encodeURIComponent(role)}`;
    } else {
      setError(res.error || "Registration failed. Please try again.");
    }
  };

  return (
    <div className="auth">
      <BrandPanel />

      <main className="auth-panel">
        <div className="auth-form wide">
          <div className="auth-head">
            <div className="kicker">Workspace onboarding</div>
            <h1>Create account</h1>
            <p>Register against the live control plane. Access is governed by your selected role and ABAC scope.</p>
            <span className={`auth-status ${backendUp === null ? "" : backendUp ? "live" : "down"}`}>
              <span className="dot" />
              {backendUp === null
                ? "Connecting to control plane…"
                : backendUp
                  ? "Control plane connected · accounts created live"
                  : "Control plane offline · registration unavailable"}
            </span>
          </div>

          {error && <div className="auth-alert err">✕ {error}</div>}

          <form onSubmit={(e) => void submit(e)}>
            <div className="field-row">
              <div className="field">
                <label htmlFor="reg-user">Username</label>
                <input id="reg-user" placeholder="e.g. j.singh" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus />
              </div>
              <div className="field">
                <label htmlFor="reg-name">Display name</label>
                <input id="reg-name" placeholder="Optional" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" />
              </div>
            </div>

            <div className="field">
              <label htmlFor="reg-email">Work email</label>
              <input id="reg-email" type="email" placeholder="Optional · used for audit & notifications" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
            </div>

            <div className="field-row">
              <div className="field">
                <label htmlFor="reg-pass">Password</label>
                <input id="reg-pass" type="password" placeholder="Minimum 8 characters" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
              </div>
              <div className="field">
                <label htmlFor="reg-confirm">Confirm password</label>
                <input id="reg-confirm" type="password" placeholder="Re-enter password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
              </div>
            </div>

            <div className="field" style={{ marginTop: 6 }}>
              <label>Select your role</label>
              <div className="role-grid">
                {ROLE_CATALOG.map(({ role: r, desc, adminOnly }) => {
                  const selected = role === r;
                  const disabled = !!adminOnly;
                  return (
                    <button
                      key={r}
                      type="button"
                      disabled={disabled}
                      onClick={() => setRole(r)}
                      className={`role-opt${selected ? " sel" : ""}`}
                      title={disabled ? "Superadmin is provisioned by an administrator only." : desc}
                    >
                      <div className="rname">
                        {r}
                        {adminOnly && <span className="lock">🔒 admin-assigned</span>}
                      </div>
                      <div className="rdesc">{desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            <button className="btn primary auth-submit" type="submit" disabled={busy}>
              {busy ? "Creating account…" : "Create account"}
            </button>
          </form>

          <div className="auth-alt">
            <span>Already have an account?</span>
            <a href="#/login">Sign in</a>
          </div>
        </div>

        <div className="auth-foot">
          Registration is recorded in the hash-chained audit log.
          <br />Accounts receive least-privilege scope under fail-closed ABAC policy.
        </div>
      </main>
    </div>
  );
}
