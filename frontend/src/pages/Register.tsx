import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiRegister, isBackendLive } from "../lib/api.js";
import { LanguageSwitcher } from "../i18n/I18n.jsx";
import { BrandMark, ICON_MD, IconClose } from "../components/icons";

/* These are the roles accepted by the live registration endpoint. The backend
 * remains authoritative and rejects unknown or admin-only roles. */
const ROLE_CATALOG: Array<{ role: string; desc: string; adminOnly?: boolean }> = [
  { role: "ciso", desc: "Compliance, policy and exception workflows" },
  { role: "security_analyst", desc: "Findings and exception workflows" },
  { role: "auditor", desc: "Read-only reports and evidence" },
  { role: "developer", desc: "Findings for owned systems" },
  { role: "business_owner", desc: "Findings for owned business systems" },
  { role: "scanner", desc: "Authorized scan submission" },
  { role: "readonly", desc: "Dashboard view only" },
  { role: "supervisor", desc: "Read-only supervisory view" },
  { role: "superadmin", desc: "Platform administration", adminOnly: true },
];

function BrandPanel() {
  return (
    <aside className="auth-brand">
      <div style={{ display: "flex", justifyContent: "flex-end" }}><LanguageSwitcher /></div>
      <div className="auth-logo">
        <BrandMark size={40} />
        <span>
          ZELNX
          <span className="tagline">CRYPTO INTELLIGENCE PLATFORM</span>
        </span>
      </div>
      <div className="auth-hero">
        <h2>Request access to the control plane.</h2>
        <p>Create a tenant-scoped account. The live API validates the role, password policy and account state.</p>
      </div>
      <div className="auth-foot" style={{ marginTop: "auto", textAlign: "left" }}>
        Account creation is recorded by the live audit service.
      </div>
    </aside>
  );
}

/** Create an account through POST /api/v1/auth/register. */
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
  const navigate = useNavigate();

  React.useEffect(() => {
    void isBackendLive().then(setBackendUp);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const uname = username.trim();
    if (uname.length < 2) return setError("Username must be at least 2 characters.");
    if (password.length < 12) return setError("Password must be at least 12 characters.");
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
      navigate(`/login?u=${encodeURIComponent(uname)}`, { replace: true });
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
            <div className="kicker">Workspace access</div>
            <h1>Create account</h1>
            <p>Account creation uses the live control plane. Access is limited by the role granted by the API.</p>
            <span className={`auth-status ${backendUp === null ? "" : backendUp ? "live" : "down"}`}>
              <span className="dot" />
              {backendUp === null
                ? "Connecting to control plane…"
                : backendUp
                  ? "Control plane connected"
                  : "Control plane offline · registration unavailable"}
            </span>
          </div>

          {error && <div className="auth-alert err" role="alert"><IconClose className="ico" size={ICON_MD} /> {error}</div>}

          <form onSubmit={(e) => void submit(e)}>
            <div className="field-row">
              <div className="field">
                <label htmlFor="reg-user">Username</label>
                <input id="reg-user" placeholder="e.g. j.singh" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
              </div>
              <div className="field">
                <label htmlFor="reg-name">Display name</label>
                <input id="reg-name" placeholder="Optional" value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoComplete="name" />
              </div>
            </div>

            <div className="field">
              <label htmlFor="reg-email">Work email</label>
              <input id="reg-email" type="email" placeholder="Optional" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
            </div>

            <div className="field-row">
              <div className="field">
                <label htmlFor="reg-pass">Password</label>
                <input id="reg-pass" type="password" placeholder="Minimum 12 characters" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required minLength={12} />
              </div>
              <div className="field">
                <label htmlFor="reg-confirm">Confirm password</label>
                <input id="reg-confirm" type="password" placeholder="Re-enter password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" required minLength={12} />
              </div>
            </div>

            <div className="field" style={{ marginTop: 6 }}>
              <label>Requested access role</label>
              <div className="role-grid">
                {ROLE_CATALOG.map(({ role: candidate, desc, adminOnly }) => {
                  const selected = role === candidate;
                  return (
                    <button
                      key={candidate}
                      type="button"
                      disabled={adminOnly}
                      onClick={() => setRole(candidate)}
                      className={`role-opt${selected ? " sel" : ""}`}
                      title={adminOnly ? "This role must be granted by an administrator." : desc}
                    >
                      <div className="rname">
                        {candidate}
                        {adminOnly && <span className="lock">admin-assigned</span>}
                      </div>
                      <div className="rdesc">{desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            <button className="btn primary auth-submit" type="submit" disabled={busy || !username.trim() || !password || !confirm}>
              {busy ? "Creating account…" : "Create account"}
            </button>
          </form>

          <div className="auth-alt">
            <span>Already have an account?</span>
            <Link to="/login">Sign in</Link>
          </div>
        </div>
        <div className="auth-foot">
          Registration is recorded in the live audit log · least-privilege access by default
        </div>
      </main>
    </div>
  );
}
