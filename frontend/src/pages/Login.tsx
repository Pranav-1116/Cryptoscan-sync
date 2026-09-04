import React, { useState } from "react";
import { apiLogin, isBackendLive, getToken, getRoles } from "../lib/api.js";

const ROLE_CATALOG: Array<{ role: string; desc: string }> = [
  { role: "superadmin", desc: "Full platform access" },
  { role: "ciso", desc: "Compliance, policy & exceptions" },
  { role: "security_analyst", desc: "Findings & exceptions" },
  { role: "developer", desc: "Findings for own systems" },
  { role: "auditor", desc: "Read-only reports" },
  { role: "business_owner", desc: "Owned systems" },
  { role: "scanner", desc: "API scan submission" },
  { role: "readonly", desc: "Dashboard only" },
];

/* ── shared left brand panel ───────────────────────────────────────── */
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
        <h2>Deterministic control plane for post-quantum crypto risk.</h2>
        <p>
          One console for cryptographic inventory, quantum-readiness, compliance
          reporting and exception governance — verified by hash and signature,
          not inference.
        </p>
        <ul className="auth-feats">
          <li>
            <span className="ic">◈</span>
            <span>
              <b>Policy-as-code, fail-closed access</b>
              <span>Hierarchical Region → BU → Environment → Asset scoping enforced on every request.</span>
            </span>
          </li>
          <li>
            <span className="ic">▤</span>
            <span>
              <b>Hash-chained audit trail</b>
              <span>Every action cryptographically linked for regulator-grade integrity.</span>
            </span>
          </li>
          <li>
            <span className="ic">⬡</span>
            <span>
              <b>Benchmarked accuracy, no AI decisions</b>
              <span>Detection performance measured against held-out datasets with stated uncertainty.</span>
            </span>
          </li>
        </ul>
      </div>

      <div className="auth-trust">
        <span className="lbl">Aligned to</span>
        <span className="badge cyan"><span className="dot" />FIPS 140-3</span>
        <span className="badge cyan"><span className="dot" />NIST SP 800-131A</span>
        <span className="badge cyan"><span className="dot" />SOC 2</span>
        <span className="badge cyan"><span className="dot" />PCI DSS 4.0</span>
        <span className="badge cyan"><span className="dot" />ISO 27001</span>
      </div>
    </aside>
  );
}

/* Login — authenticates against the control plane (POST /api/v1/auth/login).
   There is no demo mode: the console requires a sign-in and shows only real
   data from the live platform. */
export default function Login() {
  const params = new URLSearchParams(window.location.hash.split("?")[1] || "");
  const registered = params.get("u") || "";
  const registeredRole = params.get("r") || "";
  const [username, setUsername] = useState(registered || "admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(
    registered ? `Account created — sign in as ${registered}${registeredRole ? ` (${registeredRole})` : ""}.` : null,
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
      setError(res.error || "Sign-in failed. Check your credentials and try again.");
    }
  };

  return (
    <div className="auth">
      <BrandPanel />

      <main className="auth-panel">
        <div className="auth-form">
          <div className="auth-head">
            <div className="kicker">Control plane access</div>
            <h1>Sign in</h1>
            <p>Authenticate to your workspace to stream live inventory, findings and compliance telemetry.</p>
            <span className={`auth-status ${backendUp === null ? "" : backendUp ? "live" : "down"}`}>
              <span className="dot" />
              {backendUp === null
                ? "Connecting to control plane…"
                : backendUp
                  ? "Control plane connected · live data"
                  : "Control plane offline — sign in when reachable"}
            </span>
          </div>

          {notice && <div className="auth-alert ok">✓ {notice}</div>}
          {error && <div className="auth-alert err">✕ {error}</div>}

          <form onSubmit={(e) => void submit(e)}>
            <div className="field">
              <label htmlFor="login-user">Username</label>
              <input
                id="login-user"
                placeholder="e.g. admin"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
              />
            </div>
            <div className="field">
              <label htmlFor="login-pass">Password</label>
              <input
                id="login-pass"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
              />
            </div>

            <button className="btn primary auth-submit" type="submit" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
          </form>

          <div className="auth-alt">
            <span>New to the platform?</span>
            <a href="#/register">Request an account</a>
          </div>

          {token && roles.length > 0 ? (
            <div className="auth-alert ok" style={{ marginTop: 16 }}>
              <span>
                ● Already signed in as <b>{username}</b> — roles: {roles.join(", ")}.{" "}
                <a href="#/" style={{ color: "inherit", fontWeight: 700 }}>Enter console →</a>
              </span>
            </div>
          ) : (
            <details className="auth-note">
              <summary>Seeded bootstrap credentials & role catalog</summary>
              <div className="note-body">
                The bootstrap platform-owner account is <code>admin / cryptoscan</code>
                &nbsp;(alias → superadmin). Change it after first sign-in.
                <div style={{ marginTop: 8 }}>8-role RBAC catalog:</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 5, marginTop: 6 }}>
                  {ROLE_CATALOG.map(({ role }) => (
                    <code key={role} style={{ background: "var(--panel-2)", padding: "2px 7px", borderRadius: 4, color: "var(--dim)" }}>
                      {role}
                    </code>
                  ))}
                </div>
              </div>
            </details>
          )}
        </div>

        <div className="auth-foot">
          ZELNX Crypto Intelligence · policy-as-code · hash-chained audit · fail-closed RBAC
          <br />No AI inference makes policy decisions. All findings are deterministic and replayable.
        </div>
      </main>
    </div>
  );
}
