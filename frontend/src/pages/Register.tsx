import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiRegister, isBackendLive } from "../lib/api.js";
import { LanguageSwitcher } from "../i18n/I18n.jsx";
import { BrandMark, ICON_MD, IconClose } from "../components/icons";

function BrandPanel() {
  return <aside className="auth-brand">
    <div style={{ display: "flex", justifyContent: "flex-end" }}><LanguageSwitcher /></div>
    <div className="auth-logo"><BrandMark size={40} /><span>ZELNX<span className="tagline">CRYPTO INTELLIGENCE PLATFORM</span></span></div>
    <div className="auth-hero">
      <div className="auth-cue">WORKSPACE ACCESS / 01</div>
      <h2>Your identity, then your evidence.</h2>
      <p><span title={"Create a personal account on the live CryptoScan control plane. Elevated permissions are granted separately by a platform administrator."}>{"Create a personal account on the live CryptoScan control plane."}</span></p>
      <div className="auth-principles">
        <div><b>01</b><span>Identify your account</span></div>
        <div><b>02</b><span>Choose a strong password</span></div>
        <div><b>03</b><span>Sign in with read-only access</span></div>
      </div>
    </div>
    <div className="auth-foot" style={{ margin: "auto 0 0", textAlign: "left" }}>
      No offline accounts. Registration is validated and recorded by the backend when connected.
    </div>
  </aside>;
}

/** Public registration creates a least-privilege account; it is not role approval. */
export default function Register() {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    let mounted = true;
    const check = () => { void isBackendLive().then(up => { if (mounted) setBackendUp(up); }); };
    check();
    const timer = window.setInterval(check, 6000);
    return () => { mounted = false; window.clearInterval(timer); };
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    if (backendUp !== true) return setError("Connect to the CryptoScan API before creating an account.");
    const name = username.trim();
    if (name.length < 2) return setError("Username must be at least 2 characters.");
    if (password.length < 12) return setError("Password must be at least 12 characters.");
    if (password !== confirm) return setError("Passwords do not match.");
    setBusy(true);
    try {
      const result = await apiRegister({
        username: name, password, role: "readonly",
        display_name: displayName.trim() || undefined,
        email: email.trim() || undefined,
      });
      if (result.ok) navigate(`/login?u=${encodeURIComponent(name)}`, { replace: true });
      else setError(result.error || "Registration was not confirmed. Check the live API before retrying.");
    } finally {
      setBusy(false);
    }
  };

  return <div className="auth">
    <BrandPanel />
    <main className="auth-panel">
      <div className="auth-form wide">
        <div className="auth-head">
          <div className="kicker">Individual access</div>
          <h1>Create your account</h1>
          <p><span title={"Use your own credentials. Your initial role is read-only; an administrator can grant additional access after review."}>{"Use your own credentials."}</span></p>
          <span className={`auth-status ${backendUp === null ? "" : backendUp ? "live" : "down"}`}>
            <span className="dot" />{backendUp === null ? "Checking control plane…" : backendUp ? "Connected to CryptoScan" : "Control plane unavailable"}
          </span>
        </div>

        {error && <div className="auth-alert err" role="alert"><IconClose className="ico" size={ICON_MD} />{error}</div>}
        {backendUp === false && <div className="auth-offline" role="status">
          <b>Registration is temporarily unavailable</b>
          <p><span title={"CryptoScan cannot reach its API. No account or password has been submitted or saved. Start the backend, then this page will reconnect automatically."}>{"CryptoScan cannot reach its API."}</span></p>
          <Link to="/login">Return to sign in</Link>
        </div>}
        {backendUp === null && <p role="status" className="auth-wait">Checking service availability before showing the form…</p>}

        {backendUp === true && <form onSubmit={(event) => void submit(event)}>
          <fieldset className="auth-stage">
            <legend><span>01</span> Account details</legend>
            <div className="field-row">
              <div className="field">
                <label htmlFor="reg-user">Username</label>
                <input id="reg-user" placeholder="e.g. j.singh" value={username} onChange={event => setUsername(event.target.value)} autoComplete="username" minLength={2} maxLength={100} autoFocus required />
              </div>
              <div className="field">
                <label htmlFor="reg-name">Display name <small>optional</small></label>
                <input id="reg-name" placeholder="How colleagues know you" value={displayName} onChange={event => setDisplayName(event.target.value)} autoComplete="name" />
              </div>
            </div>
            <div className="field">
              <label htmlFor="reg-email">Work email <small>optional</small></label>
              <input id="reg-email" type="email" placeholder="name@organization.example" value={email} onChange={event => setEmail(event.target.value)} autoComplete="email" maxLength={320} />
            </div>
          </fieldset>

          <fieldset className="auth-stage">
            <legend><span>02</span> Secure your account</legend>
            <p className="auth-help" id="password-policy"><span title={"At least 12 characters and three of uppercase, lowercase, number or symbol. CryptoScan checks the full policy on submission."}>{"At least 12 characters and three of uppercase, lowercase, number or symbol."}</span></p>
            <div className="field-row">
              <div className="field">
                <label htmlFor="reg-pass">Password</label>
                <div className="auth-password">
                  <input id="reg-pass" type={showPassword ? "text" : "password"} value={password} onChange={event => setPassword(event.target.value)} autoComplete="new-password" aria-describedby="password-policy" minLength={12} maxLength={200} required />
                  <button type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? "Hide" : "Show"}</button>
                </div>
              </div>
              <div className="field">
                <label htmlFor="reg-confirm">Confirm password</label>
                <input id="reg-confirm" type={showPassword ? "text" : "password"} value={confirm} onChange={event => setConfirm(event.target.value)} autoComplete="new-password" minLength={12} maxLength={200} required />
              </div>
            </div>
            {confirm && password !== confirm && <p className="auth-help" role="status">Passwords do not match yet.</p>}
          </fieldset>

          <div className="auth-access-note">
            <span className="auth-access-mark" aria-hidden="true">03</span>
            <div><b>Read-only access to start</b><p>Administrative and investigation permissions are assigned through the live Users &amp; Teams workflow—not selected during public registration.</p></div>
          </div>
          <button className="btn primary auth-submit" type="submit" disabled={busy || !username.trim() || !password || !confirm || password !== confirm}>
            {busy ? "Creating account…" : "Create read-only account"}
          </button>
        </form>}

        <div className="auth-alt"><span>Already have access?</span><Link to="/login">Sign in</Link></div>
      </div>
      <div className="auth-foot">CryptoScan · current identity required · no synthetic account records</div>
    </main>
  </div>;
}
