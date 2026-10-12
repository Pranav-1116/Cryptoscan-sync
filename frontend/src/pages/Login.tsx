import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiLogin, isBackendLive } from "../lib/api.js";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";
import { BrandMark, ICON_MD, IconClose, IconOk } from "../components/icons";
import { DecryptText } from "../lib/motion";

function BrandPanel() {
  const { t } = useI18n();
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
        <DecryptText text={t("app.title")} className="auth-cue" />
        <h2>{t("login.heroTitle")}</h2>
        <p>{t("app.tagline")}</p>
      </div>
      <div className="auth-foot" style={{ marginTop: "auto", textAlign: "left" }}>
        Live control-plane data · tenant-scoped access · auditable rules
      </div>
    </aside>
  );
}

/** Sign in against the live control plane. No local credentials are shown. */
export default function Login() {
  const params = new URLSearchParams(window.location.search);
  const registered = params.get("u") || "";
  const [username, setUsername] = useState(registered);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(
    registered ? `Account created. Sign in as ${registered}.` : null,
  );
  const [busy, setBusy] = useState(false);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);
  const { t } = useI18n();
  const navigate = useNavigate();

  React.useEffect(() => {
    void isBackendLive().then(setBackendUp);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    const res = await apiLogin(username.trim(), password);
    setBusy(false);
    if (res.ok) {
      navigate("/command-center", { replace: true });
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
            <div className="kicker">{t("login.kicker")}</div>
            <h1>{t("login.title")}</h1>
            <p>{t("login.subtitle")}</p>
            <span className={`auth-status ${backendUp === null ? "" : backendUp ? "live" : "down"}`}>
              <span className="dot" />
              {backendUp === null
                ? t("app.banner.connecting")
                : backendUp
                  ? t("app.banner.live")
                  : t("app.banner.offline")}
            </span>
          </div>

          {notice && <div className="auth-alert ok" role="status"><IconOk className="ico" size={ICON_MD} /> {notice}</div>}
          {error && <div className="auth-alert err" role="alert"><IconClose className="ico" size={ICON_MD} /> {error}</div>}

          <form onSubmit={(e) => void submit(e)}>
            <div className="field">
              <label htmlFor="login-user">{t("login.username")}</label>
              <input
                id="login-user"
                placeholder={t("login.usernamePlaceholder")}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                required
              />
            </div>
            <div className="field">
              <label htmlFor="login-pass">{t("login.password")}</label>
              <input
                id="login-pass"
                type="password"
                placeholder={t("login.passwordPlaceholder")}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
              />
            </div>
            <button className="btn primary auth-submit" type="submit" disabled={busy || !username.trim() || !password}>
              {busy ? t("login.signingIn") : t("login.signIn")}
            </button>
          </form>

          <div className="auth-alt">
            <span>{t("login.newHere")}</span>
            <Link to="/register">{t("login.requestAccount")}</Link>
          </div>
        </div>
        <div className="auth-foot">
          ZELNX Crypto Intelligence · live control plane · tenant-scoped evidence
        </div>
      </main>
    </div>
  );
}
