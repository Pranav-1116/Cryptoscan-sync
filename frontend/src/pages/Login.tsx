import React, { useState } from "react";
import { apiLogin, isBackendLive, getToken, getRoles } from "../lib/api.js";
import { useI18n, LanguageSwitcher } from "../i18n/I18n.jsx";

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
  const { t } = useI18n();
  return (
    <aside className="auth-brand">
      <div style={{ display: "flex", justifyContent: "flex-end" }}><LanguageSwitcher /></div>
      <div className="auth-logo">
        <span className="mark">◈</span>
        <span>
          ZELNX
          <span className="tagline">CRYPTO INTELLIGENCE PLATFORM</span>
        </span>
      </div>

      <div className="auth-hero">
        <h2>{t("login.heroTitle")}</h2>
        <p>
          {t("app.tagline")}
        </p>
        <ul className="auth-feats">
          <li>
            <span className="ic">◈</span>
            <span>
              <b>{t("login.hero1Title")}</b>
              <span>{t("login.hero1Body")}</span>
            </span>
          </li>
          <li>
            <span className="ic">▤</span>
            <span>
              <b>{t("login.hero2Title")}</b>
              <span>{t("login.hero2Body")}</span>
            </span>
          </li>
          <li>
            <span className="ic">⬡</span>
            <span>
              <b>{t("login.hero3Title")}</b>
              <span>{t("login.hero3Body")}</span>
            </span>
          </li>
        </ul>
      </div>

      <div className="auth-trust">
        <span className="lbl">{t("login.alignedTo")}</span>
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
  const { t } = useI18n();

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

          {notice && <div className="auth-alert ok">✓ {notice}</div>}
          {error && <div className="auth-alert err">✕ {error}</div>}

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
              />
            </div>

            <button className="btn primary auth-submit" type="submit" disabled={busy}>
              {busy ? t("login.signingIn") : t("login.signIn")}
            </button>
          </form>

          <div className="auth-alt">
            <span>{t("login.newHere")}</span>
            <a href="#/register">{t("login.requestAccount")}</a>
          </div>

          {token && roles.length > 0 ? (
            <div className="auth-alert ok" style={{ marginTop: 16 }}>
              <span>
                ● {t("login.alreadySignedIn")} <b>{username}</b> — {roles.join(", ")}.{" "}
                <a href="#/" style={{ color: "inherit", fontWeight: 700 }}>{t("login.enterConsole")} →</a>
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
