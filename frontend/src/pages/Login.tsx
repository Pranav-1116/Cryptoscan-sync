import React, { useState } from "react";
import { apiLogin, isBackendLive, getToken } from "../lib/api.js";
import { Corners, Kicker } from "../components/ui.jsx";

/* Login — the console authenticates against the control plane API
   (POST /api/v1/auth/login) and stores the session token. When the
   backend is offline the console falls back to demo mode without auth. */

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [backendUp, setBackendUp] = useState<boolean | null>(null);

  React.useEffect(() => {
    void isBackendLive().then(setBackendUp);
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
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
      <div className="frame" style={{ width: "min(420px, 100%)", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: 16, padding: "34px 32px", backdropFilter: "blur(12px)" }}>
        <Corners />
        <div style={{ textAlign: "center", marginBottom: 24 }}>
          <div style={{ width: 52, height: 52, borderRadius: 14, display: "grid", placeItems: "center", margin: "0 auto 14px", background: "var(--grad)", color: "#03121a", fontFamily: "var(--mono)", fontWeight: 700, fontSize: 26, boxShadow: "0 0 26px rgba(34,211,238,.5)" }}>Z</div>
          <Kicker>ZELNX console</Kicker>
          <h1 style={{ fontSize: 24, margin: "10px 0 4px" }}>Sign in</h1>
          <p className="dim" style={{ fontSize: 13, margin: 0 }}>
            {backendUp === null ? "probing control plane…" : backendUp ? "control plane reachable — authenticate to stream live data" : "control plane offline — you can explore in demo mode"}
          </p>
        </div>
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
        <div style={{ marginTop: 14, textAlign: "center", fontSize: 12.5 }}>
          <a href="#/" className="mono" style={{ color: "var(--dim)" }}>continue in demo mode →</a>
        </div>
        {getToken() && (
          <div style={{ marginTop: 14, textAlign: "center" }}>
            <a href="#/" className="mono" style={{ fontSize: 12, color: "var(--green)" }}>already signed in — enter console</a>
          </div>
        )}
      </div>
    </div>
  );
}
