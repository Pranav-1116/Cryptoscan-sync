import React, { useState } from "react";
import { authService } from "../lib/authService";
import { Button } from "../components/ui";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rateLimitCountdown, setRateLimitCountdown] = useState<number | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) {
      setError("Please enter your work email.");
      return;
    }
    if (!password) {
      setError("Enter your password.");
      return;
    }

    setLoading(true);
    setError(null);

    const res = await authService.login(email.trim(), password, rememberMe);
    setLoading(false);

    if (res.ok) {
      window.location.hash = "#/command-center";
    } else if (res.rateLimited) {
      setError(res.error || "Too many sign-in attempts. Please wait.");
      if (res.retryAfterSec) {
        setRateLimitCountdown(res.retryAfterSec);
        const timer = setInterval(() => {
          setRateLimitCountdown((prev) => {
            if (prev === null || prev <= 1) {
              clearInterval(timer);
              return null;
            }
            return prev - 1;
          });
        }, 1000);
      }
    } else {
      setError(res.error || "Unable to sign in. The email or password is incorrect.");
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center",
        background: "var(--bg)",
        padding: "24px 16px",
      }}
    >
      {/* 3. ZELNX Branding Header */}
      <div style={{ textAlign: "center", marginBottom: "28px" }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: "10px", marginBottom: "6px" }}>
          <span
            style={{
              width: 32,
              height: 32,
              borderRadius: 8,
              display: "grid",
              placeItems: "center",
              background: "var(--grad)",
              color: "#04121d",
              fontSize: 18,
              boxShadow: "var(--glow-cyan)",
            }}
          >
            ◈
          </span>
          <span style={{ fontSize: "24px", fontWeight: 700, letterSpacing: "-0.01em", color: "var(--text)" }}>
            ZELNX
          </span>
        </div>
        <div style={{ fontSize: "13px", color: "var(--faint)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
          Cryptographic Security Platform
        </div>
      </div>

      {/* 4. Login Card (Centered, Minimal, Premium) */}
      <div
        className="panel"
        style={{
          width: "100%",
          maxWidth: "420px",
          padding: "32px 28px",
          background: "var(--panel)",
          border: "1px solid var(--line)",
          borderRadius: "12px",
          boxShadow: "0 12px 40px rgba(0, 0, 0, 0.45)",
        }}
      >
        <div style={{ marginBottom: "22px" }}>
          <h1 style={{ fontSize: "20px", fontWeight: 600, margin: "0 0 6px", color: "var(--text)" }}>
            Welcome back
          </h1>
          <p style={{ margin: 0, fontSize: "13px", color: "var(--dim)" }}>
            Sign in to your ZELNX workspace.
          </p>
        </div>

        {error && (
          <div
            style={{
              padding: "12px 14px",
              background: "rgba(239, 68, 68, 0.08)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              borderRadius: "8px",
              color: "#fca5a5",
              fontSize: "12.5px",
              marginBottom: "18px",
              lineHeight: 1.4,
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: "2px" }}>Unable to sign in</div>
            <div>{error}</div>
            {rateLimitCountdown !== null && (
              <div style={{ marginTop: "4px", fontSize: "11px", fontFamily: "var(--mono)", color: "var(--amber)" }}>
                Retry available in {rateLimitCountdown}s
              </div>
            )}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div>
            <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "6px" }}>
              Work email
            </label>
            <input
              type="text"
              autoComplete="username email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="inp"
              style={{ fontSize: "13.5px", height: "42px" }}
              disabled={loading || rateLimitCountdown !== null}
            />
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
              <label style={{ fontSize: "12.5px", fontWeight: 500, color: "var(--dim)" }}>
                Password
              </label>
              <a
                href="#/forgot-password"
                style={{ fontSize: "12px", color: "var(--cyan)", textDecoration: "none" }}
              >
                Forgot password?
              </a>
            </div>
            <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
              <input
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="inp"
                style={{ fontSize: "13.5px", height: "42px", paddingRight: "40px" }}
                disabled={loading || rateLimitCountdown !== null}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: "absolute",
                  right: "12px",
                  background: "none",
                  border: "none",
                  color: "var(--dim)",
                  cursor: "pointer",
                  fontSize: "14px",
                  padding: "4px",
                }}
                title={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? "👁" : "👁‍🗨"}
              </button>
            </div>
          </div>

          {/* 5. Remember Me */}
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <input
              type="checkbox"
              id="remember"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              style={{ cursor: "pointer", accentColor: "var(--cyan)" }}
            />
            <label htmlFor="remember" style={{ fontSize: "12px", color: "var(--dim)", cursor: "pointer" }}>
              Keep this session active on this device
            </label>
          </div>

          {/* 7. Sign In Button */}
          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={loading || rateLimitCountdown !== null}
            style={{ width: "100%", height: "42px", fontSize: "13.5px", marginTop: "4px" }}
          >
            {loading ? "◌ Signing in..." : "Sign in"}
          </Button>

          {/* 30 & 31. Enterprise SSO & Passkey Architecture Stubs */}
          <div style={{ position: "relative", textAlign: "center", margin: "10px 0" }}>
            <div style={{ position: "absolute", inset: "50% 0", borderTop: "1px solid var(--line)" }} />
            <span style={{ position: "relative", background: "var(--panel)", padding: "0 10px", fontSize: "11px", color: "var(--faint)", textTransform: "uppercase" }}>
              or
            </span>
          </div>

          <button
            type="button"
            onClick={() => {
              window.location.href = "/api/v1/auth/oidc/authorize";
            }}
            className="btn outline"
            style={{ width: "100%", height: "40px", fontSize: "12.5px", display: "flex", alignItems: "center", justifyContent: "center", gap: "8px" }}
          >
            <span>🔐</span> Continue with Enterprise SSO (SAML / OIDC)
          </button>
        </form>

        <div style={{ textAlign: "center", marginTop: "24px", fontSize: "12.5px", color: "var(--dim)" }}>
          Don't have an account?{" "}
          <a href="#/register" style={{ color: "var(--cyan)", fontWeight: 500 }}>
            Create account
          </a>
        </div>
      </div>

      {/* 35. Minimal Security Footer */}
      <div style={{ marginTop: "32px", textAlign: "center", fontSize: "11px", color: "var(--faint)", display: "flex", flexDirection: "column", gap: "6px" }}>
        <div style={{ display: "flex", gap: "16px", justifyContent: "center" }}>
          <span>Privacy</span>
          <span>Terms</span>
          <span>Security Controls</span>
          <span>Status</span>
        </div>
        <div>Protected by ZELNX enterprise cryptographic access controls · © 2026 ZELNX</div>
      </div>
    </div>
  );
}
