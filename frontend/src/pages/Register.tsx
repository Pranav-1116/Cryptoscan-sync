import React, { useState } from "react";
import { authService } from "../lib/authService";
import { Button } from "../components/ui";

export default function Register() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [organization, setOrganization] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [agreeTerms, setAgreeTerms] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isPasswordFocused, setIsPasswordFocused] = useState(false);

  // Password strength calculation
  const getPasswordStrength = (pass: string) => {
    if (!pass) return { score: 0, label: "None", tone: "slate" };
    let score = 0;
    if (pass.length >= 8) score += 1;
    if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) score += 1;
    if (/[0-9]/.test(pass) || /[^A-Za-z0-9]/.test(pass)) score += 1;
    if (pass.length >= 14) score += 1;

    if (score <= 1) return { score: 25, label: "Weak", tone: "red" };
    if (score === 2) return { score: 50, label: "Fair", tone: "amber" };
    if (score === 3) return { score: 75, label: "Good", tone: "cyan" };
    return { score: 100, label: "Strong", tone: "green" };
  };

  const strength = getPasswordStrength(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!fullName.trim()) {
      setError("Please enter your full name.");
      return;
    }
    if (!email.trim()) {
      setError("Please enter your work email.");
      return;
    }
    if (!password) {
      setError("Please enter a password.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    if (!agreeTerms) {
      setError("Please agree to the Terms of Service and Privacy Policy.");
      return;
    }

    setLoading(true);
    setError(null);

    const res = await authService.register({
      fullName: fullName.trim(),
      email: email.trim(),
      organization: organization.trim(),
      password,
    });
    setLoading(false);

    if (res.ok) {
      try {
        sessionStorage.setItem("zelnx_pending_email", email.trim());
      } catch { /* ignore */ }
      window.location.hash = "#/verify-email";
    } else {
      setError(res.error || "Unable to complete registration. Please try again.");
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
        padding: "32px 16px",
      }}
    >
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

      <div
        className="panel"
        style={{
          width: "100%",
          maxWidth: "460px",
          padding: "32px 28px",
          background: "var(--panel)",
          border: "1px solid var(--line)",
          borderRadius: "12px",
          boxShadow: "0 12px 40px rgba(0, 0, 0, 0.45)",
        }}
      >
        <div style={{ marginBottom: "20px" }}>
          <h1 style={{ fontSize: "20px", fontWeight: 600, margin: "0 0 6px", color: "var(--text)" }}>
            Create your ZELNX account
          </h1>
          <p style={{ margin: 0, fontSize: "13px", color: "var(--dim)" }}>
            Set up secure access to your cryptographic security workspace.
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
              marginBottom: "16px",
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div>
            <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
              Full name
            </label>
            <input
              type="text"
              autoComplete="name"
              placeholder="Vikram A."
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="inp"
              style={{ fontSize: "13px", height: "40px" }}
              disabled={loading}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
              Work email
            </label>
            <input
              type="email"
              autoComplete="username email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="inp"
              style={{ fontSize: "13px", height: "40px" }}
              disabled={loading}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
              Organization name
            </label>
            <input
              type="text"
              placeholder="e.g. Acme Financial Group"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              className="inp"
              style={{ fontSize: "13px", height: "40px" }}
              disabled={loading}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
              Password
            </label>
            <input
              type="password"
              autoComplete="new-password"
              placeholder="Create a strong password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onFocus={() => setIsPasswordFocused(true)}
              onBlur={() => setIsPasswordFocused(false)}
              className="inp"
              style={{ fontSize: "13px", height: "40px" }}
              disabled={loading}
            />

            {/* Password strength & policy UX feedback */}
            {password && (
              <div style={{ marginTop: "8px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11px", color: "var(--dim)", marginBottom: "4px" }}>
                  <span>Password strength: <b style={{ color: `var(--${strength.tone})` }}>{strength.label}</b></span>
                </div>
                <div className="bar">
                  <i className={strength.tone} style={{ width: `${strength.score}%` }} />
                </div>
              </div>
            )}

            {isPasswordFocused && (
              <div style={{ marginTop: "8px", padding: "8px 10px", background: "var(--bg-2)", borderRadius: "6px", fontSize: "11px", color: "var(--dim)" }}>
                <div>✓ Minimum 8 characters</div>
                <div>✓ Uppercase, lowercase & number</div>
                <div>✓ Enterprise cryptographic pass-policy</div>
              </div>
            )}
          </div>

          <div>
            <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
              Confirm password
            </label>
            <input
              type="password"
              autoComplete="new-password"
              placeholder="Re-enter your password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="inp"
              style={{ fontSize: "13px", height: "40px" }}
              disabled={loading}
            />
            {confirmPassword && password !== confirmPassword && (
              <span style={{ fontSize: "11px", color: "var(--red)", marginTop: "3px", display: "block" }}>
                Passwords do not match.
              </span>
            )}
          </div>

          {/* 17. Terms & Privacy */}
          <div style={{ display: "flex", alignItems: "flex-start", gap: "8px", marginTop: "2px" }}>
            <input
              type="checkbox"
              id="terms"
              checked={agreeTerms}
              onChange={(e) => setAgreeTerms(e.target.checked)}
              style={{ marginTop: "3px", cursor: "pointer", accentColor: "var(--cyan)" }}
            />
            <label htmlFor="terms" style={{ fontSize: "12px", color: "var(--dim)", lineHeight: 1.4, cursor: "pointer" }}>
              I agree to the <a href="#/terms" style={{ color: "var(--cyan)" }}>Terms of Service</a> and <a href="#/privacy" style={{ color: "var(--cyan)" }}>Privacy Policy</a>.
            </label>
          </div>

          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={loading}
            style={{ width: "100%", height: "42px", fontSize: "13.5px", marginTop: "8px" }}
          >
            {loading ? "◌ Creating account..." : "Create account"}
          </Button>
        </form>

        <div style={{ textAlign: "center", marginTop: "20px", fontSize: "12.5px", color: "var(--dim)" }}>
          Already have an account?{" "}
          <a href="#/login" style={{ color: "var(--cyan)", fontWeight: 500 }}>
            Sign in
          </a>
        </div>
      </div>
    </div>
  );
}
