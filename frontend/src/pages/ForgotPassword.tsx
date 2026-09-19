import React, { useState } from "react";
import { authService } from "../lib/authService";
import { Button } from "../components/ui";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;

    setLoading(true);
    await authService.forgotPassword(email.trim());
    setLoading(false);
    // Anti-enumeration: Always show generic confirmation
    setSubmitted(true);
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
      </div>

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
        {!submitted ? (
          <>
            <div style={{ marginBottom: "20px" }}>
              <h1 style={{ fontSize: "20px", fontWeight: 600, margin: "0 0 6px", color: "var(--text)" }}>
                Reset your password
              </h1>
              <p style={{ margin: 0, fontSize: "13px", color: "var(--dim)", lineHeight: 1.4 }}>
                Enter your work email and we'll send you instructions to reset your password.
              </p>
            </div>

            <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div>
                <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "6px" }}>
                  Work email
                </label>
                <input
                  type="email"
                  autoComplete="username email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="inp"
                  style={{ fontSize: "13.5px", height: "42px" }}
                  disabled={loading}
                  required
                />
              </div>

              <Button
                type="submit"
                variant="primary"
                size="lg"
                disabled={loading}
                style={{ width: "100%", height: "42px", fontSize: "13.5px", marginTop: "4px" }}
              >
                {loading ? "◌ Sending reset link..." : "Send reset link"}
              </Button>
            </form>
          </>
        ) : (
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: "36px", color: "var(--green)", marginBottom: "12px" }}>✓</div>
            <h2 style={{ fontSize: "18px", fontWeight: 600, margin: "0 0 8px" }}>Check your email</h2>
            <p style={{ fontSize: "13px", color: "var(--dim)", lineHeight: 1.5, margin: "0 0 20px" }}>
              If an account is associated with <b>{email}</b>, you will receive password reset instructions shortly.
            </p>
            <Button
              variant="outline"
              onClick={() => setSubmitted(false)}
              style={{ width: "100%", height: "40px" }}
            >
              Try another email
            </Button>
          </div>
        )}

        <div style={{ textAlign: "center", marginTop: "24px", fontSize: "12.5px" }}>
          <a href="#/login" style={{ color: "var(--cyan)", textDecoration: "none" }}>
            ← Back to sign in
          </a>
        </div>
      </div>
    </div>
  );
}
