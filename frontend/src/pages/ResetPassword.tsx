import React, { useState } from "react";
import { authService } from "../lib/authService";
import { Button } from "../components/ui";

export default function ResetPassword() {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) {
      setError("Please enter a new password.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    setError(null);

    const token = new URLSearchParams(window.location.search).get("token") || "mock-token";
    const res = await authService.resetPassword(token, password);
    setLoading(false);

    if (res.ok) {
      setSuccess(true);
    } else {
      setError(res.error || "Reset link expired or invalid.");
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
        {!success ? (
          <>
            <div style={{ marginBottom: "20px" }}>
              <h1 style={{ fontSize: "20px", fontWeight: 600, margin: "0 0 6px", color: "var(--text)" }}>
                Create a new password
              </h1>
              <p style={{ margin: 0, fontSize: "13px", color: "var(--dim)" }}>
                Enter your new enterprise password below.
              </p>
            </div>

            {error && (
              <div
                style={{
                  padding: "10px 12px",
                  background: "rgba(239, 68, 68, 0.08)",
                  border: "1px solid rgba(239, 68, 68, 0.3)",
                  borderRadius: "6px",
                  color: "#fca5a5",
                  fontSize: "12px",
                  marginBottom: "16px",
                }}
              >
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div>
                <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
                  New password
                </label>
                <input
                  type="password"
                  placeholder="Enter new password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="inp"
                  style={{ fontSize: "13px", height: "40px" }}
                  disabled={loading}
                />
              </div>

              <div>
                <label style={{ display: "block", fontSize: "12.5px", fontWeight: 500, color: "var(--dim)", marginBottom: "5px" }}>
                  Confirm new password
                </label>
                <input
                  type="password"
                  placeholder="Confirm new password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="inp"
                  style={{ fontSize: "13px", height: "40px" }}
                  disabled={loading}
                />
              </div>

              <Button
                type="submit"
                variant="primary"
                size="lg"
                disabled={loading}
                style={{ width: "100%", height: "42px", marginTop: "6px" }}
              >
                {loading ? "◌ Resetting password..." : "Reset password"}
              </Button>
            </form>
          </>
        ) : (
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: "36px", color: "var(--green)", marginBottom: "12px" }}>✓</div>
            <h2 style={{ fontSize: "18px", fontWeight: 600, margin: "0 0 8px" }}>Password updated</h2>
            <p style={{ fontSize: "13px", color: "var(--dim)", margin: "0 0 20px" }}>
              Your password has been changed successfully. For your security, please sign in again.
            </p>
            <a href="#/login" className="btn primary" style={{ textDecoration: "none", display: "block", textAlign: "center", height: "40px", lineHeight: "24px" }}>
              Sign in
            </a>
          </div>
        )}
      </div>
    </div>
  );
}
