import React, { useState, useEffect } from "react";
import { Button } from "../components/ui";

export default function VerifyEmail() {
  const [email, setEmail] = useState("your work email");
  const [resendCooldown, setResendCooldown] = useState<number | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    try {
      const pending = sessionStorage.getItem("zelnx_pending_email");
      if (pending) {
        const [user, domain] = pending.split("@");
        const masked = user.length > 2 ? `${user[0]}••••${user[user.length - 1]}@${domain}` : `${user[0]}••••@${domain}`;
        setEmail(masked);
      }
    } catch { /* ignore */ }
  }, []);

  const handleResend = () => {
    setMessage("Verification email sent. Please check your inbox and spam folder.");
    setResendCooldown(45);
    const interval = setInterval(() => {
      setResendCooldown((prev) => {
        if (prev === null || prev <= 1) {
          clearInterval(interval);
          return null;
        }
        return prev - 1;
      });
    }, 1000);
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
          textAlign: "center",
        }}
      >
        <div style={{ fontSize: "36px", marginBottom: "12px", color: "var(--cyan)" }}>✉</div>
        <h1 style={{ fontSize: "20px", fontWeight: 600, margin: "0 0 8px", color: "var(--text)" }}>
          Verify your email
        </h1>
        <p style={{ margin: "0 0 16px", fontSize: "13px", color: "var(--dim)", lineHeight: 1.5 }}>
          We've sent a verification link to:<br />
          <b style={{ color: "var(--text)", fontFamily: "var(--mono)" }}>{email}</b>
        </p>

        {message && (
          <div
            style={{
              padding: "10px 12px",
              background: "rgba(34, 197, 94, 0.08)",
              border: "1px solid rgba(34, 197, 94, 0.3)",
              borderRadius: "6px",
              color: "#86efac",
              fontSize: "12px",
              marginBottom: "16px",
            }}
          >
            {message}
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "20px" }}>
          <Button
            variant="primary"
            size="lg"
            onClick={() => window.open("mailto:", "_blank")}
            style={{ width: "100%", height: "42px" }}
          >
            Open email client
          </Button>

          <Button
            variant="outline"
            onClick={handleResend}
            disabled={resendCooldown !== null}
            style={{ width: "100%", height: "40px", fontSize: "12.5px" }}
          >
            {resendCooldown ? `Resend available in ${resendCooldown}s` : "Resend verification email"}
          </Button>
        </div>

        <div style={{ marginTop: "24px", fontSize: "12px", color: "var(--dim)" }}>
          Wrong email address?{" "}
          <a href="#/register" style={{ color: "var(--cyan)" }}>
            Change email
          </a>
        </div>
      </div>
    </div>
  );
}
