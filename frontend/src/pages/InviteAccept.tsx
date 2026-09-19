import React, { useState } from "react";
import { Badge, PageHead, Panel } from "../components/ui.jsx";
import { apiSaasAcceptInvite } from "../lib/api.js";

/* InviteAccept — redeem a one-time tenant invitation (/?token=csi_…).
   New identities set their password here; existing identities are asked to
   sign in first (the server refuses to rebind a live account from a token). */

export default function InviteAccept() {
  const params = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
  const [token, setToken] = useState(params.get("token") ?? "");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [done, setDone] = useState<{ tenant?: string; role?: string } | null>(null);

  async function accept() {
    const r = await apiSaasAcceptInvite({
      token: token.trim(),
      password: password || undefined,
    });
    if (r.ok) {
      setDone({ tenant: r.tenant_name, role: r.tenant_role });
      setMsg(null);
    } else {
      setDone(null);
      setMsg(r.error ?? "failed");
    }
  }

  return (
    <div>
      <PageHead crumb="SaaS" title="Accept invite" sub="Join an organization with your one-time invitation token" />
      <Panel title="Invitation">
        {done ? (
          <p>
            Welcome to <strong>{done.tenant}</strong> — your role is{" "}
            <Badge tone={done.role === "owner" ? "green" : undefined}>{done.role}</Badge>. Sign in to get started.
          </p>
        ) : (
          <div style={{ display: "grid", gap: 8, maxWidth: 420 }}>
            <input placeholder="invite token (csi_…)" value={token} onChange={(e) => setToken(e.target.value)} />
            <input
              placeholder="choose a password (new accounts)"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button onClick={accept}>Join the organization</button>
            {msg && (
              <p style={{ fontSize: 12, opacity: 0.8 }}>
                {msg}
              </p>
            )}
            <p style={{ fontSize: 12, opacity: 0.6 }}>
              Already have an account? Sign in first — tokens can never take over an existing identity.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}
