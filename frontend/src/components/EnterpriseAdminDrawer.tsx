/* EnterpriseAdminDrawer — right-hand administration drawer for the console
 * shell.
 *
 * Tabs:
 *  - security_center : live platform security posture (GET
 *    /api/v1/security/posture) — score, agents, plugins, open threats,
 *    certs, audit-chain status. Honest empty state when the backend is down.
 *  - user_profile    : the signed-in session (GET /api/v1/auth/me details —
 *    username, real RBAC roles, MFA state, active sessions).
 *  - about           : platform version + determinism note.
 */
import React, { useEffect, useState } from "react";
import {
  ApiResult, apiAuthMeDetails, apiSecurityPosture, SecurityPosture,
} from "../lib/api.js";
import { useAuth } from "../lib/auth.js";
import { useEnterprise } from "./EnterpriseContext";

export type AdminDrawerTab = "security_center" | "user_profile" | "about";

const TABS: Array<{ id: AdminDrawerTab; label: string; icon: string }> = [
  { id: "security_center", label: "Security Center", icon: "⛨" },
  { id: "user_profile", label: "User Profile", icon: "👤" },
  { id: "about", label: "About", icon: "ℹ" },
];

function Row({ k, v, tone }: { k: string; v: React.ReactNode; tone?: "ok" | "warn" | "bad" }) {
  const color = tone === "ok" ? "var(--green)" : tone === "warn" ? "var(--amber)" : tone === "bad" ? "var(--red)" : "var(--text)";
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, padding: "6px 0", borderBottom: "1px solid var(--line)", fontSize: "12.5px" }}>
      <span className="dim">{k}</span>
      <span style={{ color, textAlign: "right", fontWeight: 600 }}>{v}</span>
    </div>
  );
}

/* ── Security Center tab ──────────────────────────────────────────── */
function SecurityCenterTab() {
  const [posture, setPosture] = useState<SecurityPosture | null>(null);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    apiSecurityPosture().then((res: ApiResult<SecurityPosture>) => {
      if (cancelled) return;
      if (res.source === "live" && res.data) setPosture(res.data);
      else setOffline(true);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) return <div className="dim" style={{ fontSize: 12 }}>loading live posture…</div>;
  if (offline || !posture) {
    return (
      <div>
        <div className="badge" style={{ display: "inline-block", marginBottom: 10, borderColor: "var(--red)", color: "var(--red)" }}>
          <span className="dot" /> backend offline — posture unavailable
        </div>
        <p className="dim" style={{ fontSize: 12 }}>
          Open the <a href="#/security-center" style={{ color: "var(--cyan)" }}>Security Center</a> for the full console.
        </p>
      </div>
    );
  }

  const scoreTone = posture.score >= 80 ? "ok" : posture.score >= 50 ? "warn" : "bad";
  return (
    <div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
        <span style={{ fontSize: 34, fontWeight: 700, color: scoreTone === "ok" ? "var(--green)" : scoreTone === "warn" ? "var(--amber)" : "var(--red)" }}>
          {posture.score}
        </span>
        <span className="dim" style={{ fontSize: 12 }}>/ 100 deterministic posture score (snapshot {posture.snapshot_id?.slice(0, 8)})</span>
      </div>
      <Row k="Agents" v={`${posture.agents_healthy} / ${posture.agents_total} healthy`} tone={posture.agents_healthy === posture.agents_total ? "ok" : "warn"} />
      <Row k="Plugins" v={`${posture.plugins_verified} / ${posture.plugins_total} verified`} tone={posture.plugins_verified === posture.plugins_total ? "ok" : "warn"} />
      <Row k="Open threats" v={posture.threats_open ? `${posture.threats_open} (${posture.threats_critical} critical)` : "0"} tone={posture.threats_critical > 0 ? "bad" : posture.threats_open > 0 ? "warn" : "ok"} />
      <Row k="Failed logins (recent)" v={posture.failed_logins} tone={posture.failed_logins > 0 ? "warn" : "ok"} />
      <Row k="Certificates valid" v={posture.cert_valid_pct == null ? "—" : `${posture.cert_valid_pct}% of ${posture.cert_total}`} tone={(posture.cert_valid_pct ?? 100) >= 95 ? "ok" : "warn"} />
      <Row k="Audit chain" v={posture.audit_ok ? "VALID" : "BROKEN"} tone={posture.audit_ok ? "ok" : "bad"} />
      <Row k="Credentials" v={`${posture.credentials_active} active / ${posture.credentials_total}`} />
      <p className="dim" style={{ fontSize: 11, marginTop: 10 }}>
        Score is computed deterministically by the control plane — no AI. Full view:
        <a href="#/security-center" style={{ color: "var(--cyan)" }}> Security Center</a>
      </p>
    </div>
  );
}

/* ── User Profile tab ─────────────────────────────────────────────── */
interface MeDetails {
  username: string; roles: string[]; permissions: string[];
  mfa_enabled: boolean; display_name: string; email: string | null;
  active_sessions: number;
}

function UserProfileTab() {
  const { user, roles } = useAuth();
  const { org, env, infoLevel, timezone } = useEnterprise();
  const [me, setMe] = useState<MeDetails | null>(null);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    apiAuthMeDetails().then((res: ApiResult<MeDetails>) => {
      if (cancelled) return;
      if (res.source === "live" && res.data) setMe(res.data);
      else setOffline(true);
      setLoading(false);
    });
    return () => { cancelled = true; };
  }, []);

  const displayRoles = me?.roles ?? roles;
  return (
    <div>
      {loading && <div className="dim" style={{ fontSize: 12 }}>loading session…</div>}
      <Row k="Display name" v={me?.display_name || user || "—"} />
      <Row k="Username" v={me?.username || user || "—"} />
      <Row k="Email" v={me?.email || "—"} />
      <Row k="Roles" v={displayRoles.length ? displayRoles.join(", ") : (offline ? "—" : "none")} />
      <Row k="MFA" v={me ? (me.mfa_enabled ? "enabled (TOTP)" : "not enabled") : "—"} tone={me && !me.mfa_enabled ? "warn" : "ok"} />
      <Row k="Active sessions" v={me ? String(me.active_sessions) : "—"} />
      <Row k="Organization" v={org.name} />
      <Row k="Environment (view)" v={env} />
      <Row k="Info level" v={infoLevel} />
      <Row k="Timezone (view)" v={timezone} />
      {offline && (
        <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
          Session details require the backend; showing local session data only.
        </p>
      )}
    </div>
  );
}

/* ── About tab ────────────────────────────────────────────────────── */
function AboutTab() {
  return (
    <div style={{ fontSize: "12.5px", lineHeight: 1.7 }}>
      <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6 }}>ZELNX · CryptoScan Intelligence Platform</div>
      <p className="dim">
        Deterministic cryptographic discovery, inventory and compliance.
        Evidence-chained observations, YAML policy, drift detection and a
        Cryptographic Digital Twin. Policy is never decided by AI — scanners
        prove facts, rules decide compliance.
      </p>
      <p className="dim" style={{ fontSize: 11 }}>
        Version 1.0.0 · API /api/v1 · OpenAPI docs at /api/docs (when enabled)
      </p>
    </div>
  );
}

/* ── Drawer shell ─────────────────────────────────────────────────── */
export function EnterpriseAdminDrawer({
  isOpen, onClose, initialTab,
}: {
  isOpen: boolean; onClose: () => void; initialTab?: AdminDrawerTab;
}) {
  const [tab, setTab] = useState<AdminDrawerTab>(initialTab || "security_center");

  useEffect(() => {
    if (isOpen && initialTab) setTab(initialTab);
  }, [isOpen, initialTab]);

  if (!isOpen) return null;

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 10002, background: "rgba(0,0,0,0.45)" }} onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          position: "absolute", top: 0, right: 0, bottom: 0, width: "420px", maxWidth: "94vw",
          background: "var(--bg-1)", borderLeft: "1px solid var(--line-strong)",
          boxShadow: "-20px 0 40px rgba(0,0,0,0.5)", display: "flex", flexDirection: "column",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 16px", borderBottom: "1px solid var(--line)" }}>
          <span style={{ fontWeight: 700, fontSize: "14px" }}>⛨ Administration</span>
          <button onClick={onClose} className="btn sm">✕</button>
        </div>
        <div style={{ display: "flex", gap: "4px", padding: "10px 12px", borderBottom: "1px solid var(--line)" }}>
          {TABS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={tab === t.id ? "btn sm" : "btn sm ghost"}
              style={{ fontSize: "11.5px", flex: 1 }}
            >
              {t.icon} {t.label}
            </button>
          ))}
        </div>
        <div style={{ padding: "16px", overflowY: "auto", flex: 1 }}>
          {tab === "security_center" && <SecurityCenterTab />}
          {tab === "user_profile" && <UserProfileTab />}
          {tab === "about" && <AboutTab />}
        </div>
      </div>
    </div>
  );
}

export default EnterpriseAdminDrawer;
