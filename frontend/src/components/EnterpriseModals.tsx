/* EnterpriseModals — tenant / environment / role selectors for the console
 * shell.
 *
 * TenantModal reads the real tenant directory from the backend
 * (GET /api/v1/saas/admin/tenants for platform admins, otherwise
 * GET /api/v1/scope/tenant/isolation for members) and switches the active
 * tenant via lib/api.ts (X-Tenant-ID on every subsequent call).
 * EnvironmentModal and RoleModal manage the display view-profile from
 * EnterpriseContext.
 */
import React, { useEffect, useState } from "react";
import {
  ApiResult, activeTenantId, apiSaasAdminTenants, apiSaasMemberships, apiTenantIsolation,
  setActiveTenantId,
} from "../lib/api.js";
import { useAuth } from "../lib/auth.js";
import { useEnterprise, EnvProfile } from "./EnterpriseContext";

/* ── shared shell ─────────────────────────────────────────────────── */
function ModalShell({
  title, onClose, children, wide,
}: {
  title: string; onClose: () => void; children: React.ReactNode; wide?: boolean;
}) {
  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 10001, background: "rgba(0,0,0,0.7)",
        backdropFilter: "blur(4px)", display: "flex", alignItems: "center",
        justifyContent: "center",
      }}
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "var(--bg-1)", border: "1px solid var(--line-strong)",
          borderRadius: "10px", padding: "20px", width: wide ? "640px" : "440px",
          maxWidth: "92vw", maxHeight: "80vh", overflowY: "auto",
          boxShadow: "0 20px 40px rgba(0,0,0,0.6)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
          <div style={{ fontWeight: 700, fontSize: "15px", color: "var(--text)" }}>{title}</div>
          <button onClick={onClose} className="btn sm">✕</button>
        </div>
        {children}
      </div>
    </div>
  );
}

function OfflineNote() {
  return (
    <div className="badge" style={{ marginBottom: "10px", display: "inline-block" }}>
      <span className="dot" /> backend offline — showing empty state
    </div>
  );
}

/* ── Tenant / organization switcher ───────────────────────────────── */
interface TenantRow { id: string; name: string; sector?: string; plan?: string }

export function TenantModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [rows, setRows] = useState<TenantRow[]>([]);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const { hasRole } = useAuth();
  const current = activeTenantId();

  useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    setLoading(true);
    setError(undefined);
    (async () => {
      const isAdmin = hasRole("superadmin") || hasRole("admin");
      let list: TenantRow[] = [];
      let ok = false;
      if (isAdmin) {
        const res: ApiResult<{ tenants: { id: string; name: string; plan?: string; sector?: string }[] }> =
          await apiSaasAdminTenants();
        ok = res.source === "live" && !!res.data;
        if (ok && res.data) list = res.data.tenants || [];
      } else {
        // A multi-member user must be able to populate this picker before an
        // active tenant exists. The backend derives this list from membership,
        // not from the currently selected header.
        const res = await apiSaasMemberships();
        ok = res.source === "live" && !!res.data;
        if (ok && res.data) list = res.data.tenants || [];
      }
      if (!ok && isAdmin) {
        const res = await apiTenantIsolation();
        ok = res.source === "live" && !!res.data;
        if (ok && res.data) list = (res.data.tenants || []).map((t) => ({ ...t }));
      }
      if (cancelled) return;
      setRows(ok ? list : []);
      setOffline(!ok);
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [isOpen, hasRole]);

  if (!isOpen) return null;

  const pick = (id: string | null, name?: string) => {
    setActiveTenantId(id);
    try { localStorage.setItem("zelnx_tenant_name", name || ""); } catch { /* ignore */ }
    window.dispatchEvent(new CustomEvent("zelinx:auth", { detail: { token: true } }));
    onClose();
  };

  return (
    <ModalShell title="Organization / Business Unit" onClose={onClose} wide>
      {offline && !loading && <OfflineNote />}
      {loading && <div className="dim" style={{ fontSize: 12 }}>loading tenant directory…</div>}
      {error && <div style={{ color: "var(--red)", fontSize: 12, marginBottom: 8 }}>{error}</div>}
      <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
        {!offline && !loading && rows.length === 0 && (
          <div className="dim" style={{ fontSize: 12 }}>No tenants provisioned yet.</div>
        )}
        {rows.map((t) => (
          <button
            key={t.id}
            onClick={() => pick(t.id, t.name)}
            className={current === t.id ? "btn sm" : "btn sm ghost"}
            style={{
              textAlign: "left", justifyContent: "space-between", width: "100%",
              border: current === t.id ? "1px solid var(--cyan)" : undefined,
            }}
          >
            <span>🏢 {t.name}{t.sector ? ` · ${t.sector}` : ""}</span>
            <span style={{ fontSize: 10, color: "var(--faint)" }}>
              {current === t.id ? "ACTIVE" : t.plan || ""}
            </span>
          </button>
        ))}
        <button
          className="btn sm ghost"
          style={{ textAlign: "left", width: "100%" }}
          onClick={() => pick(null)}
        >
          <span>🌐 Platform estate (no tenant)</span>
        </button>
      </div>
    </ModalShell>
  );
}

/* ── Environment (deployment view profile) switcher ───────────────── */
const ENVS: { id: EnvProfile; label: string; hint: string }[] = [
  { id: "Production", label: "Production", hint: "Live estate — red badge in header" },
  { id: "Staging", label: "Staging", hint: "Pre-production mirror" },
  { id: "Development", label: "Development", hint: "Local / dev estate" },
  { id: "DR", label: "DR", hint: "Disaster-recovery site view" },
];

export function EnvironmentModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { env, setEnv } = useEnterprise();
  if (!isOpen) return null;
  return (
    <ModalShell title="Deployment Environment (view profile)" onClose={onClose}>
      <p className="dim" style={{ fontSize: 11.5, marginBottom: 12 }}>
        Display profile for the console — selects which environment context the
        dashboards review. It is stored per browser and never changes backend
        behaviour.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
        {ENVS.map((e) => (
          <button
            key={e.id}
            onClick={() => { setEnv(e.id); onClose(); }}
            className={env === e.id ? "btn sm" : "btn sm ghost"}
            style={{
              textAlign: "left", justifyContent: "space-between", width: "100%",
              border: env === e.id ? "1px solid var(--cyan)" : undefined,
            }}
          >
            <span>{e.label}</span>
            <span style={{ fontSize: 10, color: "var(--faint)" }}>{e.hint}</span>
          </button>
        ))}
      </div>
    </ModalShell>
  );
}

/* ── Role profile (RBAC) viewer ───────────────────────────────────── */
const ROLE_CATALOG: Array<{ role: string; desc: string }> = [
  { role: "superadmin", desc: "Full platform access (tenants, keys, policy)" },
  { role: "ciso", desc: "Compliance, policy & exceptions" },
  { role: "security_analyst", desc: "Findings, exceptions, approvals" },
  { role: "developer", desc: "Findings for own systems" },
  { role: "auditor", desc: "Read-only reports & attestation" },
  { role: "business_owner", desc: "Owned systems & migration progress" },
  { role: "scanner", desc: "API scan submission" },
  { role: "readonly", desc: "Dashboard only" },
];

export function RoleModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { user, roles: mine } = useAuth();
  if (!isOpen) return null;
  return (
    <ModalShell title="Role Profile (RBAC)" onClose={onClose} wide>
      <div style={{ marginBottom: 12, fontSize: 12.5 }}>
        <div>
          <span className="dim">Signed in as </span>
          <b>{user || "offline"}</b>
        </div>
        <div style={{ marginTop: 4 }}>
          <span className="dim">Session roles: </span>
          {mine.length > 0
            ? mine.map((r) => (
              <span key={r} className="badge green" style={{ marginRight: 4 }}>
                {r}
              </span>
            ))
            : <span className="badge"><span className="dot" /> none (anonymous)</span>}
        </div>
        <p className="dim" style={{ fontSize: 11, marginTop: 8 }}>
          Roles are assigned by a super admin (Users & Teams → Roles) or via
          SSO/SCIM provisioning. They are enforced server-side on every
          privileged request.
        </p>
      </div>
      <table className="tbl" style={{ width: "100%", fontSize: 12 }}>
        <thead>
          <tr><th>Role</th><th>Access</th><th>Yours</th></tr>
        </thead>
        <tbody>
          {ROLE_CATALOG.map((r) => (
            <tr key={r.role}>
              <td style={{ fontFamily: "var(--mono)" }}>{r.role}</td>
              <td>{r.desc}</td>
              <td>{mine.includes(r.role) ? <span className="badge green"><span className="dot" /> yes</span> : <span className="dim">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </ModalShell>
  );
}

export default { TenantModal, EnvironmentModal, RoleModal };
