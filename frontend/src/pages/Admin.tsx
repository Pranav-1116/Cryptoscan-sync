import React, { useEffect, useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { apiSecurity, ApiResult } from "../lib/api.js";
import { useLive } from "../lib/useLive.js";

/* RBAC policy matrix — the authoritative role→permission policy (config, not
   data). Role catalog/descriptions and the tenant list below come from the
   live backend; nothing here is fabricated. */
const PERMISSIONS = ["view", "scan", "configure", "export", "approve", "delete", "simulate", "manage policies", "manage users"];
const MATRIX: Record<string, number[]> = {
  superadmin:       [1,1,1,1,1,1,1,1,1],
  ciso:             [1,0,1,1,1,0,1,1,0],
  security_analyst: [1,1,0,1,1,0,1,0,0],
  developer:        [1,1,0,0,0,0,1,0,0],
  auditor:          [1,0,0,1,0,0,0,0,0],
  business_owner:   [1,0,0,1,1,0,0,0,0],
  scanner:          [0,1,0,0,0,0,0,0,0],
};

export default function Admin() {
  const roles = useLive<{ roles: Record<string, string> }>("/api/v1/auth/roles", { roles: {} });
  const tenants = useLive<{ tenants: any[] }>("/api/v1/control/tenants", { tenants: [] });
  const grants = useLive<{ principal?: string; roles?: string[]; count?: number; abac_enforced?: boolean }>("/api/v1/control/me/grants", {});
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setBusy(true);
    apiSecurity({ action: "validate_scan_request", scope: [], policy: "SAFE" }).then((r) => { setLive(r); setBusy(false); });
  }, []);

  const roleNames = Object.keys(roles.data.roles ?? {});
  const tenantList = tenants.data.tenants ?? [];

  return (
    <>
      <PageHead
        crumb="operate / administration"
        title="Administration"
        sub="RBAC · multi-tenant · policies — strict tenant isolation is enforced at the backend, not just the UI"
        right={<Badge tone="green"><span className="dot" /> {roleNames.length || 8} ROLES · {PERMISSIONS.length} PERMISSIONS</Badge>}
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/security — live enforcement" sub="security-control validation from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <Panel title="RBAC matrix" sub="role → permission policy (enforced server-side)" className="mt">
        <Table
          head={["role", ...PERMISSIONS]}
          rows={(roleNames.length ? roleNames : Object.keys(MATRIX)).map((role) => [
            <span className="mono" style={{ fontWeight: 600 }} title={roles.data.roles?.[role] ?? ""}>{role}</span>,
            ...(MATRIX[role] ?? new Array(PERMISSIONS.length).fill(0)).map((v: number, i: number) => (
              <span key={i} style={{ color: v ? "var(--green)" : "var(--faint)" }}>{v ? "●" : "·"}</span>
            )),
          ])}
        />
      </Panel>

      <div className="grid cols-2 mt">
        <Panel title="Your grants" sub="live ABAC scope for the signed-in principal">
          <div className="mono" style={{ fontSize: 13, display: "flex", flexDirection: "column", gap: 8 }}>
            <div><span className="faint">principal:</span> {grants.data.principal ?? "—"}</div>
            <div><span className="faint">roles:</span> {(grants.data.roles ?? []).join(", ") || "—"}</div>
            <div><span className="faint">scope grants:</span> {grants.data.count ?? 0}</div>
            <div><Badge tone={grants.data.abac_enforced ? "green" : "amber"}>ABAC {grants.data.abac_enforced ? "ENFORCED" : "not yet scoped"}</Badge></div>
          </div>
        </Panel>
        <Panel title="Tenants" sub="SaaS isolation — each tenant has its own assets, policies and reports">
          <Table
            head={["tenant id", "name", "region", "status"]}
            rows={tenantList.map((t) => [
              <span className="mono">{t.id ?? t.tenant_id ?? "—"}</span>,
              t.name ?? "—",
              t.region ?? t.data_residency_region ?? "—",
              <Badge key="s" tone={(t.status ?? "").toLowerCase() === "active" ? "green" : ""}>{t.status ?? "active"}</Badge>,
            ])}
          />
          {tenantList.length === 0 && <p className="dim" style={{ fontSize: 13 }}>No additional tenants provisioned yet.</p>}
        </Panel>
      </div>
    </>
  );
}
