import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code } from "../components/ui.jsx";
import { rbac } from "../data/demo.js";
import { apiSecurity, LiveBadge, ApiResult } from "../lib/api.js";

export default function Admin() {
  const [live, setLive] = useState<ApiResult<Record<string, unknown>> | null>(null);
  const [busy, setBusy] = useState(false);

  const enforce = async () => {
    setBusy(true);
    const res = await apiSecurity({
      action: "validate_scan_request",
      scope: ["10.0.0.0/8", "aws:123456789012"],
      policy: "SAFE",
    });
    setLive(res);
    setBusy(false);
  };

  return (
    <>
      <PageHead
        crumb="operate / administration"
        title="Administration"
        sub="RBAC · multi-tenant · policies · user management — strict tenant isolation is enforced at the backend, not just the UI"
        right={
          <div className="row">
            <Badge tone="green"><span className="dot" /> 9 ROLES · 9 PERMISSIONS</Badge>
            <button className="btn sm" onClick={() => void enforce()} disabled={busy}>
              {busy ? "Enforcing…" : "Validate scan request (live)"}
            </button>
            {live && <LiveBadge source={live.source} label={live.source === "live" ? "LIVE API RESULT" : "BACKEND OFFLINE — DEMO"} />}
          </div>
        }
      />
      {live?.data && (
        <Panel title="POST /api/v1/platform/security — engine response" sub="security-control enforcement from the control plane" className="mt">
          <Code>{JSON.stringify(live.data, null, 2)}</Code>
        </Panel>
      )}
      <Panel title="RBAC matrix" sub="view · scan · configure · export · approve · delete · simulate · manage policies · manage users">
        <Table
          head={["role", ...rbac.permissions]}
          rows={rbac.roles.map((role) => [
            <span className="mono" style={{ fontWeight: 600 }}>{role}</span>,
            ...rbac.matrix[role as keyof typeof rbac.matrix].map((v: number, i: number) => (
              <span key={i} style={{ color: v ? "var(--green)" : "var(--faint)" }}>{v ? "●" : "·"}</span>
            )),
          ])}
        />
      </Panel>
      <Panel title="Tenants" sub="SaaS isolation — each tenant has its own assets, policies, scanners and reports" className="mt">
        <Table
          head={["tenant id", "name", "regions", "assets", "scanners", "status"]}
          rows={rbac.tenants.map((t) => [
            <span className="mono">{t.id}</span>,
            t.name,
            t.region,
            <span className="num">{t.assets.toLocaleString()}</span>,
            <span className="num">{t.scanners}</span>,
            <Badge tone="green">{t.status}</Badge>,
          ])}
        />
      </Panel>
    </>
  );
}
