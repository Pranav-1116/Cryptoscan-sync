import React, { useMemo } from "react";
import { Panel, Badge, Table, PageHead, Kpi } from "../components/ui.jsx";
import { useLive } from "../lib/useLive.js";
import { useApi, LiveBadge } from "../lib/apiUi.jsx";
import { apiSafeScanPolicy } from "../lib/api.js";

/* Security is a live enforcement view: the RBAC permission matrix comes from
   GET /api/v1/auth/roles, the ABAC scope from /api/v1/control/me/grants, and
   the tamper-evident audit chain from /api/v1/auth/audit/verify. The baseline
   HTTP controls are the middleware defaults (security_headers.py). */

interface RolesResp {
  roles: Record<string, string>;
  permission_matrix: Record<string, string[]>;
  my_permissions: string[];
}

interface GrantsResp {
  principal: string;
  roles: string[];
  grants: Array<Record<string, unknown>>;
  count: number;
  abac_enforced: boolean;
}

interface AuditResp {
  status: string;
  checked: number;
  entry_count: number;
  chain_head?: string | null;
  break_at_sequence?: number | null;
  reason?: string | null;
}

const HTTP_CONTROLS: Array<[string, string, string]> = [
  ["Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; object-src 'none'", "blocks injected scripts / framing"],
  ["X-Content-Type-Options", "nosniff", "stops MIME sniffing"],
  ["X-Frame-Options", "DENY", "no clickjacking"],
  ["Referrer-Policy", "no-referrer", "no referrer leakage"],
  ["Permissions-Policy", "camera=(), microphone=(), geolocation=()", "denies browser sensors"],
  ["Strict-Transport-Security", "max-age=63072000; includeSubDomains", "HSTS in production"],
];

export default function Security() {
  const roles = useLive<RolesResp>("/api/v1/auth/roles", { roles: {}, permission_matrix: {}, my_permissions: [] });
  const grants = useLive<GrantsResp>("/api/v1/control/me/grants", { principal: "", roles: [], grants: [], count: 0, abac_enforced: false });
  const audit = useLive<AuditResp>("/api/v1/auth/audit/verify", { status: "UNKNOWN", checked: 0, entry_count: 0 });
  const policy = useApi(apiSafeScanPolicy, []);

  const roleNames = Object.keys(roles.data.roles);
  const matrix = useMemo(() => {
    const pm = roles.data.permission_matrix ?? {};
    // roles -> set of allowed actions (inverse of permission_matrix action->roles)
    const out: Record<string, Set<string>> = {};
    for (const r of roleNames) out[r] = new Set();
    for (const [action, allowed] of Object.entries(pm)) {
      for (const r of allowed) if (out[r]) out[r].add(action);
    }
    return out;
  }, [roles.data.permission_matrix, roleNames]);

  const auditOk = audit.data.status === "OK";
  return (
    <>
      <PageHead
        crumb="platform / security"
        title="Security"
        sub="Role-based access control, tenant isolation, tamper-evident audit and the baseline controls applied to every request"
        right={<LiveBadge source={roles.data.roles && Object.keys(roles.data.roles).length ? "live" : "offline"} label={roles.loading ? "LOADING…" : "LIVE POLICY"} />}
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Kpi k="RBAC roles" v={roleNames.length || 8} tone="violet" />
        <Kpi k="permissions" v={Object.keys(roles.data.permission_matrix ?? {}).length} tone="cyan" />
        <Kpi k="grants (ABAC)" v={grants.data.count} tone={grants.data.abac_enforced ? "green" : "amber"} />
        <Kpi k="audit entries" v={audit.data.entry_count} tone={auditOk ? "green" : "red"} />
      </div>

      <div className="grid cols-2">
        <Panel title="Role → permission matrix" sub="authoritative RBAC policy — enforced server-side, not in the UI">
          {roleNames.length ? (
            <Table
              head={["action", ...roleNames]}
              rows={Object.keys(roles.data.permission_matrix ?? {}).sort().map((action) => [
                <span className="mono" style={{ fontWeight: 600 }}>{action}</span>,
                ...roleNames.map((r) => {
                  const has = matrix[r]?.has(action);
                  return <span key={r} style={{ color: has ? "var(--green)" : "var(--faint)" }}>{has ? "✓" : "·"}</span>;
                }),
              ])}
            />
          ) : (
            <div className="dim" style={{ fontSize: 13 }}>Backend offline — RBAC policy unavailable.</div>
          )}
          {roles.data.my_permissions?.length > 0 && (
            <div className="row" style={{ gap: 6, flexWrap: "wrap", marginTop: 12 }}>
              <span className="dim" style={{ fontSize: 12 }}>Your permissions:</span>
              {roles.data.my_permissions.map((p) => <Badge key={p} tone="cyan">{p}</Badge>)}
            </div>
          )}
        </Panel>

        <Panel title="Tenant isolation (ABAC)" sub="Region→BU→Environment→Asset scope for the signed-in principal">
          <div className="mono-list">
            <Row k="principal" v={<span className="mono">{grants.data.principal || "—"}</span>} />
            <Row k="roles" v={grants.data.roles?.length ? grants.data.roles.join(", ") : "—"} />
            <Row k="enforcement" v={
              grants.data.abac_enforced
                ? <Badge tone="green">enforced ({grants.data.count} grants)</Badge>
                : <Badge tone="amber">no grants / dev</Badge>
            } />
          </div>
          {grants.data.grants?.map((g, i) => (
            <div key={i} className="dim" style={{ fontSize: 12, padding: "4px 0", borderBottom: "1px solid var(--line)" }}>
              {JSON.stringify(g)}
            </div>
          ))}
        </Panel>
      </div>

      <div className="grid cols-2 mt">
        <Panel title="Audit chain integrity" sub="SHA-256 hash chain verification (W57-58) — tamper-evident">
          <div className="mono-list">
            <Row k="status" v={<Badge tone={auditOk ? "green" : "red"}>{audit.data.status}</Badge>} />
            <Row k="entries checked" v={audit.data.checked} />
            <Row k="total entries" v={audit.data.entry_count} />
            {audit.data.chain_head && <Row k="chain head" v={<span className="mono">{audit.data.chain_head}</span>} />}
            {!auditOk && audit.data.reason && <Row k="reason" v={audit.data.reason} />}
          </div>
        </Panel>

        <Panel title="Safe-scan policy" sub="guardrails applied before any active probe (control plane)">
          {policy.source !== "live" && <div className="dim" style={{ fontSize: 13 }}>Backend offline — safe-scan policy unavailable.</div>}
          {policy.data && (
            <div className="mono-list">
              {((policy.data as { policies?: Array<Record<string, unknown>> }).policies ?? []).map((p, i) => (
                <div key={i} className="spread" style={{ fontSize: 13, padding: "5px 0", borderBottom: "1px solid var(--line)" }}>
                  <span className="mono">{String(p.mode ?? "—")}</span>
                  <span className="dim">{String(p.scope_region ?? "—")} · {String(p.environment ?? "—")}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Baseline HTTP controls" sub="applied by the API middleware to every response" className="mt">
        <Table
          head={["header", "value", "purpose"]}
          rows={HTTP_CONTROLS.map(([h, v, p]) => [
            <span className="mono" style={{ fontWeight: 600 }}>{h}</span>,
            <span className="dim" style={{ fontSize: 12 }}>{v}</span>,
            <span className="dim" style={{ fontSize: 12 }}>{p}</span>,
          ])}
        />
      </Panel>
    </>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="spread" style={{ fontSize: 13, padding: "6px 0", borderBottom: "1px solid var(--line)" }}>
      <span className="dim">{k}</span>
      <span style={{ textAlign: "right" }}>{v}</span>
    </div>
  );
}
