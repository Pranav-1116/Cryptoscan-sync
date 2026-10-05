import React, { useState } from "react";
import { Panel, Badge, Table, PageHead, Code, Stat } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import {
  apiScopeEnvelope, apiTenantIsolation, apiConnectorCatalog, apiScopeAuthorize,
  ScopeEnvelope, TenantIsolation, ConnectorCatalog,
} from "../lib/api.js";
import { CAPABILITIES_JSON, TIER_DETAIL, TIER_LABEL, tierCounts, type Tier } from "../lib/maturity.js";
import { TierPill } from "../components/Layout.jsx";

/* Scope & Authorization + Multi-Tenant isolation (#2 / #11).

   Shows the tenant's resolved authorization envelope (allowed targets,
   allowed methods, read-only, exclusions, rate limit, maintenance window) and
   the multi-tenant isolation report, plus a live pre-flight authorize check.
   Read-only: every value comes from the backend's authorized scope — nothing
   is fabricated, and an absent org reads as an honest empty state. */

const tone = (ok: boolean) => (ok ? "green" : "red");

export default function Scope() {
  const envelope = usePollingApi(apiScopeEnvelope, 12000);
  const isolation = usePollingApi(apiTenantIsolation, 18000);
  const connectors = usePollingApi(apiConnectorCatalog, 30000);
  useRealtimeRefresh(envelope.run, isolation.run, connectors.run);

  const env: ScopeEnvelope | null = envelope.data ?? null;
  const iso: TenantIsolation | null = isolation.data ?? null;
  const cat: ConnectorCatalog | null = connectors.data ?? null;

  const [target, setTarget] = useState("");
  const [mutating, setMutating] = useState(false);
  const [decision, setDecision] = useState<{ allowed: boolean; reason: string } | null>(null);
  const [checking, setChecking] = useState(false);

  const check = async () => {
    if (!target.trim()) return;
    setChecking(true);
    try {
      const r = await apiScopeAuthorize(target.trim(), undefined, undefined, mutating);
      if (r.source === "live" && r.data) setDecision(r.data.decision);
      else setDecision(null);
    } finally {
      setChecking(false);
    }
  };

  return (
    <>
      <PageHead
        crumb="governance / scope"
        title="Scope & Authorization"
        sub="Customer → Authorized Scope → Allowed Targets → Allowed Methods → Credentials → Scanner · exclusions, maintenance windows, rate limits, read-only"
        right={<>{envelope.source === "live" ? <Badge tone="green"><span className="dot" /> AUTHORIZED SCOPE: LIVE</Badge> : <Badge tone="amber">SCOPE: OFFLINE</Badge>}</>}
      />

      <CapabilityMaturityPanel />

      {!env && envelope.source === "live" && (
        <Panel title="No scope yet" sub="POST /onboarding/organization to create a tenant">
          <div className="dim" style={{ fontSize: 13 }}>
            Create an organization, environments, scope entries and connectors from Onboarding → Discovery to build the authorized scope. Until then the scope is empty (fail-closed).
          </div>
        </Panel>
      )}

      {env && (
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <Panel title="Tenant" frame={false}>
            <div style={{ padding: 8 }}>
              <div className="kicker">{env.org_id ? "organization" : "scope"}</div>
              <div className="stat-value">{env.tenant ?? "—"}</div>
            </div>
          </Panel>
          <Panel title="Read-only" frame={false}>
            <Stat label="mode" value={env.read_only ? "READ-ONLY" : "ACTIVE"} tone={env.read_only ? "green" : "amber"} />
            <div className="dim" style={{ fontSize: 12, marginTop: 4 }}>passive connectors enforce read-only</div>
          </Panel>
          <Panel title="Rate limit" frame={false}>
            <Stat label="calls" value={`${env.rate_limit.max}/${env.rate_limit.window_seconds}s`} />
          </Panel>
          <Panel title="Maintenance window" frame={false}>
            <Stat label="window" value={env.maintenance_window_open ? "OPEN" : "CLOSED"} tone={env.maintenance_window_open ? "green" : "red"} />
          </Panel>
        </div>
      )}

      {env && (
        <div className="row" style={{ gap: 18, alignItems: "flex-start", marginTop: 12 }}>
          <Panel title="Allowed targets" sub="enabled scope entries (fail-closed)" style={{ flex: "1 1 40%" }}>
            <Table
              head={["kind", "target", "enabled"]}
              rows={Object.entries(env.allowed_targets).flatMap(([kind, targets]) =>
                targets.length ? targets.map((t) => [<Badge tone="cyan">{kind}</Badge>, <span className="mono">{t}</span>, <Badge tone="green">in scope</Badge>]) : []
              )}
            />
            {!Object.values(env.allowed_targets).flat().length && <div className="dim" style={{ fontSize: 13, marginTop: 8 }}>No scope entries — the engine denies all targets (fail-closed).</div>}
          </Panel>
          <Panel title="Allowed methods" sub="from configured connectors" style={{ flex: "1 1 40%" }}>
            <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
              {env.allowed_methods.map((m) => <Badge key={m} tone="violet">{m}</Badge>)}
            </div>
            {env.exclusions.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>Exclusions</div>
                <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                  {env.exclusions.map((x) => <Badge key={x} tone="amber">{x}</Badge>)}
                </div>
              </div>
            )}
          </Panel>
        </div>
      )}

      {env && (
        <Panel title="Pre-flight authorize" sub="evaluate a target/method/mutation against the authorized scope" className="mt">
          <div className="toolbar" style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
            <input className="search-input" style={{ flex: "0 0 240px" }} placeholder="target (e.g. 10.9.0.1)" value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === "Enter" && check()} />
            <label className="dim" style={{ fontSize: 13, display: "inline-flex", gap: 5, alignItems: "center" }}>
              <input type="checkbox" checked={mutating} onChange={(e) => setMutating(e.target.checked)} /> mutating
            </label>
            <button className="btn btn-primary" style={{ padding: "5px 14px" }} onClick={check} disabled={checking}>{checking ? "…" : "Authorize"}</button>
            {decision && (
              <Badge tone={tone(decision.allowed)}>{decision.allowed ? "ALLOWED" : `DENIED · ${decision.reason}`}</Badge>
            )}
          </div>
        </Panel>
      )}

      <Panel title="Multi-tenant isolation" sub="Tenant A ─X─ Tenant B — data, evidence, credentials, assets, CBOM, reports, logs" className="mt">
        {iso ? (
          <div className="row" style={{ gap: 18, flexWrap: "wrap" }}>
            <Stat label="Isolation" value={iso.enforced ? "ENFORCED" : "SINGLE TENANT"} tone={iso.enforced ? "green" : "amber"} />
            <Stat label="Tenants" value={iso.tenants.length} />
            <Stat label="Scope entries" value={iso.scope_entry_count} />
            <Stat label="Connectors" value={iso.connector_count} />
            <div className="dim" style={{ fontSize: 13, flexBasis: "100%" }}>
              {iso.enforced ? `Isolation is enforced across ${iso.tenants.length} tenants.` : "Only one tenant exists — isolation is satisfied trivially but the boundary guard is armed for when a second tenant is added. Cross-tenant row access is hidden at the data layer."}
            </div>
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>{isolation.source === "offline" ? "Backend offline — isolation report unavailable." : "No tenant yet — create an organization first."}</div>
        )}
      </Panel>

      <Panel title="Connector framework (SDK)" sub="registered connector implementations + declared catalog" className="mt">
        {cat ? (
          <div className="row" style={{ gap: 16, flexWrap: "wrap" }}>
            <Table
              head={["kind", "method", "mode"]}
              rows={cat.registered.map((c) => [<Badge tone="cyan">{c.kind}</Badge>, <span className="mono">{c.method}</span>, <Badge tone={c.mode === "active" ? "amber" : "green"}>{c.mode}</Badge>])}
            />
            <div style={{ flex: "1 1 40%" }}>
              <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>Catalog kinds</div>
              <div className="row" style={{ gap: 6, flexWrap: "wrap", marginBottom: 12 }}>
                {cat.catalog_kinds.map((k) => <Badge key={k} tone="violet">{k}</Badge>)}
              </div>
              <div className="dim" style={{ fontSize: 12, marginBottom: 6 }}>Catalog methods</div>
              <div className="row" style={{ gap: 6, flexWrap: "wrap" }}>
                {cat.catalog_methods.map((m) => <Badge key={m} tone="cyan">{m}</Badge>)}
              </div>
            </div>
          </div>
        ) : (
          <div className="dim" style={{ fontSize: 13 }}>{connectors.source === "offline" ? "Backend offline — connector catalog unavailable." : "No connectors yet."}</div>
        )}
      </Panel>
    </>
  );
}


/* CapabilityMaturityPanel — which console surfaces are GA / beta / preview.
   The table is generated from shared_models/capability_maturity.py (the same
   one GET /api/v1/platform/capabilities serves), so the console cannot claim
   more than the backend declares. Static by design: it is a product statement,
   not a live metric. */
export function CapabilityMaturityPanel() {
  const counts = tierCounts();
  const tiers: Tier[] = ["ga", "beta", "preview"];
  const rows = Object.entries(CAPABILITIES_JSON as Record<string, Tier>).sort(
    ([a, ta], [b, tb]) => tiers.indexOf(ta) - tiers.indexOf(tb) || a.localeCompare(b),
  );
  return (
    <Panel
      title="Capability maturity"
      sub="Not every surface is equally proven. GA is production-supported; beta and preview are labelled on their pages."
      frame
    >
      <div className="grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", gap: 10, marginBottom: 12 }} data-testid="tier-counts">
        {tiers.map((t) => (
          <div key={t} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <TierPill tier={t} />
            <b style={{ fontSize: 20 }}>{counts[t]}</b>
            <span style={{ fontSize: 11, color: "var(--faint)" }}>{TIER_DETAIL[t]}</span>
          </div>
        ))}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
        {rows.map(([slug, tier]) => (
          <span key={slug} data-tier={tier} title={`${TIER_LABEL[tier]} — ${TIER_DETAIL[tier]}`}
            style={{ display: "inline-flex", alignItems: "center", gap: 6, fontFamily: "var(--mono)", fontSize: 11,
              padding: "3px 8px", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
            /{slug}
            <TierPill tier={tier} />
          </span>
        ))}
      </div>
    </Panel>
  );
}
