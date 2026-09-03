import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import {
  apiP2Plugins, apiP2AnomalyFlags, apiP2GovernanceRequests, apiP2LakeBatches,
  apiP2ApiKeys, apiOtMaintenanceWindows, apiSlaPosture, apiCredentialLeases,
  apiAutomationRuns, apiAutomationRules,
  LiveBadge,
} from "../lib/api.js";
import { usePollingApi } from "../lib/apiUi.jsx";

/* P2 enterprise platform — deterministic (no AI/ML):
   - Plugin marketplace: hash-pinned, Ed25519-signed plugins (quarantine on failure)
   - Data lake: append-only hash-chained export batches
   - Anomaly: statistical (z-score / EWMA / rate-of-change / frequency)
   - Governance: rule-based approval policy + migration validation
   All panels read live data from the API. */

function stateTone(state: string): "green" | "red" | "amber" | "cyan" {
  const s = (state || "").toUpperCase();
  if (s === "ENABLED" || s === "AUTO_APPROVED" || s === "APPROVED" || s === "PASS" || s === "SEALED") return "green";
  if (s === "QUARANTINED" || s === "DENIED" || s === "FAIL" || s === "HIGH") return "red";
  if (s === "PENDING" || s === "REQUIRES_APPROVAL" || s === "VERIFIED" || s === "MEDIUM" || s === "OPEN") return "amber";
  return "cyan";
}

export default function PlatformP2() {
  const plugins = usePollingApi(apiP2Plugins, 15000);
  const flags = usePollingApi(apiP2AnomalyFlags, 15000);
  const reqs = usePollingApi(apiP2GovernanceRequests, 15000);
  const lake = usePollingApi(() => apiP2LakeBatches("primary"), 20000);
  const keys = usePollingApi(apiP2ApiKeys, 20000);
  const windows = usePollingApi(apiOtMaintenanceWindows, 20000);
  const sla = usePollingApi(apiSlaPosture, 20000);
  const leases = usePollingApi(apiCredentialLeases, 20000);
  const autoRuns = usePollingApi(apiAutomationRuns, 10000);
  const autoRules = usePollingApi(apiAutomationRules, 30000);

  const pluginRows = (plugins.data ?? []) as Array<Record<string, unknown>>;
  const flagRows = (flags.data ?? []) as Array<Record<string, unknown>>;
  const reqRows = (reqs.data ?? []) as Array<Record<string, unknown>>;
  const batchRows = (lake.data ?? []) as Array<Record<string, unknown>>;
  const keyRows = (keys.data ?? []) as Array<Record<string, unknown>>;
  const windowRows = (windows.data ?? []) as Array<Record<string, unknown>>;
  const leaseRows = (leases.data ?? []) as Array<Record<string, unknown>>;
  const runRows = (autoRuns.data ?? []) as Array<Record<string, unknown>>;
  const ruleRows = (autoRules.data ?? []) as Array<Record<string, unknown>>;
  const slaData = (sla.data ?? null) as Record<string, unknown> | null;

  return (
    <>
      <PageHead
        crumb="platform / P2"
        title="P2 enterprise platform"
        sub="Plugin marketplace, tamper-evident data lake, statistical anomaly detection, rule-based governance — deterministic, no AI"
        right={<><LiveBadge source={plugins.source} /> <Badge tone="cyan">DETERMINISTIC</Badge></>}
      />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        {[
          ["plugins", pluginRows.length, "cyan"],
          ["anomaly flags", flagRows.length, flagRows.length ? "red" : "green"],
          ["open approvals", reqRows.filter((r) => r.status === "PENDING").length, "amber"],
          ["lake batches", batchRows.length, "green"],
        ].map(([k, v, tone]) => (
          <div className="kpi" key={String(k)}>
            <span className="k">{k}</span>
            <span className="v" style={{ color: `var(--${tone})` }}>{String(v)}</span>
          </div>
        ))}
      </div>

      <div className="grid cols-2">
        <Panel title="Plugin marketplace" sub="hash-pinned · Ed25519-signed · fail-closed quarantine">
          <Table
            head={["plugin", "version", "type", "state", "trusted"]}
            rows={pluginRows.slice(0, 12).map((p) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(p.plugin_id)}</span>,
              <span className="num">{String(p.version)}</span>,
              <Badge tone="cyan">{String(p.plugin_type)}</Badge>,
              <Badge tone={stateTone(String(p.state))}>{String(p.state)}</Badge>,
              p.trusted ? <Badge tone="green">signed</Badge> : <span className="muted">—</span>,
            ])}
          />
        </Panel>

        <Panel title="Statistical anomaly flags" sub="z-score · EWMA control · rate-of-change · frequency">
          <Table
            head={["severity", "rule", "metric", "explanation"]}
            rows={flagRows.slice(0, 12).map((f) => [
              <Badge tone={stateTone(String(f.severity))}>{String(f.severity)}</Badge>,
              <span className="mono">{String(f.rule)}</span>,
              <span className="mono">{String(f.metric)}</span>,
              <span className="muted">{String(f.explanation)}</span>,
            ])}
          />
        </Panel>

        <Panel title="Governance approvals" sub="rule-based policy gates + migration validation">
          <Table
            head={["type", "risk", "decision", "status"]}
            rows={reqRows.slice(0, 12).map((r) => [
              <span className="mono">{String(r.request_type)}</span>,
              <Badge tone={stateTone(String(r.risk_level))}>{String(r.risk_level)}</Badge>,
              <span className="mono">{String(r.decision ?? "—")}</span>,
              <Badge tone={stateTone(String(r.status))}>{String(r.status)}</Badge>,
            ])}
          />
        </Panel>

        <Panel title="Data-lake export chain" sub="append-only · hash-chained · tamper-evident">
          <Table
            head={["batch", "records", "batch digest", "chain digest"]}
            rows={batchRows.slice(0, 12).map((b) => [
              <span className="num">#{String(b.batch_id)}</span>,
              <span className="num">{String(b.record_count)}</span>,
              <span className="mono muted">{String(b.batch_digest).slice(0, 12)}…</span>,
              <span className="mono">{String(b.chain_digest).slice(0, 12)}…</span>,
            ])}
          />
        </Panel>

        <Panel title="Machine API keys" sub="scope + method allowlist · per-key rate quota · fail-closed">
          <Table
            head={["name", "scopes", "methods", "rate/min", "requests", "denied", "state"]}
            rows={keyRows.length ? keyRows.slice(0, 12).map((k) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(k.name)}</span>,
              <span className="muted">{(k.scopes as string[] || []).length ? (k.scopes as string[]).join(", ") : "all endpoints"}</span>,
              <span className="mono">{((k.allowed_methods as string[]) || []).join(" ") || "—"}</span>,
              <span className="num">{Number(k.rate_per_minute) ? String(k.rate_per_minute) : "∞"}</span>,
              <span className="num">{String(k.request_count)}</span>,
              <span className="num" style={{ color: Number(k.denied_count) ? "var(--red)" : undefined }}>{String(k.denied_count)}</span>,
              <Badge tone={k.active ? "green" : "red"}>{k.active ? "active" : "disabled"}</Badge>,
            ]) : [[<span className="muted" key="none">No API keys provisioned yet.</span>, "", "", "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Remediation SLA posture" sub="fixed deadline-per-severity · critical-asset window halved · deterministic breach detection">
          {slaData ? (
            <>
              <div className="grid cols-4" style={{ marginBottom: 10 }}>
                {[
                  ["breached", Number(slaData.breached ?? 0), Number(slaData.breached ?? 0) ? "red" : "green"],
                  ["at risk", Number(slaData.at_risk ?? 0), Number(slaData.at_risk ?? 0) ? "amber" : "green"],
                  ["on track", Number(slaData.on_track ?? 0), "green"],
                  ["breach rate", `${Math.round(Number(slaData.breach_rate ?? 0) * 100)}%`, Number(slaData.breach_rate ?? 0) > 0 ? "red" : "green"],
                ].map(([k, v, tone]) => (
                  <div className="kpi" key={String(k)}>
                    <span className="k">{String(k)}</span>
                    <span className="v" style={{ color: `var(--${tone})` }}>{String(v)}</span>
                  </div>
                ))}
              </div>
              <Table
                head={["finding", "severity", "state", "due", "days"]}
                rows={((slaData.items as any[]) || []).slice(0, 8).map((it) => [
                  <span className="mono">{String(it.finding_id).slice(0, 16)}</span>,
                  <Badge tone="cyan">{String(it.severity)}</Badge>,
                  <Badge tone={stateTone(String(it.state))}>{String(it.state)}</Badge>,
                  <span className="num muted">{String(it.due_at).slice(0, 10)}</span>,
                  it.state === "BREACHED"
                    ? <span className="num" style={{ color: "var(--red)" }}>+{String(it.days_overdue)}d late</span>
                    : <span className="num muted">{it.days_remaining != null ? `${String(it.days_remaining)}d left` : "—"}</span>,
                ])}
              />
            </>
          ) : <span className="muted">No SLA posture available.</span>}
        </Panel>

        <Panel title="OT maintenance windows" sub="passive-first · active ops only in approved windows · SIS never probed">
          <Table
            head={["window", "scope", "class", "ticket", "in effect"]}
            rows={windowRows.length ? windowRows.slice(0, 12).map((w) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(w.window_ref)}</span>,
              <span className="muted">{[...(w.device_ids as string[] || []), ...(w.zones as string[] || [])].slice(0, 3).join(", ") || "—"}</span>,
              <Badge tone="cyan">{String(w.allowed_action_class)}</Badge>,
              <span className="mono">{String(w.change_ticket)}</span>,
              <Badge tone={w.in_effect ? "green" : "amber"}>{w.in_effect ? "in effect" : "scheduled/closed"}</Badge>,
            ]) : [[<span className="muted" key="none">No maintenance windows scheduled.</span>, "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Vault credential leases" sub="short-lived · scoped TTL · reference-only (no key material)">
          <Table
            head={["credential", "component", "TTL", "scope", "status"]}
            rows={leaseRows.length ? leaseRows.slice(0, 12).map((l) => [
              <span className="mono" style={{ fontWeight: 600 }}>{String(l.credential_name)}</span>,
              <span className="mono">{String(l.component)}</span>,
              <span className="num">{String(l.ttl_seconds)}s</span>,
              <span className="muted">{String(l.scope ?? "—").slice(0, 28)}</span>,
              <Badge tone={l.status === "ACTIVE" && !l.expired ? "green" : "amber"}>{l.expired ? "expired" : String(l.status)}</Badge>,
            ]) : [[<span className="muted" key="none">No credential leases issued.</span>, "", "", "", ""]]}
          />
        </Panel>

        <Panel title="Automation runs" sub="event-driven · auto-selected scanners · approval-gated changes">
          {runRows.length ? (
            <Table
              head={["event", "asset", "scanners", "auto → gate", "human"]}
              rows={runRows.slice(0, 12).map((r) => [
                <span className="mono" style={{ fontWeight: 600 }}>{String(r.event_kind)}</span>,
                <span className="mono muted">{String(r.asset_id ?? "—").slice(0, 16)}</span>,
                <span className="num">{(r.scanners as string[] || []).length}</span>,
                <span className="num">{(r.auto_actions as any[] || []).length} → {(r.gated_actions as any[] || []).length}</span>,
                r.needs_human ? <Badge tone="amber">approval</Badge> : <Badge tone="green">auto</Badge>,
              ])}
            />
          ) : <span className="muted">No automation runs yet.</span>}
        </Panel>

        <Panel title="Automation rules" sub="WHEN event · IF conditions · THEN actions (rule builder)">
          {ruleRows.length ? (
            <Table
              head={["rule", "WHEN", "severity", "actions", "enabled"]}
              rows={ruleRows.slice(0, 12).map((r) => [
                <span className="mono" style={{ fontWeight: 600 }}>{String(r.rule_id)}</span>,
                <span className="mono">{String(r.when)}</span>,
                <Badge tone={stateTone(String(r.severity))}>{String(r.severity)}</Badge>,
                <span className="muted">{((r.then as string[]) || []).join(", ")}</span>,
                r.enabled ? <Badge tone="green">on</Badge> : <Badge tone="amber">off</Badge>,
              ])}
            />
          ) : <span className="muted">No custom automation rules — playbooks run by default.</span>}
        </Panel>
      </div>
    </>
  );
}
