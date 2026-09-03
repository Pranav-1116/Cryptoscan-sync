import React from "react";
import { Panel, Badge, Table, PageHead } from "../components/ui.jsx";
import {
  apiP2Plugins, apiP2AnomalyFlags, apiP2GovernanceRequests, apiP2LakeBatches,
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

  const pluginRows = (plugins.data ?? []) as Array<Record<string, unknown>>;
  const flagRows = (flags.data ?? []) as Array<Record<string, unknown>>;
  const reqRows = (reqs.data ?? []) as Array<Record<string, unknown>>;
  const batchRows = (lake.data ?? []) as Array<Record<string, unknown>>;

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
      </div>
    </>
  );
}
