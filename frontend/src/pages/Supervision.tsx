import React from "react";
import { Panel, Badge, PageHead, Stat } from "../components/ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import { useRealtimeRefresh } from "../lib/realtime.js";
import {
  apiSupervisorPack, apiGroupRoadmap,
  SupervisorPackEnvelope, GroupRoadmap,
  downloadGroupRoadmap, downloadSupervisorPack,
} from "../lib/api.js";

/* Supervision — the read-only supervisory portal (supervision.read).

   One page a financial supervisor can be pointed at: group posture,
   jurisdiction distribution, DORA register summary, the NIST IR 8547
   migration roadmap and the pack's own declared_limits. Every value is
   served by the supervision.read-gated backend — the page fabricates
   nothing, and a 403 (role not provisioned) reads as an honest notice. */

const BUCKET_TONE: Record<string, string> = {
  immediate: "red",
  "by-2030": "amber",
  "by-2035": "green",
};

const num = (v: unknown): number => (typeof v === "number" ? v : 0);

export default function Supervision() {
  const pack = usePollingApi(apiSupervisorPack, 30000);
  const roadmap = usePollingApi(apiGroupRoadmap, 30000);
  useRealtimeRefresh(pack.run, roadmap.run);

  const env: SupervisorPackEnvelope | null = pack.data ?? null;
  const rm: GroupRoadmap | null = roadmap.data ?? null;
  const denied = pack.error?.includes("403") || roadmap.error?.includes("403");

  const totals = env?.pack.group_totals ?? {};
  const buckets = rm?.summary.instances_by_bucket ?? {};

  return (
    <>
      <PageHead
        crumb="governance"
        title="Supervision"
        sub="read-only supervisory portal — group posture, DORA register, migration roadmap (supervision.read)"
        right={
          <>
            <button onClick={() => void downloadGroupRoadmap().catch(() => undefined)} style={{ padding: "4px 12px" }}>Roadmap (CSV)</button>
            <button onClick={() => void downloadSupervisorPack().catch(() => undefined)} style={{ padding: "4px 12px" }}>Supervisor pack (JSON)</button>
          </>
        }
      />
      {denied && (
        <Panel title="Access" sub="the backend refused this surface" frame>
          <p style={{ margin: 0 }}>
            HTTP 403 — this portal requires the <code>supervision.read</code> permission
            (roles: supervisor, auditor, ciso, superadmin). Access is provisioned per
            institution by the bank's administrators.
          </p>
        </Panel>
      )}

      {env && (
        <Panel
          title={`Supervisory pack — ${env.pack.pack.version}`}
          sub={`generated ${env.pack.pack.generated_for} · registry ${env.registry_count} entities · ${env.unassigned_systems} unassigned systems · from ${env.source}`}
          frame
        >
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
            <Stat label="Legal entities" value={num(totals.entities)} />
            <Stat label="Systems" value={num(totals.systems)} />
            <Stat label="Crypto instances" value={num(totals.crypto_instances)} />
            <Stat label="Weak legacy" value={num(totals.weak_legacy_instances)}
              tone={num(totals.weak_legacy_instances) ? "red" : "green"} />
            <Stat label="Quantum-exposed PKI" value={num(totals.quantum_vulnerable_public_key)}
              tone={num(totals.quantum_vulnerable_public_key) ? "red" : "green"} />
          </div>

          {Object.keys(env.pack.by_jurisdiction).length > 0 && (
            <table style={{ borderCollapse: "collapse", marginBottom: 10, width: "100%" }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Jurisdiction</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Entities</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Systems</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Crypto instances</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Weak legacy</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(env.pack.by_jurisdiction).map(([jur, row]) => (
                  <tr key={jur}>
                    <td style={{ padding: "4px 8px" }}>{jur}</td>
                    <td style={{ textAlign: "right", padding: "4px 8px" }}>{num(row.entities)}</td>
                    <td style={{ textAlign: "right", padding: "4px 8px" }}>{num(row.systems)}</td>
                    <td style={{ textAlign: "right", padding: "4px 8px" }}>{num(row.crypto_instances)}</td>
                    <td style={{ textAlign: "right", padding: "4px 8px" }}>{num(row.weak_legacy_instances)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <Stat label="DORA rows" value={num(env.pack.dora_register_summary.total)} />
            <Stat label="DORA critical" value={num(env.pack.dora_register_summary.critical)}
              tone={num(env.pack.dora_register_summary.critical) ? "amber" : ""} />
            <Stat label="Critical expiring ≤180d" value={num(env.pack.dora_register_summary.critical_expiring_180d)}
              tone={num(env.pack.dora_register_summary.critical_expiring_180d) ? "red" : "green"} />
          </div>
        </Panel>
      )}

      {rm && (
        <Panel title={`Migration roadmap — ${rm.summary.rows} rows`} sub={rm.basis} frame>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
            <Stat label="Purge now (legacy)" value={num(buckets.immediate)}
              tone={num(buckets.immediate) ? "red" : "green"} />
            <Stat label="Deprecated after 2030" value={num(buckets["by-2030"])}
              tone={num(buckets["by-2030"]) ? "amber" : "green"} />
            <Stat label="Disallowed after 2035" value={num(buckets["by-2035"])}
              tone={num(buckets["by-2035"]) ? "amber" : "green"} />
          </div>
          {rm.rows.length > 0 ? (
            <table style={{ borderCollapse: "collapse", width: "100%" }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Entity</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Family</th>
                  <th style={{ textAlign: "right", padding: "4px 8px" }}>Instances</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Bucket</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Deadline</th>
                  <th style={{ textAlign: "left", padding: "4px 8px" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {rm.rows.map((row, i) => (
                  <tr key={`${row.entity_code}-${row.family}-${i}`}>
                    <td style={{ padding: "4px 8px" }}>{row.entity_name || row.entity_code} <span style={{ opacity: 0.55 }}>({row.jurisdiction})</span></td>
                    <td style={{ padding: "4px 8px" }}>{row.family}</td>
                    <td style={{ textAlign: "right", padding: "4px 8px" }}>{row.instances}</td>
                    <td style={{ padding: "4px 8px" }}><Badge tone={BUCKET_TONE[row.bucket] || ""}>{row.bucket}</Badge></td>
                    <td style={{ padding: "4px 8px" }}>{row.deadline}</td>
                    <td style={{ padding: "4px 8px" }}>{row.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p style={{ margin: 0, opacity: 0.7 }}>
              No flagged families — the extract-based inventory currently shows no
              legacy-broken or Shor-vulnerable public-key instances. Absence of a
              family is not proof of absence (see declared limits).
            </p>
          )}
        </Panel>
      )}

      {env && (
        <Panel title="Declared limits" sub="travel with every pack — the honest boundary of this portal" frame>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            {env.pack.declared_limits.map((limit, i) => (
              <li key={i} style={{ marginBottom: 4 }}>{limit}</li>
            ))}
          </ul>
        </Panel>
      )}
    </>
  );
}
