/* CryptoLog — Retention management (docs/cryptolog/01_PRODUCT_SPEC.md §10):
   policy in the open, plans as projections. A plan performs nothing:
   DELETE_CANDIDATE is its strongest claim, and execution is a separate,
   disposition-gated act — a deletion is never silent. */
import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologRetentionPlan, apiCryptologRetentionPolicy,
  type ApiResult, type CryptologRetentionPlan, type CryptologRetentionPolicy,
} from "../lib/api.js";

const CONTROL_STYLE: React.CSSProperties = {
  padding: "6px 8px", borderRadius: 6, border: "1px solid var(--line)",
  background: "var(--panel)", color: "var(--ink)", fontSize: 12,
};

function describeRetentionRead(result: ApiResult<unknown>, subject: string): string {
  const status = result.error?.match(/HTTP (\d{3})/)?.[1];
  if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
  if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
  return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
}

function actionTone(action: string): "green" | "violet" | "red" | "grey" {
  if (action === "RETAIN") return "green";
  if (action === "ARCHIVE") return "violet";
  if (action === "DELETE_CANDIDATE") return "red";
  return "grey";
}

export default function CryptoLogRetention() {
  const [policy, setPolicy] = useState<CryptologRetentionPolicy | null>(null);
  const [policyFailure, setPolicyFailure] = useState<string | null>(null);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [plan, setPlan] = useState<CryptologRetentionPlan | null>(null);
  const [planFailure, setPlanFailure] = useState<string | null>(null);
  const [working, setWorking] = useState(false);

  useEffect(() => {
    let alive = true;
    apiCryptologRetentionPolicy().then((result) => {
      if (!alive) return;
      if (!result.data) {
        setPolicy(null);
        setPolicyFailure(describeRetentionRead(result, "read the retention policy"));
        return;
      }
      setPolicy(result.data);
    });
    return () => { alive = false; };
  }, []);

  const runPlan = () => {
    setWorking(true);
    setPlanFailure(null);
    setPlan(null);
    apiCryptologRetentionPlan({
      start_occurred: start || undefined,
      end_occurred: end || undefined,
    }).then((result) => {
      setWorking(false);
      if (!result.data) {
        setPlanFailure(describeRetentionRead(result, "build a retention plan"));
        return;
      }
      setPlan(result.data);
    });
  };

  return (
    <div data-testid="cryptolog-retention" style={{ display: "grid", gap: 16 }}>
      <Panel title="Retention policy" sub="Named windows per retention class — and a deletion that always requires a disposition">
        {policyFailure ? (
          <div className="dim" data-testid="retention-policy-failure">
            {policyFailure} A refused read is a named refusal, never a default drawn as a policy.
          </div>
        ) : !policy ? (
          <div className="dim" data-testid="retention-policy-loading">Reading the retention policy…</div>
        ) : (
          <div data-testid="retention-policy" style={{ display: "grid", gap: 4, fontSize: 12 }}>
            <div>activity events: <strong>{policy.activity_retention_days} days</strong></div>
            <div>configuration changes: <strong>{policy.change_retention_days} days</strong></div>
            <div>audit records: <strong>{policy.audit_retention_days} days</strong></div>
            <div>archive after: <strong>{policy.archive_after_days} days</strong></div>
            <div>
              disposition required for deletion:{" "}
              <strong>{policy.require_disposition_ref ? "yes" : "no — this must never read no"}</strong>
            </div>
            <div className="dim" data-testid="retention-policy-note">{policy.note}</div>
          </div>
        )}
      </Panel>

      <Panel title="Retention plan" sub="A projection over recorded events — the plan performs nothing and never presents itself as a production change">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input aria-label="retention start" placeholder="Window start (e.g. 2020-01-01)" value={start}
            onChange={(e) => setStart(e.target.value)} style={CONTROL_STYLE} />
          <input aria-label="retention end" placeholder="Window end (e.g. 2026-12-31)" value={end}
            onChange={(e) => setEnd(e.target.value)} style={CONTROL_STYLE} />
          <button className="btn" data-testid="run-retention-plan" onClick={runPlan} disabled={working}>
            {working ? "Planning…" : "Build retention plan"}
          </button>
          <button className="btn" onClick={() => {
            setStart(""); setEnd(""); setPlan(null); setPlanFailure(null);
          }}>Reset</button>
        </div>

        {planFailure ? (
          <div className="dim" data-testid="retention-plan-failure" style={{ marginTop: 12 }}>
            {planFailure} A refused plan is a named refusal, never an empty plan drawn as a clean estate.
          </div>
        ) : plan ? (
          <div data-testid="retention-plan" style={{ marginTop: 12 }}>
            <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
              <Badge tone="green">retain {plan.counts.RETAIN ?? 0}</Badge>
              <Badge tone="violet">archive {plan.counts.ARCHIVE ?? 0}</Badge>
              <Badge tone="red">delete candidates {plan.counts.DELETE_CANDIDATE ?? 0}</Badge>
            </div>
            {plan.rows.length === 0 ? (
              <div className="dim" data-testid="retention-plan-empty" style={{ marginTop: 8 }}>
                No recorded events in this window — a gap in the record, never a clean estate.
              </div>
            ) : (
              <ol data-testid="retention-plan-rows" style={{ marginTop: 8, paddingLeft: 18, fontSize: 12, display: "grid", gap: 4 }}>
                {plan.rows.map((row) => (
                  <li key={row.event_id}>
                    <Badge tone={actionTone(row.action)}>{row.action}</Badge>{" "}
                    <span style={{ fontFamily: "var(--mono)" }}>{row.event_id}</span>{" "}
                    <span className="dim">({row.retention_class}{row.age_days != null ? `, ${row.age_days} days old` : ""}) — {row.reason}</span>
                  </li>
                ))}
              </ol>
            )}
            <div className="dim" data-testid="retention-plan-not-proven" style={{ marginTop: 8, fontSize: 11 }}>
              {plan.not_proven.join(" · ")}
            </div>
            <div className="dim" style={{ fontSize: 11 }}>{plan.note}</div>
          </div>
        ) : (
          <div className="dim" style={{ marginTop: 12, fontSize: 12 }}>
            No plan built yet. Nothing here executes: a deletion always needs a named disposition.
          </div>
        )}
      </Panel>
    </div>
  );
}
