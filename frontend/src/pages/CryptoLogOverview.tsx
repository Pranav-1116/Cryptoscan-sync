/* CryptoLog — Overview (docs/cryptolog/01_PRODUCT_SPEC.md §9):
   event volume, critical changes, integrity and collection health, all
   computed server-side over the recorded events. A recorded count is not
   an estate guarantee; a failed read is a named failure, never zeros. */
import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologOverview,
  type ApiResult, type CryptologOverview,
} from "../lib/api.js";

function describeOverviewRead(result: ApiResult<unknown>, subject: string): string {
  const status = result.error?.match(/HTTP (\d{3})/)?.[1];
  if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
  if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
  return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
}

function breakdown(entries: Record<string, number>): string {
  const rows = Object.entries(entries).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return rows.length ? rows.map(([k, v]) => `${k} ${v}`).join(" · ") : "none recorded";
}

export default function CryptoLogOverview() {
  const [data, setData] = useState<CryptologOverview | null>(null);
  const [failure, setFailure] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setFailure(null);
    apiCryptologOverview().then((result) => {
      if (!alive) return;
      if (!result.data) {
        setData(null);
        setFailure(describeOverviewRead(result, "read the CryptoLog overview"));
        return;
      }
      setData(result.data);
    });
    return () => { alive = false; };
  }, []);

  return (
    <div data-testid="cryptolog-overview" style={{ display: "grid", gap: 16 }}>
      {failure ? (
        <Panel title="CryptoLog overview">
          <div className="dim" data-testid="overview-failure">
            {failure} A source that could not be read is not an estate with no events.
          </div>
        </Panel>
      ) : !data ? (
        <Panel title="CryptoLog overview">
          <div className="dim" data-testid="overview-loading">Reading the recorded events…</div>
        </Panel>
      ) : (
        <>
          <Panel title="Event volume" sub="Counts of recorded CryptoLog events — server-computed, window-free">
            <div className="row" data-testid="overview-volume" style={{ gap: 16, flexWrap: "wrap" }}>
              <div>
                <div className="dim" style={{ fontSize: 11 }}>Recorded events</div>
                <strong style={{ fontSize: 22, fontFamily: "var(--mono)" }}>{data.event_total}</strong>
              </div>
              <div>
                <div className="dim" style={{ fontSize: 11 }}>Critical changes (HIGH/CRITICAL configuration change)</div>
                <strong style={{ fontSize: 22, fontFamily: "var(--mono)" }} data-testid="overview-critical">{data.critical_changes}</strong>
              </div>
              <div>
                <div className="dim" style={{ fontSize: 11 }}>Alerts (open / total)</div>
                <strong style={{ fontSize: 22, fontFamily: "var(--mono)" }} data-testid="overview-alerts">{data.alerts_open} / {data.alerts_total}</strong>
              </div>
            </div>
            <div className="dim" data-testid="overview-by-severity" style={{ marginTop: 10, fontSize: 12 }}>
              by severity: {breakdown(data.by_severity)}
            </div>
            <div className="dim" data-testid="overview-by-kind" style={{ marginTop: 4, fontSize: 12 }}>
              by logging kind: {breakdown(data.by_logging_kind)}
            </div>
            <div className="dim" data-testid="overview-note" style={{ marginTop: 10, fontSize: 11 }}>{data.note}</div>
          </Panel>

          <Panel title="Integrity" sub="The ledger's state — VERIFIED is only ever reported after a verified checkpoint">
            <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <Badge tone={data.integrity.state === "CHECKPOINTED" ? "violet" : "grey"}>{data.integrity.state}</Badge>
              <span className="dim" style={{ fontSize: 12 }} data-testid="overview-integrity">
                {data.integrity.checkpoint_count} checkpoint{data.integrity.checkpoint_count === 1 ? "" : "s"} recorded
                {data.integrity.latest_checkpoint_ref ? ` · latest ${data.integrity.latest_checkpoint_ref}` : ""}
              </span>
            </div>
            <div className="dim" style={{ marginTop: 8, fontSize: 12 }}>{data.integrity.note}</div>
          </Panel>

          <Panel title="Collection health" sub="Who is recording what — a missing collector is named, never a clean zero">
            {data.collectors.length === 0 ? (
              <div className="dim" data-testid="overview-collectors-empty">
                No collector has recorded events. That is a collection gap, not a healthy estate.
              </div>
            ) : (
              <div data-testid="overview-collectors" style={{ display: "grid", gap: 6 }}>
                {data.collectors.map((c) => (
                  <div key={c.collector_id} className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap", fontSize: 12 }}>
                    <strong style={{ fontFamily: "var(--mono)" }}>{c.collector_id}</strong>
                    <span className="dim">
                      {c.event_count} event{c.event_count === 1 ? "" : "s"}
                      {" · modes: "}
                      {Object.entries(c.telemetry_modes).map(([m, n]) => `${m} ${n}`).join(" · ") || "none recorded"}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
