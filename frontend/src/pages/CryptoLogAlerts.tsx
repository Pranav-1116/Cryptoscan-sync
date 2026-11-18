/* CryptoLog — Threat investigation (docs/cryptolog/01_PRODUCT_SPEC.md §9).
   Alerts with their honest boundary: every alert shows what is proven AND
   what is not proven; severity is named drivers, never one unexplained
   number; the lifecycle history is append-only and displayed as such.
   Failed reads are named failures, never an empty list drawn as a truth. */
import React, { useEffect, useState } from "react";
import { Badge, Panel } from "../components/ui.jsx";
import {
  apiCryptologAlert, apiCryptologAlerts, apiCryptologRules,
  type CryptologRuleCatalogue,
  type ApiResult, type CryptologAlert, type CryptologAlertParams,
} from "../lib/api.js";

const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const STATES = ["OPEN", "ACKNOWLEDGED", "RESOLVED"];
const PAGE_SIZE = 25;

const CONTROL_STYLE: React.CSSProperties = {
  padding: "6px 8px", borderRadius: 6, border: "1px solid var(--line)",
  background: "var(--panel)", color: "var(--ink)", fontSize: 12,
};

export function describeAlertRead(result: ApiResult<unknown>, subject: string): string {
  const status = result.error?.match(/HTTP (\d{3})/)?.[1];
  if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
  if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
  return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
}

export default function CryptoLogAlerts() {
  const [state, setState] = useState("");
  const [severity, setSeverity] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [query, setQuery] = useState({ state: "", severity: "", ruleId: "" });
  const [session, setSession] = useState(0);

  const [rows, setRows] = useState<CryptologAlert[]>([]);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const [rules, setRules] = useState<CryptologRuleCatalogue | null>(null);
  const [rulesFailure, setRulesFailure] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CryptologAlert | null>(null);
  const [detailFailure, setDetailFailure] = useState<string | null>(null);

  const params = (extra: CryptologAlertParams = {}): CryptologAlertParams => ({
    state: query.state || undefined,
    severity: query.severity || undefined,
    rule_id: query.ruleId || undefined,
    limit: PAGE_SIZE,
    ...extra,
  });

  useEffect(() => {
    let alive = true;
    setFailure(null);
    apiCryptologAlerts(params()).then((result) => {
      if (!alive) return;
      if (!result.data) {
        setRows([]);
        setTotalCount(null);
        setNextCursor(null);
        setHasMore(false);
        setFailure(describeAlertRead(result, "read the CryptoLog alert store"));
        return;
      }
      setRows(result.data.rows);
      setTotalCount(result.data.total_count ?? result.data.rows.length);
      setNextCursor(result.data.next_cursor);
      setHasMore(Boolean(result.data.has_more));
    });
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, session]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setDetailFailure(null); return; }
    let alive = true;
    setDetailFailure(null);
    apiCryptologAlert(selectedId).then((result) => {
      if (!alive) return;
      if (!result.data) {
        setDetail(null);
        setDetailFailure(describeAlertRead(result, "read this alert"));
        return;
      }
      setDetail(result.data);
    });
    return () => { alive = false; };
  }, [selectedId]);

  const loadMore = () => {
    if (!nextCursor) return;
    apiCryptologAlerts(params({ cursor: nextCursor })).then((result) => {
      if (!result.data) {
        setFailure(describeAlertRead(result, "read the next page of alerts"));
        return;
      }
      setRows((prev) => [...prev, ...result.data!.rows]);
      setTotalCount(result.data.total_count ?? rows.length + result.data.rows.length);
      setNextCursor(result.data.next_cursor);
      setHasMore(Boolean(result.data.has_more));
    });
  };

  useEffect(() => {
    let alive = true;
    apiCryptologRules().then((result) => {
      if (!alive) return;
      if (!result.data) {
        setRulesFailure(result.error ?? "the rule catalogue did not load");
        return;
      }
      setRules(result.data);
    });
    return () => { alive = false; };
  }, []);

  return (
    <div data-testid="cryptolog-alerts" style={{ display: "grid", gap: 16 }}>
      <Panel title="Event rules & detection" sub="the deterministic detection catalogue — weak algorithms, unexpected provider changes, certificate expiry and more: a rule is a detection, never a verdict">
        {rulesFailure ? (
          <div className="dim" data-testid="rules-failure">
            {rulesFailure} A failed catalogue read is a failure — never zero rules,
            never a clean estate.
          </div>
        ) : !rules ? (
          <div className="dim">Reading the detection catalogue…</div>
        ) : (
          <>
            <div className="dim" data-testid="rules-note" style={{ fontSize: 12, lineHeight: 1.55, marginBottom: 10 }}>
              {rules.note}
            </div>
            <div data-testid="rules-rows" style={{ display: "grid", gap: 6 }}>
              {rules.rules.map((rule) => (
                <div key={rule.rule_id} style={{
                  border: "1px solid var(--rule)", borderRadius: 6, padding: "8px 10px",
                  display: "grid", gap: 4,
                }}>
                  <div className="row" style={{ gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                    <span className="mono" style={{ fontSize: 12 }}>{rule.rule_id}</span>
                    <span style={{ fontSize: 12.5 }}>{rule.detection}</span>
                    <span className="dim" style={{ fontSize: 11, marginLeft: "auto" }}>
                      suggested severity · {rule.suggested_severity}
                    </span>
                  </div>
                  <div className="dim" style={{ fontSize: 11.5, lineHeight: 1.5 }}>
                    investigation: {rule.investigation}
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </Panel>
      <Panel title="Threat investigation" sub="Rule findings with their boundaries: what is proven AND what is not proven — a pattern never automatically becomes a confirmed compromise">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <select aria-label="alert state" value={state} onChange={(e) => setState(e.target.value)} style={CONTROL_STYLE}>
            <option value="">All states</option>
            {STATES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select aria-label="alert severity" value={severity} onChange={(e) => setSeverity(e.target.value)} style={CONTROL_STYLE}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <input aria-label="rule id" placeholder="Rule id (e.g. CL-002)" value={ruleId}
            onChange={(e) => setRuleId(e.target.value)} style={CONTROL_STYLE} />
          <button className="btn" data-testid="apply-alert-filters"
            onClick={() => setQuery({ state, severity, ruleId })}>Apply filters</button>
          <button className="btn" onClick={() => {
            setState(""); setSeverity(""); setRuleId("");
            setQuery({ state: "", severity: "", ruleId: "" });
          }}>Reset</button>
        </div>

        {failure ? (
          <div className="dim" data-testid="alerts-failure" style={{ marginTop: 12 }}>
            {failure} A source that could not be read is not a source with no alerts.
          </div>
        ) : rows.length === 0 ? (
          <div className="dim" data-testid="alerts-empty" style={{ marginTop: 12 }}>
            <span title={"No alerts recorded for this filter. An empty result is an empty result — this screen never invents alerts."}>{"No alerts recorded for this filter."}</span>
          </div>
        ) : (
          <div data-testid="alerts-rows" style={{ marginTop: 12, display: "grid", gap: 6 }}>
            {rows.map((alert) => (
              <button key={alert.alert_id} data-testid="alert-row"
                onClick={() => setSelectedId(alert.alert_id)}
                style={{ textAlign: "left", padding: "8px 10px", borderRadius: 6, border: "1px solid var(--line)", background: selectedId === alert.alert_id ? "var(--panel)" : "transparent", cursor: "pointer" }}>
                <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <strong style={{ fontSize: 13 }}>{alert.title}</strong>
                  <Badge tone={alert.severity === "HIGH" || alert.severity === "CRITICAL" ? "red" : "violet"}>{alert.severity}</Badge>
                  <Badge tone="grey">{alert.state}</Badge>
                  <span className="dim" style={{ fontSize: 11 }}>{alert.rule_id} · {alert.asset_id}</span>
                </div>
              </button>
            ))}
            <div className="dim" data-testid="alerts-loaded-line" style={{ fontSize: 11 }}>
              {rows.length} loaded
              {totalCount !== null ? ` of ${totalCount} recorded` : ""}
              {hasMore ? " · more available" : " · end of results"}
              {hasMore && (
                <button className="btn" data-testid="alerts-load-more" onClick={loadMore} style={{ marginLeft: 8 }}>Load more</button>
              )}
            </div>
          </div>
        )}
      </Panel>

      {detailFailure ? (
        <Panel title="Alert detail"><div className="dim" data-testid="alert-detail-failure">{detailFailure}</div></Panel>
      ) : detail ? (
        <Panel title="Alert detail" sub="Proven and not proven are stated separately; severity is its named drivers, never one unexplained number">
          <div data-testid="alert-detail" style={{ display: "grid", gap: 6, fontSize: 12, fontFamily: "var(--mono)" }}>
            <div>{detail.alert_id} · {detail.rule_id} · {detail.state}</div>
            <div>event: {detail.event_id} · asset: {detail.asset_id} · {detail.occurred_at || "no observation time recorded"}</div>
          </div>

          <div data-testid="alert-proven" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>What is proven</div>
            {detail.what_is_proven.length === 0 ? (
              <div className="dim" style={{ fontSize: 12 }}>Nothing is proven on this alert.</div>
            ) : (
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
                {detail.what_is_proven.map((line, i) => <li key={i}>{line}</li>)}
              </ul>
            )}
          </div>

          <div data-testid="alert-not-proven" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>What is NOT proven</div>
            {detail.what_is_not_proven.length === 0 ? (
              <div className="dim" style={{ fontSize: 12 }}>Nothing recorded.</div>
            ) : (
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
                {detail.what_is_not_proven.map((line, i) => <li key={i}>{line}</li>)}
              </ul>
            )}
          </div>

          <div data-testid="alert-basis" style={{ marginTop: 12, fontSize: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Severity basis</div>
            {(() => {
              const basis = detail.basis ?? {};
              const drivers = (basis.severity_drivers ?? []) as unknown[];
              const explanation = basis.severity_basis as string | undefined;
              if (!explanation && drivers.length === 0) {
                return <div className="dim"><span title={"No severity basis recorded — an unexplained severity is not a severity."}>{"No severity basis recorded"}</span></div>;
              }
              return (
                <div className="dim">
                  {explanation ? <div>{explanation}</div> : null}
                  {drivers.length > 0 ? <div>drivers: {drivers.map((d) => String(d)).join(" · ")}</div> : null}
                </div>
              );
            })()}
          </div>

          <div data-testid="alert-transitions" style={{ marginTop: 12, fontSize: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Lifecycle history (append-only)</div>
            {detail.transitions.length === 0 ? (
              <div className="dim">No lifecycle transitions recorded yet.</div>
            ) : (
              <ol style={{ margin: 0, paddingLeft: 18, display: "grid", gap: 4 }}>
                {detail.transitions.map((t, i) => (
                  <li key={i}>
                    {t.at} · {t.action} by {t.actor}
                    {t.state ? ` → ${t.state}` : ""}
                    {t.resolution ? ` (${t.resolution})` : ""}
                    {t.note ? ` — ${t.note}` : ""}
                  </li>
                ))}
              </ol>
            )}
          </div>
        </Panel>
      ) : null}
    </div>
  );
}
