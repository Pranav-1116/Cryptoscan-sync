import React, { useEffect, useState } from "react";
import { Badge, Panel, PageHead } from "../components/ui.jsx";
import CryptoLogAlerts from "./CryptoLogAlerts.js";
import CryptoLogIntegrity from "./CryptoLogIntegrity.js";
import {
  apiCryptologCorrections, apiCryptologEvent, apiCryptologEvents,
  type ApiResult, type CryptologCorrection, type CryptologEventPage,
  type CryptologEventRow,
} from "../lib/api.js";

/* CryptoLog workspace (docs/cryptolog/01_PRODUCT_SPEC.md, Phase 6):
   Event Explorer + Event Details. Investigation and event evidence are the
   primary experience — no assistant panel. Reads are server-side (the
   filters travel as query parameters, never a page-local filter), and every
   count on screen is a count the server reported: a truncated page reads
   "X loaded · more available", never an invented total. */

const CATEGORIES = [
  "CRYPTO_OPERATION", "ALGORITHM", "KEY_LIFECYCLE", "CERTIFICATE", "TLS",
  "SSH", "IPSEC_VPN", "HSM_KMS", "CRYPTO_LIBRARY", "CONFIGURATION",
  "CRYPTO_DRIFT", "GOVERNANCE",
];
const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const INVESTIGATION_STATES = [
  "OBSERVED", "CHANGE_OBSERVED", "PENDING_VALIDATION", "INVESTIGATION_REQUIRED",
];
const PAGE_SIZE = 25;

const CONTROL_STYLE: React.CSSProperties = {
  background: "transparent", color: "inherit", border: "1px solid var(--rule)",
  borderRadius: 6, padding: "5px 8px", fontSize: 12, fontFamily: "var(--mono)",
};

function readIds(value: unknown, key: string): string[] {
  const record = value as Record<string, unknown> | null | undefined;
  const list = record?.[key];
  return Array.isArray(list) ? list.filter((v): v is string => typeof v === "string" && v.trim().length > 0) : [];
}

function ctxEntries(value: unknown): Array<[string, string]> {
  return Object.entries((value ?? {}) as Record<string, unknown>)
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => [k, typeof v === "object" ? JSON.stringify(v) : String(v)] as [string, string]);
}

function observedAt(event: CryptologEventRow): string {
  const obs = event.observation as Record<string, unknown> | undefined;
  const at = obs?.observed_at;
  return typeof at === "string" && at ? at : "Not supplied";
}

export default function CryptoLog() {
  const [view, setView] = useState<"explorer" | "alerts" | "integrity">("explorer");
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [query, setQuery] = useState({ category: "", severity: "", status: "" });
  const [session, setSession] = useState(0);

  const [events, setEvents] = useState<CryptologEventRow[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadedCount, setLoadedCount] = useState(0);
  const [source, setSource] = useState<string>("");
  const [failure, setFailure] = useState<string | null>(null);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CryptologEventRow | null>(null);
  const [corrections, setCorrections] = useState<CryptologCorrection[]>([]);
  const [detailFailure, setDetailFailure] = useState<string | null>(null);

  const describe = (result: ApiResult<unknown>, subject: string) => {
    const status = result.error?.match(/HTTP (\d{3})/)?.[1];
    if (status === "401") return `Authentication required to ${subject}. Sign in and try again.`;
    if (status === "403") return `Access denied to ${subject} for this account or tenant.`;
    return status ? `Unable to ${subject} (HTTP ${status}).` : `Unable to ${subject}; the service is offline or unreachable.`;
  };

  useEffect(() => {
    let alive = true;
    setFailure(null);
    apiCryptologEvents({
      category: query.category || undefined,
      severity: query.severity || undefined,
      investigation_status: query.status || undefined,
      limit: PAGE_SIZE,
    }).then((result) => {
      if (!alive) return;
      setSource(result.source);
      if (!result.data) {
        setEvents([]);
        setNextCursor(null);
        setLoadedCount(0);
        setFailure(describe(result, "read the CryptoLog event store"));
        return;
      }
      setEvents(result.data.events);
      setNextCursor(result.data.next_cursor);
      setLoadedCount(result.data.returned);
    });
    return () => { alive = false; };
  }, [query, session]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setCorrections([]); setDetailFailure(null); return; }
    let alive = true;
    setDetailFailure(null);
    void Promise.all([
      apiCryptologEvent(selectedId),
      apiCryptologCorrections(selectedId),
    ]).then(([eventResult, correctionsResult]) => {
      if (!alive) return;
      if (!eventResult.data) {
        setDetail(null);
        setDetailFailure(describe(eventResult, "read this event"));
        return;
      }
      setDetail(eventResult.data);
      setCorrections(correctionsResult.data?.corrections ?? []);
    });
    return () => { alive = false; };
  }, [selectedId]);

  const loadMore = () => {
    if (!nextCursor) return;
    apiCryptologEvents({
      category: query.category || undefined,
      severity: query.severity || undefined,
      investigation_status: query.status || undefined,
      limit: PAGE_SIZE, cursor: nextCursor,
    }).then((result) => {
      if (!result.data) {
        setFailure(describe(result, "read the next page of events"));
        return;
      }
      setEvents((rows) => [...rows, ...result.data!.events]);
      setNextCursor(result.data.next_cursor);
      setLoadedCount((count) => count + result.data!.returned);
    });
  };

  const evidenceIds = detail ? readIds(detail.evidence, "evidence_ids") : [];
  const relatedAssets = detail ? readIds(detail.relationships, "related_asset_ids") : [];
  const relationshipEvidence = detail ? readIds(detail.relationships, "relationship_evidence_ids") : [];

  return (
    <div className="page" data-testid="cryptolog-page" style={{ maxWidth: 1280, margin: "0 auto", padding: "10px 0 60px" }}>
      <PageHead
        crumb="estate / cryptolog"
        title="CryptoLog"
        sub="Cryptographic event intelligence: recorded events, their evidence and their provenance — recorded observations, never verdicts"
        right={<Badge tone="violet">{loadedCount} event{loadedCount === 1 ? "" : "s"} loaded</Badge>}
      />

      <div className="row" data-testid="cryptolog-views" style={{ gap: 8, marginBottom: 16 }}>
        {([["explorer", "Event explorer"], ["alerts", "Threat investigation"], ["integrity", "Integrity monitor"]] as const).map(([key, label]) => (
          <button key={key} className="btn" data-testid={`cryptolog-view-${key}`}
            aria-pressed={view === key}
            onClick={() => setView(key)}
            style={view === key ? { background: "var(--ink)", color: "var(--panel)" } : undefined}>
            {label}
          </button>
        ))}
      </div>

      {view === "alerts" ? <CryptoLogAlerts /> : view === "integrity" ? <CryptoLogIntegrity /> : (
      <><Panel title="Event explorer" sub="Filters are server-side: the term travels to the event store, never a page-local filter">
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <select aria-label="category" value={category} onChange={(e) => setCategory(e.target.value)} style={CONTROL_STYLE}>
            <option value="">All categories</option>
            {CATEGORIES.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
          <select aria-label="severity" value={severity} onChange={(e) => setSeverity(e.target.value)} style={CONTROL_STYLE}>
            <option value="">All severities</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <select aria-label="investigation status" value={status} onChange={(e) => setStatus(e.target.value)} style={CONTROL_STYLE}>
            <option value="">All investigation states</option>
            {INVESTIGATION_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="btn" data-testid="apply-filters"
            onClick={() => setQuery({ category, severity, status })}>Apply filters</button>
          <button className="btn" onClick={() => {
            setCategory(""); setSeverity(""); setStatus("");
            setQuery({ category: "", severity: "", status: "" });
          }}>Reset</button>
        </div>

        {failure ? (
          <div className="dim" data-testid="cryptolog-failure" style={{ marginTop: 12 }}>
            {failure} A source that could not be read is not a source with no events.
          </div>
        ) : events.length === 0 ? (
          <div className="dim" data-testid="cryptolog-empty" style={{ marginTop: 12 }}>
            No events were returned for this filter. This screen never invents events.
          </div>
        ) : (
          <div data-testid="cryptolog-rows" style={{ marginTop: 12, display: "grid", gap: 6 }}>
            {events.map((event) => (
              <button key={event.event_id} data-testid="cryptolog-row"
                onClick={() => setSelectedId(event.event_id)}
                style={{
                  textAlign: "left", background: selectedId === event.event_id
                    ? "color-mix(in srgb, var(--violet) 12%, transparent)" : "transparent",
                  border: "1px solid var(--rule)", borderRadius: 6,
                  padding: "8px 10px", cursor: "pointer", color: "inherit",
                }}>
                <span className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                  <Badge tone={event.severity === "HIGH" || event.severity === "CRITICAL" ? "red" : "violet"}>
                    {event.severity}
                  </Badge>
                  <strong style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{event.event_type}</strong>
                  <span className="dim" style={{ fontSize: 11 }}>{event.category} · {event.asset_id} · {observedAt(event)}</span>
                  <span className="dim" style={{ fontSize: 11 }}>
                    {readIds(event.evidence, "evidence_ids").length} evidence record{readIds(event.evidence, "evidence_ids").length === 1 ? "" : "s"}
                  </span>
                </span>
              </button>
            ))}
            <div className="dim" data-testid="cryptolog-loaded-line" style={{ fontSize: 11 }}>
              {loadedCount} event{loadedCount === 1 ? "" : "s"} loaded{nextCursor ? " · more available" : " · end of results"}
            </div>
            {nextCursor ? (
              <button className="btn" data-testid="cryptolog-load-more" onClick={loadMore}>Load more</button>
            ) : null}
          </div>
        )}
      </Panel>

      {detailFailure ? (
        <Panel title="Event details"><div className="dim" data-testid="detail-failure">{detailFailure}</div></Panel>
      ) : detail ? (
        <Panel title="Event details" sub="Five views: metadata, cryptographic parameters, evidence and provenance, Digital Twin relationships, assessment context">
          <div data-testid="detail-metadata" style={{ display: "grid", gap: 4, fontSize: 12, fontFamily: "var(--mono)" }}>
            <div>{detail.event_id} · {detail.event_type} · {detail.category} · {detail.logging_kind}</div>
            <div>severity {detail.severity} · {detail.investigation_status} · telemetry {detail.telemetry_mode ?? "EVENT"}</div>
            <div>asset {detail.asset_id}{detail.business_system_id ? ` · business system ${detail.business_system_id}` : ""}</div>
          </div>

          <div data-testid="detail-parameters" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Cryptographic parameters</div>
            {ctxEntries(detail.cryptographic_context).length + ctxEntries(detail.attributes).length === 0 ? (
              <div className="dim" style={{ fontSize: 12 }}>No cryptographic parameters recorded on this event.</div>
            ) : (
              <div style={{ display: "grid", gap: 2, fontSize: 12, fontFamily: "var(--mono)" }}>
                {ctxEntries(detail.cryptographic_context).map(([k, v]) => <div key={`ctx-${k}`}>{k}: {v}</div>)}
                {ctxEntries(detail.attributes).map(([k, v]) => <div key={`attr-${k}`}>{k}: {v}</div>)}
              </div>
            )}
          </div>

          <div data-testid="detail-evidence" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Original evidence and provenance</div>
            <div style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
              evidence: {evidenceIds.length ? evidenceIds.join(", ") : "none recorded"}
              {" · "}integrity: {String((detail.evidence as Record<string, unknown>)?.integrity_status ?? "UNVERIFIED")}
              {" · "}signature: {String((detail.evidence as Record<string, unknown>)?.signature_status ?? "UNKNOWN")}
            </div>
            <div className="dim" style={{ fontSize: 12 }}>
              collector: {String((detail.source as Record<string, unknown>)?.collector_id ?? "Not supplied")}
              {" · "}source: {String((detail.source as Record<string, unknown>)?.source_type ?? "Not supplied")}
            </div>
          </div>

          <div data-testid="detail-relationships" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Digital Twin relationships</div>
            {relatedAssets.length === 0 ? (
              <div className="dim" style={{ fontSize: 12 }}>No relationships recorded on this event.</div>
            ) : (
              <div style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                {relatedAssets.join(", ")}
                <div className="dim">relationship evidence: {relationshipEvidence.length ? relationshipEvidence.join(", ") : "none recorded"}</div>
              </div>
            )}
          </div>

          <div data-testid="detail-assessment" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Assessment context</div>
            <div className="dim" style={{ fontSize: 12 }}>
              This panel shows the recorded event, not a verdict. Deterministic
              rules (CL-001..CL-015) evaluate recorded events separately and open
              investigations carrying what is proven and what is not — a pattern
              never automatically becomes a confirmed compromise.
            </div>
          </div>

          <div data-testid="detail-corrections" style={{ marginTop: 12 }}>
            <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>Corrections</div>
            {corrections.length === 0 ? (
              <div className="dim" style={{ fontSize: 12 }}>
                No corrections recorded. The original event is preserved byte-identical
                until a correction supersedes it with its own provenance.
              </div>
            ) : (
              <div style={{ display: "grid", gap: 6 }}>
                {corrections.map((correction, index) => (
                  <div key={`${correction.corrects_event_id}-${index}`} style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
                    <div>by {correction.actor} · {correction.reason}</div>
                    <div className="dim">original hash {correction.original_hash}</div>
                    <div className="dim">correction evidence: {correction.evidence_ids.length ? correction.evidence_ids.join(", ") : "none recorded"}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Panel>
      ) : (
        <Panel title="Event details">
          <div className="dim" data-testid="detail-idle">Select an event to inspect its metadata, parameters, evidence, relationships and corrections.</div>
        </Panel>
      )}
      </>)}
    </div>
  );
}
