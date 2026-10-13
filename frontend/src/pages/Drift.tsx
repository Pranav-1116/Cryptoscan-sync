import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Badge } from "../components/ui";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { activeTenantId, tenantFetch } from "../lib/api";

// GET /drift returns persisted, tenant-scoped events; it does not return an
// estate-wide comparison verdict or remediation verification.
type DriftEvent = {
  drift_id: string;
  current_scan_id: string;
  baseline_id: string | null;
  drift_type: string;
  severity: string;
  detected_at: string | null;
  resolution_status: string;
  drift_details: Record<string, unknown> | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolution_notes: string | null;
  remediation_task_ids?: string[];
};
type ScanComparison = { scan_id: string; status: string; scan_end?: string | null; statistics?: { baseline_comparison?: string } | null };
type Family = "all" | "code" | "config" | "keys";
const PAGE_SIZE = 50;
const text = (value: unknown) => typeof value === "string" && value.trim() ? value.trim() : null;
const timestamp = (value: string | null | undefined) => value ? new Date(value).toLocaleString() : "Time not provided";
const requestError = (status: number, subject: string) => status === 401
  ? `Authentication required to ${subject}. Sign in and try again.`
  : status === 403 ? `Access denied to ${subject} for this account or tenant.`
    : `Unable to ${subject} (HTTP ${status}).`;
const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);

function parsePage(body: unknown): { events: DriftEvent[]; total: number } | null {
  if (!isRecord(body) || !Array.isArray(body.events) || !Number.isSafeInteger(body.total_count) || (body.total_count as number) < 0) return null;
  if (!body.events.every((event: unknown) => isRecord(event) && text(event.drift_id))) return null;
  return { events: body.events as DriftEvent[], total: body.total_count as number };
}

function familyOf(event: DriftEvent): Exclude<Family, "all"> {
  if (event.drift_type?.startsWith("KEY_")) return "keys";
  if (event.drift_type?.startsWith("CONFIG_")) return "config";
  return "code";
}

function finding(value: unknown): string {
  if (!isRecord(value)) return "Not supplied by this drift event";
  const parts = [text(value.algorithm), typeof value.key_size === "number" ? `${value.key_size} bits` : null,
    text(value.mode), text(value.file_path), typeof value.line_number === "number" ? `line ${value.line_number}` : null].filter(Boolean);
  return parts.length ? parts.join(" · ") : "Not supplied by this drift event";
}

export default function Drift() {
  const [events, setEvents] = useState<DriftEvent[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [nextPage, setNextPage] = useState<number | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [family, setFamily] = useState<Family>("all");
  const [loading, setLoading] = useState(true);
  const [pageLoading, setPageLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [comparisonError, setComparisonError] = useState<string | null>(null);
  const [fetchedAt, setFetchedAt] = useState<string | null>(null);
  const [scope, setScope] = useState(activeTenantId());
  const [refreshKey, setRefreshKey] = useState(0);
  const [notes, setNotes] = useState("");
  const [action, setAction] = useState<"acknowledge" | "resolve" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionEventId, setActionEventId] = useState<string | null>(null);
  const epoch = useRef(0);
  const paging = useRef(false);
  const acting = useRef(false);

  const selectedEvent = events.find(event => event.drift_id === selectedId) ?? null;
  const visible = events.filter(event => family === "all" || familyOf(event) === family);
  const canLoadMore = nextPage !== null;

  useEffect(() => {
    const reset = () => {
      epoch.current++;
      paging.current = false;
      acting.current = false;
      setScope(activeTenantId());
      setEvents([]);
      setTotal(null);
      setNextPage(null);
      setSelectedId(null);
      setFamily("all");
      setComparison(null);
      setComparisonError(null);
      setFetchedAt(null);
      setError(null);
      setPageError(null);
      setActionError(null);
      setActionSuccess(null);
      setActionEventId(null);
      setNotes("");
      setAction(null);
      setPageLoading(false);
      setLoading(true);
      setRefreshKey(key => key + 1);
    };
    window.addEventListener("zelinx:tenant", reset);
    window.addEventListener("zelinx:auth", reset);
    return () => { window.removeEventListener("zelinx:tenant", reset); window.removeEventListener("zelinx:auth", reset); };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const requestEpoch = epoch.current;
    const current = () => !cancelled && epoch.current === requestEpoch;
    async function loadEvents() {
      try {
        const response = await tenantFetch(`/api/v1/drift?page=1&page_size=${PAGE_SIZE}`, { signal: AbortSignal.timeout(8000) });
        if (!current()) return;
        if (!response.ok) { setError(requestError(response.status, "view drift events")); return; }
        const page = parsePage(await response.json());
        if (!current()) return;
        if (!page || (page.total > 0 && !page.events.length)) { setError("Drift event response is incomplete or invalid."); return; }
        const unique = [...new Map(page.events.map(event => [event.drift_id, event])).values()];
        setEvents(unique);
        setSelectedId(unique[0]?.drift_id ?? null);
        setTotal(page.total);
        setNextPage(page.events.length && page.total > PAGE_SIZE ? 2 : null);
        setFetchedAt(new Date().toISOString());
        if (unique.length !== page.events.length) setPageError("Duplicate event IDs returned; loaded results may be incomplete.");
      } catch {
        if (current()) setError("Drift service is offline or unreachable. Event state is unknown.");
      } finally {
        if (current()) setLoading(false);
      }
    }
    async function loadComparison() {
      // Scan statistics carry the persisted per-scan baseline_comparison value.
      // The latest scan is context only, never an estate-wide all-clear.
      try {
        const response = await tenantFetch("/api/v1/scans?page=1&page_size=1", { signal: AbortSignal.timeout(8000) });
        if (!current()) return;
        if (!response.ok) { setComparisonError(requestError(response.status, "view scan comparison status")); return; }
        const body: unknown = await response.json();
        if (!current()) return;
        if (!isRecord(body) || !Array.isArray(body.scans)) { setComparisonError("Scan comparison response is invalid."); return; }
        const latest: unknown = body.scans[0];
        if (isRecord(latest) && text(latest.scan_id)) setComparison(latest as ScanComparison);
      } catch {
        if (current()) setComparisonError("Scan comparison service is offline or unreachable.");
      }
    }
    void loadEvents();
    void loadComparison();
    return () => { cancelled = true; };
  }, [refreshKey]);

  async function loadMore() {
    if (!nextPage || paging.current) return;
    paging.current = true;
    setPageLoading(true);
    setPageError(null);
    const requestEpoch = epoch.current;
    const pageNumber = nextPage;
    try {
      const response = await tenantFetch(`/api/v1/drift?page=${pageNumber}&page_size=${PAGE_SIZE}`, { signal: AbortSignal.timeout(8000) });
      if (epoch.current !== requestEpoch) return;
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          setEvents([]); setSelectedId(null); setTotal(null); setNextPage(null);
          setError(requestError(response.status, "view drift events"));
        } else setPageError(requestError(response.status, `load page ${pageNumber} of drift events`));
        return;
      }
      const parsed = parsePage(await response.json());
      if (epoch.current !== requestEpoch) return;
      if (!parsed || !parsed.events.length) { setPageError(`Page ${pageNumber} returned no events; results may be incomplete.`); return; }
      const seen = new Set(events.map(event => event.drift_id));
      const added = parsed.events.filter(event => { if (seen.has(event.drift_id)) return false; seen.add(event.drift_id); return true; });
      const count = events.length + added.length;
      setEvents(previous => [...previous, ...added]);
      setTotal(parsed.total);
      setFetchedAt(new Date().toISOString());
      setNextPage(pageNumber * PAGE_SIZE < parsed.total ? pageNumber + 1 : null);
      if (!added.length || (count < parsed.total && pageNumber * PAGE_SIZE >= parsed.total)) setPageError(`Loaded ${count} distinct events of ${parsed.total}; repeated or missing rows may remain.`);
    } catch {
      if (epoch.current === requestEpoch) setPageError(`Drift service is offline or unreachable while loading page ${pageNumber}.`);
    } finally {
      if (epoch.current === requestEpoch) { paging.current = false; setPageLoading(false); }
    }
  }

  async function changeDisposition(kind: "acknowledge" | "resolve") {
    if (!selectedEvent || acting.current || (kind === "resolve" && !notes.trim())) return;
    const id = selectedEvent.drift_id;
    const requestEpoch = epoch.current;
    acting.current = true;
    setAction(kind);
    setActionEventId(id);
    setActionError(null);
    setActionSuccess(null);
    try {
      const response = await tenantFetch(`/api/v1/drift/${encodeURIComponent(id)}/${kind}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: notes.trim() || null }), signal: AbortSignal.timeout(8000),
      });
      if (epoch.current !== requestEpoch) return;
      if (!response.ok) { setActionError(requestError(response.status, `${kind} this drift event`)); return; }
      const updated: unknown = await response.json();
      if (epoch.current !== requestEpoch) return;
      if (!isRecord(updated) || updated.drift_id !== id ||
          (kind === "resolve" ? updated.resolution_status !== "RESOLVED" : updated.resolution_status !== "ACKNOWLEDGED")) {
        setActionError("Disposition response is invalid; refresh the event feed before acting again."); return;
      }
      setEvents(previous => previous.map(event => event.drift_id === id ? updated as DriftEvent : event));
      setNotes("");
      setActionSuccess(kind === "resolve"
        ? "Administratively resolved by the server. Remediation has not been verified."
        : "Acknowledged by the server. This does not resolve or verify remediation.");
    } catch {
      if (epoch.current === requestEpoch) setActionError("Drift service is offline or unreachable. Disposition is unknown; refresh before retrying.");
    } finally {
      if (epoch.current === requestEpoch) { acting.current = false; setAction(null); }
    }
  }

  const comparisonState = text(comparison?.statistics?.baseline_comparison);
  const comparisonLabel: Record<string, string> = {
    NO_APPROVED_BASELINE: "No approved baseline",
    BASELINE_UNAVAILABLE: "Approved baseline unavailable",
    PARTIAL_CONFIG_UNAVAILABLE: "Partial: configuration unavailable",
    COMPARED: "Compared",
  };

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24, flexWrap: "wrap", gap: 16 }}>
        <div>
          <div style={{ fontSize: 12, fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>Persisted Drift Events</div>
          <h1 style={{ fontSize: 26, fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Drift Timeline</h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)" }}>Recorded scan-to-baseline deviations and their administrative dispositions in the current API scope.</p>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <AuthenticatedDownload path="/api/v1/drift?page=1&page_size=50" filename="cryptoscan-drift-first-50.json" className="btn outline" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>Download first 50 events (JSON)</AuthenticatedDownload>
          <Link to="/scanners" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>Open Scanners</Link>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 16 }}>
        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase" }}>Persisted events</div>
          <div style={{ fontSize: 26, fontWeight: 700, margin: "4px 0" }}>{total === null ? "—" : total}</div>
          <div style={{ fontSize: 12, color: "var(--dim)" }}>{total === null ? "Count unavailable" : `Server total · ${events.length} loaded`}</div>
        </div>
        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase" }}>Critical events in loaded pages</div>
          <div style={{ fontSize: 26, fontWeight: 700, color: "var(--red)", margin: "4px 0" }}>{total === null ? "—" : events.filter(event => event.severity === "CRITICAL").length}</div>
          <div style={{ fontSize: 12, color: "var(--dim)" }}>All dispositions; not a count of active violations</div>
        </div>
        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase" }}>Latest scan comparison</div>
          <div style={{ fontSize: 16, fontWeight: 700, margin: "7px 0" }}>{comparisonState ? comparisonLabel[comparisonState] || comparisonState : "Comparison status unavailable"}</div>
          <div style={{ fontSize: 12, color: "var(--dim)" }}>
            {comparisonError || (comparison ? `Scan ${comparison.scan_id} · ${comparison.status} · ended ${timestamp(comparison.scan_end)}` : "No scan status returned; no estate-wide comparison claim.")}
          </div>
        </div>
      </div>
      <p style={{ fontSize: 12, color: "var(--dim)", margin: "0 0 20px" }}>
        Source: GET /api/v1/drift · {scope ? `selected tenant ${scope}` : "server-resolved authorization scope"} · {fetchedAt ? `last page fetched ${timestamp(fetchedAt)}` : "event feed not loaded"}. Comparison, when available, comes from the latest GET /api/v1/scans row's statistics.baseline_comparison; it is per scan, not proof that the estate is clear.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 440px), 1fr))", gap: 24 }}>
        <section className="panel" style={{ padding: 20 }} aria-label="Detected drift stream">
          <h2 style={{ margin: "0 0 4px", fontSize: 16, fontWeight: 600 }}>Detected Drift Stream</h2>
          <p style={{ margin: "0 0 16px", fontSize: 12, color: "var(--dim)" }}>Persisted events, newest first. Filters apply to loaded pages only.</p>
          {error && <p role="alert" style={{ color: "var(--amber)" }}>{error}</p>}
          {loading && <p role="status">Loading drift events…</p>}
          {total !== null && <p style={{ fontSize: 12, color: "var(--dim)" }}>Loaded {events.length} of {total} events</p>}
          <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }} aria-label="Filter loaded drift events">
            {([ ["all", `All loaded (${events.length})`], ["code", "Finding changes"], ["config", "Configuration"], ["keys", "Key inventory"] ] as const).map(([id, label]) => (
              <button key={id} type="button" className={`btn sm ${family === id ? "primary" : "outline"}`} aria-pressed={family === id} onClick={() => setFamily(id)} style={{ fontSize: 11 }}>{label}</button>
            ))}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 10, maxHeight: 560, overflowY: "auto" }}>
            {visible.map(event => <button key={event.drift_id} type="button" onClick={() => { setSelectedId(event.drift_id); setNotes(""); setActionError(null); setActionSuccess(null); }} aria-pressed={selectedId === event.drift_id}
              style={{ textAlign: "left", padding: "12px 14px", background: selectedId === event.drift_id ? "color-mix(in srgb, var(--accent) 8%, transparent)" : "var(--bg-2)", border: `1px solid ${selectedId === event.drift_id ? "var(--cyan)" : "var(--line)"}`, borderRadius: "var(--r)", cursor: "pointer", display: "flex", flexDirection: "column", gap: 6, color: "var(--text)" }}>
              <span style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}><strong>{event.drift_type || event.drift_id}</strong><Badge variant={event.severity === "CRITICAL" ? "danger" : event.severity === "HIGH" ? "warning" : "info"}>{event.severity || "Unknown severity"}</Badge></span>
              <span style={{ fontSize: 12 }}>{text(event.drift_details?.reason) || "Reason not provided"}</span>
              <span style={{ fontSize: 11, color: "var(--dim)" }}>Scan {event.current_scan_id || "not provided"} · {event.resolution_status || "Status unavailable"}</span>
              <span style={{ fontSize: 11, color: "var(--dim)" }}>Detected {timestamp(event.detected_at)}</span>
            </button>)}
            {!loading && !error && total === 0 && <div style={{ textAlign: "center", padding: 40, color: "var(--dim)" }}><strong style={{ color: "var(--text)" }}>No drift events returned</strong><p>The event feed has no recorded events in this API scope. This is not evidence that a baseline was approved or a comparison completed.</p></div>}
            {!loading && !error && total !== null && total > 0 && !visible.length && <p style={{ color: "var(--dim)" }}>No matching events in loaded pages. Other pages may contain matches.</p>}
          </div>
          {pageError && <p role="alert" style={{ color: "var(--amber)" }}>{pageError}</p>}
          {canLoadMore && !error && <button type="button" className="btn sm outline" onClick={() => void loadMore()} disabled={pageLoading} style={{ marginTop: 12 }}>{pageLoading ? "Loading…" : "Load more events"}</button>}
        </section>

        <section className="panel" style={{ padding: 24 }} aria-label="Drift event details">
          <h2 style={{ margin: "0 0 4px", fontSize: 16, fontWeight: 600 }}>Deviation Analysis</h2>
          <p style={{ margin: "0 0 16px", fontSize: 12, color: "var(--dim)" }}>Event details reported by the drift list endpoint; no verification is implied.</p>
          {selectedEvent ? <div style={{ display: "flex", flexDirection: "column", gap: 14, overflowWrap: "anywhere" }}>
            <div style={{ padding: 12, background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}><strong>{selectedEvent.drift_type}</strong><div style={{ fontSize: 12, color: "var(--dim)" }}>Event {selectedEvent.drift_id} · baseline {selectedEvent.baseline_id || "not supplied"}</div></div>
            <div><div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase" }}>Baseline finding (recorded, not independently verified)</div><div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12 }}>{finding(selectedEvent.drift_details?.baseline_finding)}</div></div>
            <div><div style={{ fontSize: 11, color: "var(--dim)", textTransform: "uppercase" }}>Current scan finding</div><div style={{ padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 12 }}>{finding(selectedEvent.drift_details?.current_finding)}</div></div>
            <div style={{ fontSize: 12 }}>Reason: {text(selectedEvent.drift_details?.reason) || "Not supplied by this drift event"}</div>
            <div style={{ fontSize: 12 }}>Disposition: <strong>{selectedEvent.resolution_status || "Unavailable"}</strong>{selectedEvent.resolution_status === "RESOLVED" && " · administrative closure, not remediation VERIFIED"}{selectedEvent.resolution_status === "ACKNOWLEDGED" && " · analyst triage — neither resolves nor verifies remediation"}</div>
            {selectedEvent.acknowledged_at && <div style={{ fontSize: 12 }}>Acknowledged {timestamp(selectedEvent.acknowledged_at)} by {selectedEvent.acknowledged_by || "unknown actor"}</div>}
            {selectedEvent.resolved_at && <div style={{ fontSize: 12 }}>Closed {timestamp(selectedEvent.resolved_at)} by {selectedEvent.resolved_by || "unknown actor"}</div>}
            {selectedEvent.resolution_notes && <div style={{ fontSize: 12, whiteSpace: "pre-wrap" }}>Notes: {selectedEvent.resolution_notes}</div>}
            {!!selectedEvent.remediation_task_ids?.length && <div style={{ fontSize: 12 }}>Created remediation task IDs: {selectedEvent.remediation_task_ids.join(", ")} (verification not provided)</div>}
            {selectedEvent.resolution_status === "OPEN" || selectedEvent.resolution_status === "ACKNOWLEDGED" ? <>
              <label htmlFor="drift-notes" style={{ fontSize: 12 }}>Disposition notes (required for administrative resolution)</label>
              <textarea id="drift-notes" value={notes} onChange={event => setNotes(event.target.value)} rows={3} style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", color: "var(--text)" }} />
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                {selectedEvent.resolution_status === "OPEN" && <button type="button" className="btn sm outline" disabled={!!action} onClick={() => void changeDisposition("acknowledge")}>{action === "acknowledge" ? "Acknowledging…" : "Acknowledge"}</button>}
                <button type="button" className="btn sm outline" disabled={!!action || !notes.trim()} onClick={() => void changeDisposition("resolve")}>{action === "resolve" ? "Resolving…" : "Administratively resolve"}</button>
              </div>
              <p style={{ fontSize: 12, color: "var(--dim)", margin: 0 }}>These actions require server-side auditor or admin authorization. Resolution closes the drift record; it does not verify a fix.</p>
            </> : null}
            {actionEventId === selectedEvent.drift_id && actionError && <p role="alert" style={{ color: "var(--amber)" }}>{actionError}</p>}
            {actionEventId === selectedEvent.drift_id && actionSuccess && <p role="status" style={{ color: "var(--text)" }}>{actionSuccess}</p>}
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <Link to="/what-if" className="btn sm primary" style={{ textDecoration: "none" }}>Open What-if (not event-specific)</Link>
              <Link to="/evidence" className="btn sm outline" style={{ textDecoration: "none" }}>Open Evidence (not linked proof)</Link>
            </div>
          </div> : <div style={{ textAlign: "center", padding: 40, color: "var(--dim)", fontSize: 13 }}>Select a loaded drift event to view its recorded details.</div>}
        </section>
      </div>
    </div>
  );
}
