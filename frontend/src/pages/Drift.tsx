import React, { useEffect, useRef, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Badge, Panel, Bar, Ring } from "../components/ui";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { activeTenantId, tenantFetch } from "../lib/api";
import { IconCertificate, IconCrypto, IconHardware, IconTarget, IconClock, IconSecurity, IconTrendUp, IconTrendDown, IconInfo, IconWarn, IconSearch } from "../components/icons";

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
  verification_status?: string | null;
  verified_by_scan_id?: string | null;
  verified_at?: string | null;
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

const FAMILY_META: Record<Exclude<Family,"all">, { label: string; color: string; bg: string; icon: string }> = {
  code: { label: "Finding changes", color: "var(--accent)", bg: "color-mix(in srgb, var(--accent) 12%, transparent)", icon: "◈" },
  config: { label: "Configuration", color: "var(--violet)", bg: "color-mix(in srgb, var(--violet) 12%, transparent)", icon: "⬡" },
  keys: { label: "Key inventory", color: "var(--amber)", bg: "color-mix(in srgb, var(--amber) 12%, transparent)", icon: "⬢" },
};

const SEV_TONE: Record<string, { tone: string; dot: string; bar: string }> = {
  CRITICAL: { tone: "red", dot: "var(--red)", bar: "red" },
  HIGH: { tone: "orange", dot: "var(--orange)", bar: "red" },
  MEDIUM: { tone: "amber", dot: "var(--amber)", bar: "amber" },
  LOW: { tone: "green", dot: "var(--green)", bar: "green" },
};

const RESOLUTION_META: Record<string, { label: string; tone: string; desc: string }> = {
  OPEN: { label: "OPEN", tone: "red", desc: "requires triage" },
  ACKNOWLEDGED: { label: "ACKNOWLEDGED", tone: "amber", desc: "triage — not verified" },
  RESOLVED: { label: "RESOLVED", tone: "green", desc: "administrative closure" },
};

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

  // Analytics
  const analytics = useMemo(() => {
    const bySev: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const byFamily: Record<string, number> = { code: 0, config: 0, keys: 0 };
    const byStatus: Record<string, number> = { OPEN: 0, ACKNOWLEDGED: 0, RESOLVED: 0 };
    events.forEach(e => {
      const s = (e.severity || "LOW").toUpperCase();
      if (s in bySev) bySev[s]++; else bySev.LOW++;
      const f = familyOf(e); byFamily[f]++;
      const r = (e.resolution_status || "OPEN").toUpperCase();
      if (r in byStatus) byStatus[r]++; else byStatus.OPEN++;
    });
    const criticalPct = events.length ? bySev.CRITICAL / events.length : 0;
    const openPct = events.length ? byStatus.OPEN / events.length : 0;
    const resolvedPct = events.length ? byStatus.RESOLVED / events.length : 0;
    return { bySev, byFamily, byStatus, criticalPct, openPct, resolvedPct };
  }, [events]);

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

  const criticalCount = analytics.bySev.CRITICAL;
  const openCount = analytics.byStatus.OPEN;
  const resolvedCount = analytics.byStatus.RESOLVED;
  const ringTone = criticalCount ? "red" : openCount ? "amber" : "green";
  const ringPct = total !== null && events.length ? Math.max(0, 1 - (criticalCount / Math.max(1, events.length))) : 0;

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header — visual */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 420px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid var(--accent)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: criticalCount ? "var(--red)" : openCount ? "var(--amber)" : "var(--green)" }} /> PERSISTED DRIFT EVENTS · TENANT-SCOPED
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconCrypto size={18} /></span>
            Cryptographic Drift
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Recorded <b style={{ color: "var(--text)" }}>scan-to-baseline deviations</b> and their administrative dispositions. Every event is <span style={{ color: "var(--accent)" }}>persisted and attributed</span> — not an estate-wide verdict.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>BASELINE ≠ VERDICT</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>DISPOSITION ≠ VERIFIED</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>per-scan comparison</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={ringPct} label={total === null ? "…" : String(total)} sub="events" tone={ringTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>DRIFT POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{criticalCount ? `${criticalCount} critical need triage` : openCount ? `${openCount} open events` : total === 0 ? "No drift recorded" : "All triaged"}</div>
              <div style={{ marginTop: 6 }}><Bar value={total ? 1 - criticalCount / total : 0} tone={ringTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <AuthenticatedDownload path="/api/v1/drift?page=1&page_size=50" filename="cryptoscan-drift-first-50.json" className="btn outline" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>Export 50 events</AuthenticatedDownload>
            <Link to="/scanners" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Open Scanners →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{events.length} loaded · {total ?? "—"} total</span>
          </div>
        </div>
      </div>

      {/* Top 4 metric cards — visual */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconTarget size={12} /> PERSISTED EVENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : total === null ? "—" : total.toLocaleString()}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{events.length} loaded · server total</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{scope ? `tenant ${scope.slice(0, 8)}` : "server scope"}</span><span style={{ color: "var(--accent)" }}>● persisted</span></div>
            <Bar value={total ? Math.min(1, events.length / total) : 0} tone="cyan" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{total !== null && events.length < total ? `${total - events.length} more on server` : "all loaded"}</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${criticalCount ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconWarn size={12} /> CRITICAL DRIFT</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: criticalCount ? "var(--red)" : "var(--green)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : criticalCount}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>All dispositions · loaded pages</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: criticalCount ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid ${criticalCount ? "var(--red)" : "var(--green)"}`, color: criticalCount ? "var(--red)" : "var(--green)" }}>{criticalCount ? <IconTrendUp size={16} /> : <IconSecurity size={16} />}</span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{criticalCount ? `${Math.round(analytics.criticalPct * 100)}% of loaded` : "no critical"}</span><span style={{ color: criticalCount ? "var(--red)" : "var(--green)" }}>{criticalCount ? "triage now" : "clear"}</span></div>
            <Bar value={analytics.criticalPct} tone={criticalCount ? "red" : "green"} />
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${openCount ? "var(--amber)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconClock size={12} /> OPEN DISPOSITIONS</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: openCount ? "var(--amber)" : "var(--green)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : openCount}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{analytics.byStatus.ACKNOWLEDGED} acknowledged</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: openCount ? "color-mix(in srgb, var(--amber) 12%, transparent)" : "color-mix(in srgb, var(--green) 12%, transparent)", border: `1px solid ${openCount ? "var(--amber)" : "var(--green)"}`, color: openCount ? "var(--amber)" : "var(--green)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
              <Badge tone={openCount ? "amber" : "green"}>{openCount} open</Badge>
              <Badge tone="slate">{analytics.byStatus.ACKNOWLEDGED} ack</Badge>
            </div>
            <Bar value={analytics.openPct} tone={openCount ? "amber" : "green"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Requires analyst disposition</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)", background: "color-mix(in srgb, var(--violet) 4%, var(--panel))" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>SCAN COMPARISON</div>
              <div style={{ fontSize: 15, fontWeight: 800, margin: "8px 0 2px", color: comparisonState === "COMPARED" ? "var(--green)" : comparisonState ? "var(--amber)" : "var(--dim)", lineHeight: 1.2 }}>{comparisonState ? comparisonLabel[comparisonState] || comparisonState : "Unavailable"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{comparison ? `${comparison.scan_id.slice(0, 8)} · ${comparison.status}` : comparisonError ? "comparison error" : "no scan returned"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)", color: "var(--violet)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, height: 8, background: "var(--bg-2)", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: comparisonState === "COMPARED" ? "100%" : comparisonState ? "55%" : "12%", height: "100%", background: comparisonState === "COMPARED" ? "var(--green)" : comparisonState ? "var(--amber)" : "var(--line-strong)", opacity: .9 }} />
            </div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{comparison ? `ended ${timestamp(comparison.scan_end)}` : "Per-scan · not estate verdict"}</div>
          </div>
        </div>
      </div>

      {/* Analytics strip — severity + family + resolution */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Drift by severity" sub="loaded pages — not active violations" style={{ padding: "14px 16px" }}>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
            const n = analytics.bySev[sev] ?? 0;
            const pct = events.length ? n / events.length : 0;
            const tone = SEV_TONE[sev]?.bar || "cyan";
            return (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <span style={{ width: 80, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: SEV_TONE[sev]?.dot }} /> {sev}</span>
                <div style={{ flex: 1 }}><Bar value={pct} tone={tone} /></div>
                <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 42, textAlign: "right" }}>{n} · {Math.round(pct * 100)}%</span>
              </div>
            );
          })}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Critical + High = triage priority · source: drift list</div>
        </Panel>

        <Panel title="Drift by family" sub="code · config · keys" style={{ padding: "14px 16px" }}>
          {(["code", "config", "keys"] as const).map((f) => {
            const n = analytics.byFamily[f] ?? 0;
            const pct = events.length ? n / events.length : 0;
            const m = FAMILY_META[f];
            return (
              <div key={f} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <span style={{ width: 110, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", display: "flex", alignItems: "center", gap: 6 }}><span style={{ width: 18, height: 18, borderRadius: 6, display: "grid", placeItems: "center", background: m.bg, border: `1px solid ${m.color}`, color: m.color, fontSize: 9 }}>{m.icon}</span> {m.label}</span>
                <div style={{ flex: 1 }}><Bar value={pct} tone={f === "code" ? "cyan" : f === "config" ? "violet" : "amber"} /></div>
                <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 42, textAlign: "right" }}>{n}</span>
              </div>
            );
          })}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Family from drift_type prefix · KEY_* → keys, CONFIG_* → config</div>
        </Panel>

        <Panel title="Disposition progress" sub="OPEN → ACK → RESOLVED" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: resolvedCount === events.length && events.length ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `2px solid ${resolvedCount === events.length && events.length ? "var(--green)" : resolvedCount ? "var(--amber)" : "var(--red)"}`, display: "grid", placeItems: "center", color: resolvedCount === events.length && events.length ? "var(--green)" : "var(--amber)", fontSize: 18, fontWeight: 800 }}>{events.length ? Math.round(analytics.resolvedPct * 100) : 0}%</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Closure progress</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{resolvedCount} of {events.length} resolved</div>
              <div style={{ fontSize: 10, color: resolvedCount === events.length && events.length ? "var(--green)" : "var(--amber)", marginTop: 2 }}>{resolvedCount === events.length && events.length ? "all closed" : `${openCount} need disposition`}</div>
            </div>
          </div>
          <div style={{ height: 8, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${analytics.openPct * 100}%`, background: "var(--red)" }} title={`${openCount} open`} />
            <div style={{ width: `${events.length ? (analytics.byStatus.ACKNOWLEDGED / events.length) * 100 : 0}%`, background: "var(--amber)" }} title={`${analytics.byStatus.ACKNOWLEDGED} ack`} />
            <div style={{ flex: 1, background: "var(--green)" }} title={`${resolvedCount} resolved`} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>● open</span><span>● acknowledged</span><span>● resolved</span></div>
        </Panel>
      </div>

      <p style={{ fontSize: 11, color: "var(--faint)", margin: "0 0 16px", display: "flex", gap: 8, flexWrap: "wrap" }}>
        <span>Source: persisted drift events</span><span>·</span><span>{scope ? `tenant ${scope.slice(0, 12)}` : "server scope"}</span><span>·</span><span>{fetchedAt ? `last fetch ${timestamp(fetchedAt)}` : "not loaded"}</span>
        <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>GET /drift · GET /scans baseline_comparison</span>
      </p>

      {/* Two-column: stream + deviation analysis */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 440px), 1fr))", gap: 16 }}>
        <section className="panel" style={{ padding: 0, overflow: "hidden" }} aria-label="Detected drift stream">
          <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)", display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 10 }}>
            <div>
              <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> Drift Stream</h2>
              <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Persisted events, newest first · filters apply to loaded pages only</p>
            </div>
            <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
              <Badge tone={visible.length ? "cyan" : "slate"}>{visible.length} shown</Badge>
              <Badge tone="slate">{events.length} loaded</Badge>
            </div>
          </div>
          <div style={{ padding: "12px 14px 8px" }}>
            {error && <p role="alert" style={{ color: "var(--amber)", fontSize: 12 }}>{error}</p>}
            {loading && <p role="status" style={{ fontSize: 12, color: "var(--dim)" }}>Loading drift events…</p>}
            {total !== null && <div style={{ fontSize: 11, color: "var(--faint)", marginBottom: 10, display: "flex", justifyContent: "space-between" }}><span>Loaded {events.length} of {total} events</span><span style={{ fontFamily: "var(--mono)" }}>page {nextPage ? nextPage - 1 : 1}</span></div>}
            <div style={{ display: "flex", gap: 6, marginBottom: 10, flexWrap: "wrap" }} aria-label="Filter loaded drift events">
              {([ ["all", `All (${events.length})`], ["code", `Code ${analytics.byFamily.code}`], ["config", `Config ${analytics.byFamily.config}`], ["keys", `Keys ${analytics.byFamily.keys}`] ] as const).map(([id, label]) => (
                <button key={id} type="button" className={`btn sm ${family === id ? "primary" : "outline"}`} aria-pressed={family === id} onClick={() => setFamily(id)} style={{ fontSize: 11, padding: "5px 10px" }}>{label}</button>
              ))}
            </div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 560, overflowY: "auto", padding: "0 12px 12px" }}>
            {visible.map(event => {
              const sev = SEV_TONE[(event.severity || "").toUpperCase()] || SEV_TONE.LOW;
              const resMeta = RESOLUTION_META[(event.resolution_status || "OPEN").toUpperCase()] || RESOLUTION_META.OPEN;
              const fam = FAMILY_META[familyOf(event)];
              const isSelected = selectedId === event.drift_id;
              return (
                <button key={event.drift_id} type="button" onClick={() => { setSelectedId(event.drift_id); setNotes(""); setActionError(null); setActionSuccess(null); }} aria-pressed={isSelected}
                  style={{ textAlign: "left", padding: 0, overflow: "hidden", background: isSelected ? "color-mix(in srgb, var(--accent) 8%, var(--panel-2))" : "var(--panel-2)", border: `1px solid ${isSelected ? "var(--accent)" : "var(--line)"}`, borderLeft: `2px solid ${sev.dot}`, borderRadius: "var(--r)", cursor: "pointer", display: "flex", flexDirection: "column", color: "var(--text)" }}>
                  <div style={{ padding: "10px 12px 8px", display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                    <span style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0 }}>
                      <span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: fam.bg, border: `1px solid ${fam.color}`, color: fam.color, fontSize: 9, flexShrink: 0 }}>{fam.icon}</span>
                      <strong style={{ fontSize: 12.5, fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{event.drift_type || event.drift_id.slice(0, 12)}</strong>
                    </span>
                    <span style={{ display: "flex", gap: 6, flexShrink: 0 }}>
                      <Badge tone={sev.tone}>{event.severity || "—"}</Badge>
                    </span>
                  </div>
                  <div style={{ padding: "0 12px 6px", fontSize: 11.5, color: "var(--dim)", lineHeight: 1.4, display: "-webkit-box", WebkitLineClamp: 2 as any, WebkitBoxOrient: "vertical" as any, overflow: "hidden" }}>{text(event.drift_details?.reason) || "Reason not provided"}</div>
                  <div style={{ padding: "8px 12px 10px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, flexWrap: "wrap", borderTop: "1px dashed var(--line)", background: "var(--bg-2)" }}>
                    <span style={{ fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)" }}>Scan {event.current_scan_id ? event.current_scan_id.slice(0, 8) : "—"} · {timestamp(event.detected_at).slice(0, 16)}</span>
                    <Badge tone={resMeta.tone}>{resMeta.label}</Badge>
                  </div>
                </button>
              );
            })}
            {!loading && !error && total === 0 && <div style={{ textAlign: "center", padding: 32, color: "var(--dim)", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px dashed var(--line-strong)" }}><div style={{ width: 40, height: 40, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel)", border: "1px solid var(--line)", margin: "0 auto 10px" }}><IconSearch size={16} style={{ color: "var(--faint)" }} /></div><strong style={{ color: "var(--text)" }}>No drift events</strong><p style={{ fontSize: 12, margin: "6px 0 0" }}>No recorded events in this scope. Not evidence of baseline approval or clean comparison.</p></div>}
            {!loading && !error && total !== null && total > 0 && !visible.length && <p style={{ color: "var(--dim)", fontSize: 12, textAlign: "center", padding: 16 }}>No matching events in loaded pages — other pages may contain matches. Try another family filter.</p>}
          </div>
          {pageError && <p role="alert" style={{ color: "var(--amber)", fontSize: 12, padding: "0 14px" }}>{pageError}</p>}
          {canLoadMore && !error && <div style={{ padding: "8px 14px 14px" }}><button type="button" className="btn sm outline" onClick={() => void loadMore()} disabled={pageLoading} style={{ width: "100%" }}>{pageLoading ? "Loading…" : `Load more — ${total !== null ? `${total - events.length} remaining` : "next page"}`}</button></div>}
        </section>

        <section className="panel" style={{ padding: 0, overflow: "hidden" }} aria-label="Drift event details">
          <div style={{ padding: "14px 16px", borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
            <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: selectedEvent ? "var(--accent)" : "var(--line-strong)" }} /> Deviation Analysis</h2>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Event details from drift list · no verification implied</p>
          </div>
          {selectedEvent ? <div style={{ display: "flex", flexDirection: "column", gap: 0, overflowWrap: "anywhere" }}>
            {/* Event header visual */}
            <div style={{ padding: "14px 16px", display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 10, flexWrap: "wrap" }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{ width: 32, height: 32, borderRadius: 10, display: "grid", placeItems: "center", background: (SEV_TONE[(selectedEvent.severity || "").toUpperCase()]?.dot || "var(--line-strong)"), color: "#fff", fontSize: 12 }}>◈</span>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 13, fontFamily: "var(--mono)" }}>{selectedEvent.drift_type}</div>
                  <div style={{ fontSize: 11, color: "var(--faint)", fontFamily: "var(--mono)" }}>{selectedEvent.drift_id.slice(0, 16)} · baseline {selectedEvent.baseline_id ? selectedEvent.baseline_id.slice(0, 8) : "—"}</div>
                </div>
              </div>
              <div style={{ display: "flex", gap: 6 }}>
                <Badge tone={(SEV_TONE[(selectedEvent.severity || "").toUpperCase()]?.tone) || "slate"}>{selectedEvent.severity || "—"}</Badge>
                <Badge tone={(RESOLUTION_META[(selectedEvent.resolution_status || "OPEN").toUpperCase()]?.tone) || "slate"}>{selectedEvent.resolution_status || "—"}</Badge>
              </div>
            </div>

            {/* Baseline vs Current visual diff */}
            <div style={{ padding: "0 16px 14px", display: "grid", gridTemplateColumns: "1fr auto 1fr", gap: 8, alignItems: "stretch" }}>
              <div style={{ padding: "10px 12px", background: "color-mix(in srgb, var(--slate) 8%, var(--panel-2))", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", textTransform: "uppercase", marginBottom: 6 }}>Baseline finding</div>
                <div style={{ fontSize: 12, fontFamily: "var(--mono)", lineHeight: 1.5, color: "var(--dim)" }}>{finding(selectedEvent.drift_details?.baseline_finding)}</div>
                <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>recorded — not independently verified</div>
              </div>
              <div style={{ display: "grid", placeItems: "center", color: "var(--accent)", fontSize: 14, padding: "0 2px" }}>→</div>
              <div style={{ padding: "10px 12px", background: "var(--panel-2)", border: "1px solid var(--line)", borderLeft: `2px solid ${SEV_TONE[(selectedEvent.severity || "").toUpperCase()]?.dot || "var(--accent)"}`, borderRadius: "var(--r)" }}>
                <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", textTransform: "uppercase", marginBottom: 6 }}>Current scan finding</div>
                <div style={{ fontSize: 12, fontFamily: "var(--mono)", lineHeight: 1.5 }}>{finding(selectedEvent.drift_details?.current_finding)}</div>
              </div>
            </div>

            <div style={{ padding: "0 16px", display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={{ padding: "10px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderLeft: "2px solid var(--accent)", borderRadius: "var(--r)", fontSize: 12 }}>
                <span style={{ fontWeight: 700 }}>Reason:</span> {text(selectedEvent.drift_details?.reason) || "Not supplied by this drift event"}
              </div>
              <div style={{ fontSize: 12, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <span>Disposition:</span> <Badge tone={(RESOLUTION_META[(selectedEvent.resolution_status || "OPEN").toUpperCase()]?.tone) || "slate"}>{selectedEvent.resolution_status || "Unavailable"}</Badge>
                <span style={{ color: "var(--dim)", fontSize: 11 }}>{RESOLUTION_META[(selectedEvent.resolution_status || "").toUpperCase()]?.desc || ""}</span>
              </div>
              {selectedEvent.resolution_status === "RESOLVED" && <div style={{ fontSize: 11, color: "var(--faint)" }}>Administrative closure — not remediation VERIFIED</div>}
              {selectedEvent.resolution_status === "ACKNOWLEDGED" && <div style={{ fontSize: 11, color: "var(--faint)" }}>Analyst triage — neither resolves nor verifies remediation</div>}
              {selectedEvent.verification_status === "VERIFIED" && (
                <div style={{ padding: "10px 12px", background: "color-mix(in srgb, var(--green) 10%, transparent)", border: "1px solid var(--green)", borderRadius: "var(--r)", fontSize: 12, color: "var(--green)" }}>✓ Condition verified by rescan {selectedEvent.verified_by_scan_id || "unknown"} at {timestamp(selectedEvent.verified_at)} — gone from evidence.</div>
              )}
              {selectedEvent.verification_status === "CONDITION_PRESENT" && (
                <div style={{ padding: "10px 12px", background: "color-mix(in srgb, var(--red) 10%, transparent)", border: "1px solid var(--red)", borderRadius: "var(--r)", fontSize: 12, color: "var(--red)" }}>CONDITION STILL PRESENT in rescan {selectedEvent.verified_by_scan_id || "unknown"} — closure closed nothing.</div>
              )}
              {selectedEvent.acknowledged_at && <div style={{ fontSize: 11, color: "var(--dim)" }}>Acknowledged {timestamp(selectedEvent.acknowledged_at)} by {selectedEvent.acknowledged_by || "unknown"}</div>}
              {selectedEvent.resolved_at && <div style={{ fontSize: 11, color: "var(--dim)" }}>Closed {timestamp(selectedEvent.resolved_at)} by {selectedEvent.resolved_by || "unknown"}</div>}
              {selectedEvent.resolution_notes && <div style={{ fontSize: 12, whiteSpace: "pre-wrap", padding: "8px 12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>Notes: {selectedEvent.resolution_notes}</div>}
              {!!selectedEvent.remediation_task_ids?.length && <div style={{ fontSize: 11, color: "var(--dim)" }}>Created remediation tasks: <span style={{ fontFamily: "var(--mono)", color: "var(--text)" }}>{selectedEvent.remediation_task_ids.join(", ")}</span> (verification not provided)</div>}

              {(selectedEvent.resolution_status === "OPEN" || selectedEvent.resolution_status === "ACKNOWLEDGED") ? <>
                <label htmlFor="drift-notes" style={{ fontSize: 11, fontWeight: 600, color: "var(--dim)", letterSpacing: ".06em", textTransform: "uppercase" }}>Disposition notes {selectedEvent.resolution_status === "ACKNOWLEDGED" ? "(required for resolve)" : ""}</label>
                <textarea id="drift-notes" value={notes} onChange={event => setNotes(event.target.value)} rows={3} style={{ width: "100%", boxSizing: "border-box", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", color: "var(--text)", padding: "8px 12px", fontFamily: "var(--sans)", fontSize: 12 }} placeholder="Required for administrative resolution…" />
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {selectedEvent.resolution_status === "OPEN" && <button type="button" className="btn sm outline" disabled={!!action} onClick={() => void changeDisposition("acknowledge")} style={{ fontSize: 12 }}>{action === "acknowledge" ? "Acknowledging…" : "Acknowledge"}</button>}
                  <button type="button" className="btn sm primary" disabled={!!action || !notes.trim()} onClick={() => void changeDisposition("resolve")} style={{ fontSize: 12 }}>{action === "resolve" ? "Resolving…" : "Administratively resolve"}</button>
                </div>
                <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>Requires server-side auditor/admin authorization. Resolution closes the record; it does not verify a fix.</p>
              </> : null}
              {actionEventId === selectedEvent.drift_id && actionError && <p role="alert" style={{ color: "var(--amber)", fontSize: 12, padding: "8px 12px", background: "color-mix(in srgb, var(--amber) 10%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)" }}>{actionError}</p>}
              {actionEventId === selectedEvent.drift_id && actionSuccess && <p role="status" style={{ color: "var(--green)", fontSize: 12, padding: "8px 12px", background: "color-mix(in srgb, var(--green) 10%, transparent)", border: "1px solid var(--green)", borderRadius: "var(--r)" }}>{actionSuccess}</p>}
            </div>

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", padding: "14px 16px", borderTop: "1px solid var(--line)", marginTop: 14, background: "var(--bg-2)" }}>
              <Link to="/what-if" className="btn sm outline" style={{ textDecoration: "none", fontSize: 12 }}>Open What-if →</Link>
              <Link to="/evidence" className="btn sm outline" style={{ textDecoration: "none", fontSize: 12 }}>Open Evidence →</Link>
              <Link to="/remediation" className="btn sm outline" style={{ textDecoration: "none", fontSize: 12 }}>Remediation →</Link>
            </div>
          </div> : <div style={{ textAlign: "center", padding: 40, color: "var(--dim)", fontSize: 13 }}>
            <div style={{ width: 44, height: 44, borderRadius: 12, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", margin: "0 auto 10px" }}><IconSearch size={18} style={{ color: "var(--faint)" }} /></div>
            <div style={{ fontWeight: 600, color: "var(--text)" }}>No event selected</div>
            <div style={{ fontSize: 12, marginTop: 4 }}>Select a drift event from the stream to view baseline vs current, disposition, and verification state.</div>
          </div>}
        </section>
      </div>
    </div>
  );
}
