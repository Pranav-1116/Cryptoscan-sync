import React, { useEffect, useMemo, useState } from "react";
import { Panel, Badge, Table } from "./ui.jsx";
import { usePollingApi, useEstateEvents } from "../lib/apiUi.jsx";
import {
  apiEstatePlan, apiEstateScan, EstatePlan, EstateScanReport, EstateCoverageRow, EstateBom,
  apiEstateBomAnchor, apiEstateBomAnchorVerify, apiEstateDrift, apiEstateRealtime,
  EstateBomAnchor, EstateAnchorVerify, EstateDriftReport, EstateRealtime,
} from "../lib/api.js";

/* EstatePanel — spec 93, and the correction it exists to make visible.

   CryptoScan is ONE evidence-discovery engine, not six scanners. This panel
   runs a single estate-discovery job and shows the six BOMs as projections of
   the same evidence graph (identical projection id), so a reader cannot end up
   comparing six documents that disagree with each other.

   Three things are deliberately loud:

   * coverage is attempted/expected per plane, never "percent of crypto found";
   * a plane that failed is red with its impact statement, never empty-looking;
   * an unrequested plane is "NOT_OBSERVED", not "clean".

   Nothing here infers a relationship or a cipher: if a plane did not run, this
   panel says so instead of drawing a complete-looking estate. */

const BOM_ORDER = ["SBOM", "CBOM", "HBOM", "NBOM", "VBOM", "TECHBOM"];

function coverageTone(status: string): "green" | "amber" | "red" | "slate" {
  if (status === "COMPLETE") return "green";
  if (status === "PARTIAL") return "amber";
  if (status === "FAILED") return "red";
  return "slate";
}

function verdictTone(verdict: string): "green" | "amber" | "red" | "slate" {
  if (verdict === "COMPLETE") return "green";
  if (verdict === "PARTIAL_COVERAGE") return "amber";
  if (verdict === "UNKNOWN" || verdict === "NOT_OBSERVED") return "slate";
  return "amber";
}

function CoverageMatrix({ rows }: { rows: EstateCoverageRow[] }) {
  if (!rows.length) return <div className="dim" style={{ fontSize: 12 }}>no plane reported</div>;
  return (
    <Table
      head={["plane", "expected", "collected", "status", "cannot see"]}
      rows={rows.map((row) => [
        <span className="mono" style={{ fontSize: 11 }}>{row.target}</span>,
        <span className="num" style={{ fontFamily: "var(--mono)" }}>{row.expected}</span>,
        <span className="num" style={{ fontFamily: "var(--mono)" }}>{row.collected}</span>,
        <Badge tone={coverageTone(row.status)}>{row.status}</Badge>,
        <span className="dim" style={{ fontSize: 10.5 }}>
          {row.reason || row.impact || (row.status === "COMPLETE" ? "—" : "NOT_OBSERVED")}
        </span>,
      ])}
    />
  );
}

function BomSwitch({ boms, counts }: { boms: Record<string, EstateBom>; counts: Record<string, number> }) {
  const [selected, setSelected] = useState<string>("CBOM");
  const kinds = useMemo(() => {
    const present = Object.keys(boms);
    return [...BOM_ORDER.filter((kind) => present.includes(kind)), ...present.filter((kind) => !BOM_ORDER.includes(kind))];
  }, [boms]);
  const bom = boms[selected];
  const components = (bom?.components ?? []) as Array<Record<string, unknown>>;
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <span className="dim" style={{ fontSize: 11 }}>projections of one snapshot</span>
        {kinds.map((kind) => (
          <button
            key={kind}
            type="button"
            className={`btn sm ${selected === kind ? "primary" : ""}`}
            onClick={() => setSelected(kind)}
          >
            {kind} · {counts[kind] ?? components.length}
          </button>
        ))}
      </div>
      <div style={{ marginTop: 8, display: "flex", gap: 6, flexWrap: "wrap" }}>
        {components.slice(0, 10).map((component, index) => (
          <Badge key={`${selected}-${index}`} tone="cyan">
            {String(component.name ?? component.bom_ref ?? "component")}
          </Badge>
        ))}
        {!components.length && (
          <span className="dim" style={{ fontSize: 11 }}>
            this projection is empty for the current evidence — an empty BOM is NOT a statement that the estate has no crypto
          </span>
        )}
        {components.length > 10 && <span className="faint" style={{ fontSize: 11 }}>+{components.length - 10} more</span>}
      </div>
    </div>
  );
}

const LIVENESS_TONE: Record<string, string> = {
  LIVE: "green",
  STALE: "red",
  STOPPED: "amber",
  NEVER_STARTED: "slate",
};

const VERDICT_TONE: Record<string, string> = {
  RUNNING: "cyan",
  WAITING: "green",
  DEGRADED: "amber",
  IDLE_NO_SCHEDULES: "amber",
  NOT_RUNNING: "red",
};

function LiveStrip({ live, connected }: { live: EstateRealtime | null; connected: boolean }) {
  if (!live) return <span className="faint" style={{ fontSize: 10.5 }}>realtime status unavailable</span>;
  const liveness = live.daemon.liveness.state;
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginTop: 8 }}>
      <Badge tone={LIVENESS_TONE[liveness] ?? "slate"}>daemon {liveness}</Badge>
      <Badge tone={VERDICT_TONE[live.verdict] ?? "slate"}>{live.verdict}</Badge>
      <Badge tone={connected ? "green" : "slate"}>{connected ? "live events" : "events offline"}</Badge>
      <span className="faint" style={{ fontSize: 10.5 }}>
        {live.schedules.enabled} enabled ·{" "}
        {live.schedules.next_due_at ? `next due ${new Date(live.schedules.next_due_at).toLocaleTimeString()}` : "nothing scheduled"}
        {live.schedules.leases.length ? ` · ${live.schedules.leases.length} run(s) in flight` : ""}
        {live.runs.last_run_age_seconds != null ? ` · last run ${Math.round(live.runs.last_run_age_seconds)}s ago` : ""}
      </span>
      <span className="dim" style={{ fontSize: 10.5 }}>{live.reason}</span>
      {live.next_action && <span className="faint" style={{ fontSize: 10.5 }}>next: {live.next_action}</span>}
    </div>
  );
}

export default function EstatePanel() {
  const plan = usePollingApi(apiEstatePlan, 120000);
  const planDoc = (plan.data ?? null) as EstatePlan | null;
  const live = usePollingApi(apiEstateRealtime, 15000);
  const liveDoc = (live.data ?? null) as EstateRealtime | null;

  const [report, setReport] = useState<EstateScanReport | null>(null);
  const [anchor, setAnchor] = useState<EstateBomAnchor | null>(null);
  const [verification, setVerification] = useState<EstateAnchorVerify | null>(null);
  const [drift, setDrift] = useState<EstateDriftReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [estate, setEstate] = useState("default");

  useEffect(() => {
    setReport(null);
  }, [estate]);

  // Realtime: the stream tells us *when* to re-read the stored state; it is not
  // itself the authority (a reconnecting client must not miss a run).
  const [lastEvent, setLastEvent] = useState<{ type: string; at: string; severity?: string } | null>(null);
  const { connected } = useEstateEvents((type, payload) => {
    setLastEvent({
      type,
      at: String(payload.at ?? new Date().toISOString()),
      severity: payload.severity ? String(payload.severity) : undefined,
    });
    if (type === "estate.run.finished" || type === "estate.change.detected" || type === "estate.run.failed") {
      live.run();
    }
  });

  const run = async () => {
    setBusy(true);
    setError(null);
    const result = await apiEstateScan({ estate, persist: true, include_boms: true });
    if (result.ok && result.data) {
      setReport(result.data as EstateScanReport);
    } else {
      setError(result.error ?? "estate discovery failed");
    }
    setBusy(false);
  };

  const anchorNow = async () => {
    const created = await apiEstateBomAnchor(`${estate} snapshot`);
    if (created.ok && created.data) {
      setAnchor(created.data as EstateBomAnchor);
      const checked = await apiEstateBomAnchorVerify((created.data as EstateBomAnchor).anchor_id);
      setVerification(checked.ok ? (checked.data as EstateAnchorVerify) : null);
    }
  };

  const checkDrift = async () => {
    const result = await apiEstateDrift();
    setDrift(result.ok ? (result.data as EstateDriftReport) : null);
  };

  const coverage = report?.coverage;
  const unknownCount = report ? Number((report.unknown as Record<string, unknown>).unknown_count ?? 0) : 0;

  return (
    <Panel
      title="Unified estate — one discovery, six BOM projections"
      sub="one job reads every plane's stored evidence and joins it into one graph; a failed plane is UNKNOWN with an impact, never an empty estate"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input
          className="input"
          style={{ width: 160, fontSize: 11 }}
          value={estate}
          onChange={(event) => setEstate(event.target.value)}
          aria-label="estate name"
        />
        <button type="button" className="btn sm primary" onClick={run} disabled={busy}>
          {busy ? "discovering…" : "Run estate discovery"}
        </button>
        {planDoc && <Badge tone="slate">{planDoc.planes.length} planes</Badge>}
        {report && <Badge tone={verdictTone(report.verdict)}>{report.verdict}</Badge>}
        {report && <Badge tone="violet">{report.projection_id.slice(0, 12)}</Badge>}
        {report && <Badge tone="cyan">{report.summary.assets} assets</Badge>}
        {report && <Badge tone="slate">{report.summary.evidence} evidence</Badge>}
        {report && <Badge tone="amber">{unknownCount} unknown</Badge>}
        {report?.unknown_workflow && (
          <Badge tone={report.unknown_workflow.open_work ? "amber" : "green"}>
            {report.unknown_workflow.open_work} open
          </Badge>
        )}
      </div>

      <LiveStrip live={liveDoc} connected={connected} />
      {lastEvent && (
        <div className="faint" style={{ fontSize: 10.5, marginTop: 4 }}>
          last event {lastEvent.type}
          {lastEvent.severity ? ` (${lastEvent.severity})` : ""} at {new Date(lastEvent.at).toLocaleTimeString()}
        </div>
      )}

      {error && <div className="dim" style={{ fontSize: 11.5, marginTop: 8, color: "var(--red)" }}>{error}</div>}
      {!report && !error && (
        <div className="dim" style={{ fontSize: 12, marginTop: 10 }}>
          {planDoc
            ? `planes: ${planDoc.enabled.join(" · ")}. Coverage reports attempted targets — it never claims a percentage of the bank's crypto.`
            : "loading the collector plan…"}
        </div>
      )}

      {report && coverage && (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginTop: 12 }}>
            <Badge tone={coverageTone(report.verdict === "COMPLETE" ? "COMPLETE" : "PARTIAL")}>
              coverage {coverage.summary.coverage_percent == null ? "n/a" : `${coverage.summary.coverage_percent}%`}
            </Badge>
            <span className="faint" style={{ fontSize: 10.5 }}>
              {coverage.summary.collected}/{coverage.summary.expected} attempted targets · {coverage.meaning}
            </span>
          </div>

          <CoverageMatrix rows={coverage.targets} />

          {(report.failed_planes.length > 0 || report.partial_planes.length > 0 || report.coverage_gaps.length > 0) && (
            <div style={{ marginTop: 10, display: "flex", flexDirection: "column", gap: 4 }}>
              {report.collectors
                .filter((item) => item.status === "FAILED" || item.status === "PARTIAL")
                .map((item) => (
                  <div key={item.plane} style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
                    <Badge tone={coverageTone(item.status)}>{item.status}</Badge>
                    <span className="dim" style={{ fontSize: 10.5 }}>
                      <span className="mono" style={{ color: "var(--cyan)" }}>{item.plane}</span> · {item.impact ?? item.reason}
                    </span>
                  </div>
                ))}
            </div>
          )}

          {report.unknown_workflow && (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 10 }}>
              {report.unknown_workflow.stages.filter((stage) => stage.count > 0).map((stage) => (
                <Badge
                  key={stage.state}
                  tone={stage.state === "UNKNOWN_UNRESOLVED" ? "red" : stage.state.startsWith("ESTABLISHED") ? "green" : "amber"}
                >
                  {stage.state.replace("ESTABLISHED_", "")} · {stage.count}
                </Badge>
              ))}
            </div>
          )}

          {report.boms && report.bom_counts && <BomSwitch boms={report.boms} counts={report.bom_counts} />}

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 12 }}>
            <button type="button" className="btn sm" onClick={() => void anchorNow()}>Anchor this BOM set</button>
            <button type="button" className="btn sm" onClick={() => void checkDrift()}>Check drift</button>
            {anchor && <Badge tone="violet">{anchor.anchor_id.slice(0, 18)}</Badge>}
            {anchor && <Badge tone="slate">{anchor.external ? "external" : "exportable (not external yet)"}</Badge>}
            {verification && (
              <Badge tone={verification.status === "PROJECTION_INTACT" ? "green" : verification.status === "PROJECTION_CHANGED" ? "amber" : "red"}>
                {verification.status}
              </Badge>
            )}
          </div>

          {drift && (
            <div style={{ marginTop: 10, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
              <Badge tone={drift.verdict === "NO_DRIFT" ? "green" : drift.verdict === "DRIFT" ? "amber" : "slate"}>
                {drift.verdict}
              </Badge>
              {!!drift.changed_boms?.length && <span className="dim" style={{ fontSize: 10.5 }}>changed: {drift.changed_boms.join(" · ")}</span>}
              {!!drift.degraded_planes?.length && (
                <span className="dim" style={{ fontSize: 10.5, color: "var(--amber)" }}>
                  stopped collecting: {drift.degraded_planes.join(" · ")}
                </span>
              )}
              <span className="faint" style={{ fontSize: 10.5 }}>{drift.reason ?? drift.summary ?? drift.meaning}</span>
            </div>
          )}

          <div className="faint" style={{ fontSize: 10.5, marginTop: 10 }}>
            {report.verdict_detail}
          </div>
        </>
      )}
    </Panel>
  );
}
