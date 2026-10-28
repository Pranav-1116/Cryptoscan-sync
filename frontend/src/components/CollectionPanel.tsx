import React, { useEffect, useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import type { ApiResult } from "../lib/api.js";
import {
  apiCollectionCollectors, apiCollectionTargets, apiCollectionJobs, apiCollectionJob,
  apiCollectionJobCoverage, apiCollectionJobErrors, apiCollectionJobEvidence,
  apiCollectionJobProjections, apiCollectionEnqueue, apiCollectionCancel,
  apiCollectionAuthorize, apiCollectionRevoke,
  CollectionCollector, CollectionTarget, CollectionJob,
} from "../lib/api.js";

/* CollectionPanel — the operator's view of the collection surface (targets, jobs,
   worker control).

   Before this panel these endpoints existed with no screen: an operator could not
   see which targets were authorised, which jobs existed, or what a job's coverage
   and errors were. Three rules are rendered rather than assumed:

   * **A collector that is not qualified for production says so**, in red, next to
     its own capabilities — an available-looking collector that cannot legally run
     is worse than no collector.
   * **An empty list is "nothing registered"**, never "nothing found": every empty
     state names which of the two it is.
   * **Actions carry the revision they were read at.** The backend rejects a stale
     revision, so the panel shows the revision it is acting on instead of retrying
     behind the operator's back. */

const STATUS_TONE = (state: string): "green" | "amber" | "red" | "slate" => {
  const value = state.toUpperCase();
  if (["AUTHORIZED", "COMPLETE", "COMPLETED", "DONE", "CURRENT"].includes(value)) return "green";
  if (["PENDING", "QUEUED", "IN_PROGRESS", "ENQUEUED", "RUNNING", "DRAFT"].includes(value)) return "amber";
  if (["FAILED", "REVOKED", "CANCELLED", "BLOCKED", "ERROR"].includes(value)) return "red";
  return "slate";
};

function label(item: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = item[key];
    if (typeof value === "string" && value) return value;
    if (typeof value === "number") return String(value);
  }
  return null;
}

export default function CollectionPanel() {
  const [collectors, setCollectors] = useState<CollectionCollector[] | null>(null);
  const [targets, setTargets] = useState<CollectionTarget[] | null>(null);
  const [jobs, setJobs] = useState<CollectionJob[] | null>(null);
  const [job, setJob] = useState<CollectionJob | null>(null);
  const [coverage, setCoverage] = useState<Record<string, unknown> | null>(null);
  const [errors, setErrors] = useState<{ errors: Array<Record<string, unknown>>; asset_absence_proven: boolean } | null>(null);
  const [evidence, setEvidence] = useState<Record<string, unknown> | null>(null);
  const [projections, setProjections] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revokeReason, setRevokeReason] = useState("operator revoke from console");

  const load = async () => {
    setError(null);
    const [c, t, j] = await Promise.all([apiCollectionCollectors(), apiCollectionTargets(), apiCollectionJobs()]);
    if (c.ok) setCollectors((c.data as { collectors: CollectionCollector[] }).collectors);
    if (t.ok) setTargets((t.data as { items: CollectionTarget[] }).items);
    if (j.ok) setJobs((j.data as { items: CollectionJob[] }).items);
    // an unreachable API is not an empty collection estate
    if (!c.ok && !t.ok && !j.ok) setError("collection API is unavailable — this is not 'no targets and no jobs'");
  };

  useEffect(() => {
    void load();
  }, []);

  const openJob = async (id: string) => {
    setBusy(true);
    setError(null);
    setCoverage(null);
    setErrors(null);
    setEvidence(null);
    setProjections(null);
    const [detail, cov, err, ev, proj] = await Promise.all([
      apiCollectionJob(id),
      apiCollectionJobCoverage(id),
      apiCollectionJobErrors(id),
      apiCollectionJobEvidence(id),
      apiCollectionJobProjections(id),
    ]);
    if (detail.ok) setJob(detail.data as CollectionJob);
    if (cov.ok) setCoverage(cov.data as Record<string, unknown>);
    if (err.ok) setErrors(err.data as { errors: Array<Record<string, unknown>>; asset_absence_proven: boolean });
    if (ev.ok) setEvidence(ev.data as Record<string, unknown>);
    if (proj.ok) setProjections(proj.data as Record<string, unknown>);
    if (!detail.ok) setError("job detail unavailable — the job may not exist or the API is down");
    setBusy(false);
  };

  const act = async (action: () => Promise<ApiResult<Record<string, unknown>>>, message: string) => {
    setBusy(true);
    setError(null);
    setNote(null);
    const result = await action();
    if (result.ok === true) {
      setNote(message);
      await load();
      if (job) await openJob(job.id);
    } else {
      setError(result.error ?? "the action was rejected — refresh and check the revision");
    }
    setBusy(false);
  };

  return (
    <Panel
      title="Collection — targets, jobs and worker control"
      sub="what is authorised, what is running, and what a job actually collected; an empty list here is 'nothing registered', never 'nothing found'"
      className="mt"
    >
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <button type="button" className="btn sm" onClick={() => void load()} disabled={busy}>Refresh</button>
        {busy && <span className="faint" style={{ fontSize: 10.5 }}>working…</span>}
        {note && <Badge tone="green">{note}</Badge>}
      </div>
      {error && <div className="dim" style={{ fontSize: 11.5, marginTop: 8, color: "var(--red)" }}>{error}</div>}

      <div style={{ marginTop: 12 }}>
        <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>COLLECTORS</div>
        {collectors === null && <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>loading the collector catalog…</div>}
        {collectors !== null && collectors.length === 0 && (
          <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>no collector is registered in this build — nothing can be collected</div>
        )}
        {collectors?.map((collector) => (
          <div key={collector.id} style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 5 }}>
            <span className="mono" style={{ fontSize: 11 }}>{collector.id}</span>
            <Badge tone={STATUS_TONE(collector.state)}>{collector.state}</Badge>
            <Badge tone={collector.production_execution_qualified ? "green" : "red"}>
              {collector.production_execution_qualified ? "production-qualified" : "NOT production-qualified"}
            </Badge>
            <Badge tone={collector.server_execution ? "green" : "slate"}>
              {collector.server_execution ? "server execution" : "no server execution"}
            </Badge>
            <span className="faint" style={{ fontSize: 9.5 }}>{collector.method}</span>
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18, marginTop: 16 }}>
        <div>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>TARGETS</div>
          {targets !== null && targets.length === 0 && (
            <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>
              no collection target is registered. That is an authorisation gap, not an estate with nothing in it.
            </div>
          )}
          {targets?.map((target) => {
            const revision = Number(target.revision ?? 0);
            const state = label(target, ["state", "status", "authorization_state"]) ?? "UNKNOWN";
            return (
              <div key={target.id} style={{ marginTop: 8, borderTop: "1px solid rgba(255,255,255,0.06)", paddingTop: 6 }}>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                  <span className="mono" style={{ fontSize: 10.5 }}>{target.id.slice(0, 12)}…</span>
                  <Badge tone={STATUS_TONE(state)}>{state}</Badge>
                  {revision > 0 && <Badge tone="slate">rev {revision}</Badge>}
                </div>
                <div className="faint" style={{ fontSize: 10, marginTop: 2 }}>
                  {label(target, ["target_key", "address", "system_id"]) ?? "no key/address recorded"}
                </div>
                <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
                  <button
                    type="button"
                    className="btn sm"
                    style={{ fontSize: 10 }}
                    disabled={busy || revision < 1}
                    onClick={() => void act(() => apiCollectionAuthorize(target.id, revision), "target authorised")}
                  >
                    authorize
                  </button>
                  <button
                    type="button"
                    className="btn sm"
                    style={{ fontSize: 10 }}
                    disabled={busy || revision < 1}
                    onClick={() => void act(() => apiCollectionRevoke(target.id, revision, revokeReason), "target revoked")}
                  >
                    revoke
                  </button>
                </div>
              </div>
            );
          })}
          {targets !== null && targets.length > 0 && (
            <div className="faint" style={{ fontSize: 9.5, marginTop: 8 }}>
              actions carry the revision shown; a stale revision is rejected rather than retried silently.
              registering a new target is an API/CLI flow because a target is an authorisation document, not a form.
            </div>
          )}
        </div>

        <div>
          <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>JOBS</div>
          {jobs !== null && jobs.length === 0 && (
            <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>
              no collection job exists. Nothing has been asked of any collector yet.
            </div>
          )}
          {jobs?.map((item) => {
            const state = label(item, ["state", "status"]) ?? "UNKNOWN";
            return (
              <div key={item.id} style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginTop: 6 }}>
                <button
                  type="button"
                  className="btn sm"
                  style={{ fontSize: 10 }}
                  onClick={() => void openJob(item.id)}
                >
                  {item.id.slice(0, 10)}…
                </button>
                <Badge tone={STATUS_TONE(state)}>{state}</Badge>
                {item.revision != null && <Badge tone="slate">rev {String(item.revision)}</Badge>}
                <span className="faint" style={{ fontSize: 9.5 }}>{String(item.created_at ?? "")}</span>
              </div>
            );
          })}
        </div>
      </div>

      {job && (
        <div style={{ marginTop: 16, borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: 10 }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <span className="mono" style={{ fontSize: 11, color: "var(--cyan)" }}>JOB {job.id.slice(0, 12)}…</span>
            <Badge tone={STATUS_TONE(label(job, ["state", "status"]) ?? "UNKNOWN")}>
              {label(job, ["state", "status"]) ?? "UNKNOWN"}
            </Badge>
            {job.revision != null && <Badge tone="slate">rev {String(job.revision)}</Badge>}
            <button
              type="button"
              className="btn sm"
              style={{ fontSize: 10 }}
              disabled={busy || job.revision == null}
              onClick={() => void act(() => apiCollectionEnqueue(job.id, Number(job.revision)), "job enqueued")}
            >
              enqueue
            </button>
            <button
              type="button"
              className="btn sm"
              style={{ fontSize: 10 }}
              disabled={busy || job.revision == null}
              onClick={() => void act(() => apiCollectionCancel(job.id, Number(job.revision)), "job cancelled")}
            >
              cancel
            </button>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 8 }}>
            <div>
              <div className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>COVERAGE</div>
              {!coverage && <div className="faint" style={{ fontSize: 10 }}>no coverage document returned</div>}
              {coverage && Object.entries(coverage).slice(0, 10).map(([key, value]) => (
                <div key={key} className="faint" style={{ fontSize: 10 }}>
                  <span className="mono">{key}</span>: {typeof value === "object" ? JSON.stringify(value).slice(0, 90) : String(value)}
                </div>
              ))}
              <div className="mono" style={{ fontSize: 10, color: "var(--cyan)", marginTop: 8 }}>ERRORS</div>
              {errors === null && <div className="faint" style={{ fontSize: 10 }}>errors unavailable</div>}
              {errors && errors.errors.length === 0 && (
                <div className="faint" style={{ fontSize: 10 }}>
                  no collection errors recorded — absence of errors is not proof of complete collection
                  {errors.asset_absence_proven ? "" : " (asset absence is explicitly not proven)"}
                </div>
              )}
              {errors?.errors.slice(0, 6).map((entry, index) => (
                <div key={index} className="dim" style={{ fontSize: 10, color: "var(--amber)" }}>
                  {JSON.stringify(entry).slice(0, 110)}
                </div>
              ))}
            </div>
            <div>
              <div className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>EVIDENCE</div>
              {!evidence && <div className="faint" style={{ fontSize: 10 }}>no evidence document returned</div>}
              {evidence && Object.keys(evidence).slice(0, 8).map((key) => (
                <div key={key} className="faint" style={{ fontSize: 10 }}>
                  <span className="mono">{key}</span>: {JSON.stringify(evidence[key]).slice(0, 80)}
                </div>
              ))}
              <div className="mono" style={{ fontSize: 10, color: "var(--cyan)", marginTop: 8 }}>PROJECTIONS</div>
              {!projections && <div className="faint" style={{ fontSize: 10 }}>no projections returned</div>}
              {projections && Object.keys(projections).slice(0, 8).map((key) => (
                <div key={key} className="faint" style={{ fontSize: 10 }}>
                  <span className="mono">{key}</span>: {JSON.stringify(projections[key]).slice(0, 80)}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </Panel>
  );
}
