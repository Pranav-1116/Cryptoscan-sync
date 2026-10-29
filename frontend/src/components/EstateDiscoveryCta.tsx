/* Estate discovery is the one action that turns "nothing has been discovered
 * yet" into a readable estate, and until now no page could trigger it: every
 * /estate/evidence/* read answered 404 no_estate_discovery and the console
 * showed only "Read refused (HTTP 404)".
 *
 * This component probes that state explicitly and offers the job. It says what
 * the job does and, crucially, what its output means: a discovery run over an
 * empty store is NOT_OBSERVED — not an estate without cryptography. Nothing is
 * rendered when a run already exists, or when the probe fails for any other
 * reason (the page's own error already covers that case).
 */
import { useCallback, useEffect, useState } from "react";
import { apiEstateScan, apiEstateSummary } from "../lib/api";

type Phase = "idle" | "probing" | "needed" | "hidden" | "running";

export default function EstateDiscoveryCta({ onDiscovered, compact = false }: {
  /** Called after a successful job so the page can re-read its own endpoint. */
  onDiscovered?: () => void;
  compact?: boolean;
}) {
  const [phase, setPhase] = useState<Phase>("probing");
  const [message, setMessage] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  const probe = useCallback(async () => {
    setPhase("probing");
    const res = await apiEstateSummary();
    // A stored run answers 200; the 404 no_estate_discovery refusal means the
    // estate has never been discovered on this tenant. `source` is "live" for a
    // refusal too, so only `ok` decides whether a run exists.
    if (res.ok && res.data) { setPhase("hidden"); return; }
    if ((res.detail || "").includes("no_estate_discovery")) { setPhase("needed"); return; }
    setPhase("hidden");
  }, []);

  useEffect(() => { void probe(); }, [probe]);

  const run = useCallback(async () => {
    setPhase("running");
    setMessage(null);
    setFailed(false);
    const res = await apiEstateScan({});
    const report = res.data;
    if (!res.ok || !report) {
      setPhase("needed");
      setFailed(true);
      setMessage(res.detail || res.error || "the discovery job did not return a report");
      return;
    }
    const ran = report.collectors?.filter((c) => c.status !== "NOT_ATTEMPTED") ?? [];
    const collected = report.summary?.assets ?? 0;
    if (report.run_id == null) {
      // change_only: the estate fingerprints to the stored projection.
      setPhase("hidden");
      setMessage(
        "estate unchanged since the stored discovery — nothing new was stored. "
        + `The stored run still holds ${collected} asset(s) across ${ran.length} attempted plane(s).`,
      );
    } else {
      setPhase("hidden");
      setMessage(
        `estate discovery stored (run ${report.run_id}): ${collected} asset(s) over ${ran.length} attempted plane(s). `
        + "A plane that returned nothing is NOT_OBSERVED, not an estate without crypto.",
      );
      onDiscovered?.();
    }
  }, [onDiscovered]);

  if (phase === "probing" || phase === "hidden") {
    return message ? (
      <p role="status" style={{ margin: "0 0 12px", fontSize: 11.5, color: "var(--dim)" }}>{message}</p>
    ) : null;
  }

  return (
    <div
      role="status"
      className="panel"
      style={{
        padding: compact ? "10px 12px" : "14px 16px",
        marginBottom: 14,
        borderLeft: "3px solid var(--amber)",
        background: "color-mix(in srgb, var(--amber) 5%, var(--panel))",
        display: "flex",
        gap: 14,
        alignItems: "flex-start",
        flexWrap: "wrap",
      }}
    >
      <div style={{ flex: "1 1 320px", minWidth: 240 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: "var(--amber)" }}>
          No estate discovery has run for this tenant
        </div>
        <p style={{ margin: "4px 0 0", fontSize: 11.5, color: "var(--dim)", lineHeight: 1.5 }}>
          The estate evidence reads below answer <code>no_estate_discovery</code> until one job has run.
          The job is read-only: it joins the evidence this deployment has already persisted across the
          discovery planes and projects the BOMs from that graph. It does not scan, so re-running it costs
          nothing. An empty result is <b style={{ color: "var(--text)" }}>NOT_OBSERVED</b> — never an estate
          without cryptography.
        </p>
        {message && (
          <p style={{ margin: "6px 0 0", fontSize: 11.5, color: failed ? "var(--red)" : "var(--dim)" }}>
            {message}
          </p>
        )}
      </div>
      <button
        type="button"
        className="btn primary"
        onClick={() => void run()}
        disabled={phase === "running"}
        style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", whiteSpace: "nowrap" }}
      >
        {phase === "running" ? "Running estate discovery…" : "Run estate discovery"}
      </button>
    </div>
  );
}
