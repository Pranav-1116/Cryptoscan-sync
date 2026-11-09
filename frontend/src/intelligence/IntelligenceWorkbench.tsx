import React, { useCallback, useState } from "react";
import type { ApiResult } from "../lib/api";
import {
  apiExternalValidations,
  apiIntelligenceCoverage,
  apiIntelligenceFindings,
  apiIntelligencePqcClaims,
  apiIntelligenceRisk,
  apiIntelligenceSimulation,
} from "../lib/api";
import { useApi, LiveBadge } from "../lib/apiUi";
import { Donut, FlowStrip, HBars, Meter, type FlowState } from "../components/viz";
import FindingsTable from "./FindingsTable";
import PqcClaimsLadder from "./PqcClaimsLadder";
import RiskDimensionsPanel from "./RiskDimensionsPanel";
import SimulationPanel from "./SimulationPanel";
import type {
  EstateCoverage,
  ExternalValidationRegister,
  PqcReport,
  RiskProfile,
  SimulationResult,
  ThreatReport,
} from "./types";

const SCENARIOS = [
  "RSA_2048_TO_ML_DSA",
  "HYBRID_PQ_KEY_ESTABLISHMENT",
  "HSM_FAILURE",
  "KMS_OUTAGE",
  "CERTIFICATE_EXPIRY",
  "TLS_DOWNGRADE",
  "LIBRARY_VULNERABILITY",
  "VENDOR_RETIREMENT",
  "CA_COMPROMISE",
  "TRUST_PATH_MODIFICATION",
  "PROVIDER_REPLACEMENT",
  "SEGMENTATION_CHANGE",
];

/** The live workbench: the roadmap models over the intelligence API.
 *
 *  Honest states everywhere: when the backend is unreachable the page says so
 *  and the empty panels keep their "not a clean estate" wording — absence of
 *  rows is never drawn as absence of risk. The threat-horizon field is a
 *  required input because the API refuses to hide one in a default.
 */
export default function IntelligenceWorkbench() {
  const findings = useApi<ThreatReport>(apiIntelligenceFindings);
  const claims = useApi<PqcReport>(apiIntelligencePqcClaims);
  const coverage = useApi<EstateCoverage>(apiIntelligenceCoverage);
  const external = useApi<ExternalValidationRegister>(apiExternalValidations);

  const [assetId, setAssetId] = useState("");
  const [horizon, setHorizon] = useState("5");
  const [risk, setRisk] = useState<ApiResult<RiskProfile>>({ source: "offline", data: null });
  const [riskBusy, setRiskBusy] = useState(false);

  const [scenario, setScenario] = useState(SCENARIOS[0]);
  const [focalAsset, setFocalAsset] = useState("");
  const [snapshotVersion, setSnapshotVersion] = useState("");
  const [sim, setSim] = useState<ApiResult<SimulationResult & { evidence_note?: string }>>({
    source: "offline",
    data: null,
  });
  const [simBusy, setSimBusy] = useState(false);

  const loadRisk = useCallback(async () => {
    if (!assetId.trim()) return;
    setRiskBusy(true);
    try {
      setRisk(await apiIntelligenceRisk(assetId.trim(), Number(horizon)));
    } finally {
      setRiskBusy(false);
    }
  }, [assetId, horizon]);

  const runSimulation = useCallback(async () => {
    if (!focalAsset.trim() || !snapshotVersion.trim()) return;
    setSimBusy(true);
    try {
      setSim(await apiIntelligenceSimulation({
        scenario,
        focal_asset: focalAsset.trim(),
        snapshot_version: Number(snapshotVersion),
      }));
    } finally {
      setSimBusy(false);
    }
  }, [scenario, focalAsset, snapshotVersion]);

  const report = findings.data;
  const subjects = claims.data
    ? Object.entries(claims.data.subjects).map(([subject, entry]) => ({ subject, ...entry }))
    : [];

  // Visual summary — every bar and segment is a count of rows already
  // shown below; nothing is derived, smoothed or inferred here.
  const classCounts: Record<string, number> = {};
  for (const f of report?.findings ?? []) {
    classCounts[f.class] = (classCounts[f.class] ?? 0) + 1;
  }
  const notFiredNames = Object.keys(report?.detectors_not_fired ?? {});
  const readinessCounts: Record<string, number> = {};
  for (const sRow of subjects) {
    readinessCounts[sRow.readiness] = (readinessCounts[sRow.readiness] ?? 0) + 1;
  }

  return (
    <div className="intel">
      <div className="filters">
        <LiveBadge source={findings.source} />
        <LiveBadge source={claims.source} label={claims.source === "live" ? "CLAIMS LIVE" : "CLAIMS OFFLINE"} />
      </div>
      {(findings.source === "offline" || claims.source === "offline") && (
        <div className="banner">
          The intelligence API is unreachable for at least one section: nothing
          on this page is a clean result. Absence of rows is not absence of risk,
          and no figures are invented to fill the gap.
        </div>
      )}

      {(report || claims.data || coverage.data) && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, margin: "12px 0" }}>
          <section aria-label="Findings by class" style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: 12, background: "#1a2332" }}>
            <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 8 }}>
              FINDINGS BY CLASS
            </div>
            {report ? (
              (report.findings ?? []).length > 0 ? (
                <Donut
                  segments={Object.entries(classCounts).map(([label, value], i) => ({
                    label,
                    value,
                    tone: ["orange", "amber", "violet", "accent", "green", "slate"][i % 6],
                  }))}
                  centerLabel={(report.findings ?? []).length}
                  centerSub="findings"
                  size={108}
                />
              ) : (
                <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>
                  no findings recorded — an empty result, not a clean estate
                </p>
              )
            ) : (
              <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>not loaded — unknown, never zero</p>
            )}
          </section>

          <section aria-label="Detector firing" style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: 12, background: "#1a2332" }}>
            <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 8 }}>
              DETECTOR FIRING
            </div>
            {report ? (
              <>
                <FlowStrip
                  label="detector stages"
                  stages={[
                    { label: "fired", state: "done" as FlowState, note: "detectors that produced findings" },
                    {
                      label: "not fired",
                      state: notFiredNames.length > 0 ? ("unknown" as FlowState) : ("done" as FlowState),
                      note: "each carries its reason below — never an all-clear",
                    },
                  ]}
                />
                <p style={{ fontSize: 11, color: "var(--faint)", margin: "8px 0 0" }}>
                  {notFiredNames.length > 0
                    ? `${notFiredNames.length} detector(s) did not run here — explained below`
                    : "all detectors in this report fired"}
                </p>
              </>
            ) : (
              <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>not loaded — unknown, never zero</p>
            )}
          </section>

          <section aria-label="PQC readiness spread" style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: 12, background: "#1a2332" }}>
            <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 8 }}>
              PQC CLAIMS BY READINESS
            </div>
            {claims.data ? (
              subjects.length > 0 ? (
                <HBars
                  rows={Object.entries(readinessCounts).map(([label, value]) => ({
                    key: label,
                    label: `readiness · ${label}`,
                    value,
                    tone: label === "PQC_READY_VALIDATED" ? "green" : "slate",
                  }))}
                  unit=" subject(s)"
                  emptyTitle="no subjects"
                  emptyNote="no migration-stage claims recorded — unknown, which is neither ready nor fine"
                />
              ) : (
                <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>
                  no migration-stage claims recorded — unknown, which is neither ready nor fine
                </p>
              )
            ) : (
              <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>not loaded — unknown, never zero</p>
            )}
          </section>

          <section aria-label="Collection coverage meter" style={{ border: "1px solid var(--rule)", borderRadius: 8, padding: 12, background: "#1a2332" }}>
            <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 8 }}>
              COLLECTION COVERAGE
            </div>
            {coverage.data ? (
              coverage.data.coverage_percent === null ? (
                <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>
                  percent refused — the denominator is incomplete, never estimated
                </p>
              ) : (
                <Meter
                  value={coverage.data.coverage_percent}
                  label="coverage"
                  tone={coverage.data.coverage_percent >= 90 ? "green" : coverage.data.coverage_percent >= 60 ? "amber" : "red"}
                  note={coverage.data.verdict}
                />
              )
            ) : (
              <p style={{ fontSize: 11, color: "var(--faint)", margin: 0 }}>not loaded — no readings is not clean coverage</p>
            )}
          </section>
        </div>
      )}

      <FindingsTable findings={report?.findings ?? []} />
      {report?.detectors_not_fired && Object.keys(report.detectors_not_fired).length > 0 && (
        <table aria-label="Detectors that did not run">
          <thead>
            <tr>
              <th>detector not fired</th>
              <th>why — explained absence, never an all-clear</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(report.detectors_not_fired).map(([name, reason]) => (
              <tr key={name}>
                <td><span className="chip chip-unknown">{name}</span></td>
                <td className="muted">{reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <PqcClaimsLadder subjects={subjects} />
      {claims.data?.derived_from && (
        <p className="muted">{claims.data.derived_from}</p>
      )}

      <h2>Risk — five dimensions for one asset</h2>
      <div className="filters">
        <input
          placeholder="asset id"
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
          aria-label="Asset id"
        />
        <input
          type="number"
          min={1}
          value={horizon}
          onChange={(e) => setHorizon(e.target.value)}
          aria-label="Quantum threat horizon in years (policy input)"
          title="Policy input — required, never defaulted by the platform"
        />
        <button onClick={loadRisk} disabled={riskBusy || !assetId.trim()}>
          {riskBusy ? "loading…" : "load risk"}
        </button>
        <span className="muted">
          the threat horizon is a policy input — the platform hides none in a default
        </span>
      </div>
      {risk.data ? (
        <RiskDimensionsPanel dimensions={Object.values(risk.data.dimensions)} />
      ) : (
        risk.error && (
          <p className="muted">
            risk dimensions did not load ({risk.detail || risk.error}) — unknown,
            never zero.
          </p>
        )
      )}

      <h2>Simulation — one scenario, one selected versioned snapshot</h2>
      <div className="filters">
        <select
          value={scenario}
          onChange={(e) => setScenario(e.target.value)}
          aria-label="Scenario"
        >
          {SCENARIOS.map((name) => (
            <option key={name} value={name}>{name}</option>
          ))}
        </select>
        <input
          placeholder="focal asset"
          value={focalAsset}
          onChange={(e) => setFocalAsset(e.target.value)}
          aria-label="Focal asset"
        />
        <input
          type="number"
          min={1}
          placeholder="snapshot version"
          value={snapshotVersion}
          onChange={(e) => setSnapshotVersion(e.target.value)}
          aria-label="Snapshot version"
          title="A simulation runs against an explicitly selected versioned snapshot"
        />
        <button
          onClick={runSimulation}
          disabled={simBusy || !focalAsset.trim() || !snapshotVersion.trim()}
        >
          {simBusy ? "running…" : "run simulation"}
        </button>
      </div>
      {sim.data ? (
        <>
          <SimulationPanel result={sim.data} />
          {sim.data.evidence_note && <p className="muted">{sim.data.evidence_note}</p>}
        </>
      ) : (
        sim.error && (
          <p className="muted">
            the simulation did not run ({sim.detail || sim.error}) — a refused
            run is reported, never shown as a result.
          </p>
        )
      )}

      <h2>Collection coverage</h2>
      {coverage.data ? (
        <>
          <p className="muted">
            {coverage.data.status === "FILED"
              ? `batch ${coverage.data.batch_id} — ${coverage.data.reason}`
              : coverage.data.reason}
            {" "}A missing asset never silently becomes a clean security result.
          </p>
          <p>
            <strong>{coverage.data.verdict}</strong>
            {" · "}coverage:{" "}
            {coverage.data.coverage_percent === null
              ? "not computed (denominator incomplete — refused, not estimated)"
              : `${coverage.data.coverage_percent}%`}
            {" · "}authorized targets:{" "}
            {coverage.data.authorized_targets ?? "unknown"}
            {" · "}discovered: {coverage.data.discovered_assets ?? "unknown"}
            {" · "}unknown assets: {coverage.data.unknown_assets}
          </p>
          {coverage.data.gaps.length > 0 ? (
            <table>
              <thead>
                <tr>
                  <th>Gap</th>
                  <th>Count</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {coverage.data.gaps.map((gap) => (
                  <tr key={gap.kind + gap.detail}>
                    <td>{gap.kind}</td>
                    <td>{gap.count}</td>
                    <td>{gap.detail} (not a clean result)</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            coverage.data.status === "FILED" && (
              <p className="muted">
                no gaps recorded in this batch — a filed batch with no gaps is a
                measured fact about that batch only, not a clean estate.
              </p>
            )
          )}
        </>
      ) : (
        coverage.error && (
          <p className="muted">
            coverage did not load ({coverage.detail || coverage.error}) — no
            readings is not clean coverage.
          </p>
        )
      )}

      <h2>External validation register</h2>
      {external.data ? (
        <>
          <p className="muted">{external.data.note}</p>
          <table>
            <thead>
              <tr>
                <th>Validation</th>
                <th>Status</th>
                <th>Latest filing</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(external.data.kinds).map(([kind, entry]) => (
                <tr key={kind}>
                  <td>{kind}</td>
                  <td>{entry.status}</td>
                  <td>
                    {entry.latest
                      ? `${entry.latest.result} by ${entry.latest.performed_by} on ${String(entry.latest.performed_at).slice(0, 10)} — evidence: ${entry.latest.evidence_ids.join(", ")}`
                      : "not filed is not passed"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : (
        external.error && (
          <p className="muted">
            the register did not load ({external.detail || external.error}) —
            the status of every external validation stays unknown, never passed.
          </p>
        )
      )}
    </div>
  );
}
