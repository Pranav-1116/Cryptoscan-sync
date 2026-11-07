import React, { useCallback, useState } from "react";
import type { ApiResult } from "../lib/api";
import {
  apiIntelligenceFindings,
  apiIntelligencePqcClaims,
  apiIntelligenceRisk,
  apiIntelligenceSimulation,
} from "../lib/api";
import { useApi, LiveBadge } from "../lib/apiUi";
import FindingsTable from "./FindingsTable";
import PqcClaimsLadder from "./PqcClaimsLadder";
import RiskDimensionsPanel from "./RiskDimensionsPanel";
import SimulationPanel from "./SimulationPanel";
import type {
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
      <p className="muted">
        Coverage intelligence is modelled and tested in shared_models but has no
        live endpoint yet — this section stays empty and says so, because an
        unwired panel must never render invented coverage.
      </p>
    </div>
  );
}
