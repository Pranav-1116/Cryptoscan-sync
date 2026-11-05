import React, { useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiEstateTwin, apiEstateTwinSearch, apiEstateTwinImpact, apiEstateTwinSimulate, apiEstateTwinAsset,
  apiEstateTwinSnapshots, apiEstateTwinCapture, apiEstateTwinCompare, apiEstateTwinCryptoGraph, apiEstateTwinGraph,
  apiEstateTwinGraphLoadPlan, apiEstateTwinSimulations,
  apiEstateChanges, apiEstateChangesDetect, apiEstateChangeAcknowledge,
  apiEstateCatalog, apiEstateCatalogAssets, apiEstateCatalogAsset, apiEstateCryptoRegistry,
  apiEstateTwinPlacement, apiEstateTwinWhy,
  apiEstateAssetHistory, apiEstateHistorySummary, apiEstateSearch, apiEstateConflicts,
  apiEstateLifecycle, apiEstateIntel, apiEstateAlgorithm, apiEstateTrustPaths,
  EstateTwinOverview, EstateTwinSearchResult, EstateTwinImpact, EstateTwinSimulation, EstateTwinAssetView,
  EstateTwinSnapshotList, EstateTwinCompare, EstateTwinCryptoGraph, EstateTwinGraphExport,
  EstateTwinGraphLoad, EstateTwinSimulationList,
  EstateChangeFeed, EstateChangeEvent,
  EstateCatalogSummary, EstateCatalogAsset, EstateCatalogDetail, EstateCryptoRegistry,
  EstatePlacement, EstateTwinWhy, EstateAssetHistory, EstateHistorySummary, EstateSearchResult,
  EstateConflictSurvey, EstateLifecycle, EstateCryptoIntel, EstateAlgorithmView,
  EstateTrustPaths,
} from "../lib/api.js";

/* DigitalTwinPanel — spec 94.

   The twin is the correlated model behind the six BOMs, so this panel answers
   the four questions the BOMs cannot:

   * where things belong (placement, with unplaced called out);
   * how well the estate is described (completeness — explicitly not posture);
   * what a change would touch (blast radius, with its blind spots);
   * what a planned change would do (simulation on a copy, never on the bank).

   Two refusals are rendered as first-class states rather than empty tables:
   `NO_MATCH` (we could not find the thing you asked about) is not "no impact",
   and an UNMEASURED dimension is not 0% — it is `n/a` with its reason. */

function barTone(percent: number | null): string {
  if (percent == null) return "var(--slate)";
  if (percent >= 95) return "var(--green)";
  if (percent >= 80) return "var(--amber)";
  return "var(--red)";
}

function DimensionRow({ item }: { item: { dimension: string; percent: number | null; state: string; meaning: string; reason?: string | null } }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 2, marginTop: 6 }}>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span className="mono" style={{ fontSize: 10.5, color: "var(--cyan)", minWidth: 168 }}>{item.dimension}</span>
        <div style={{ flex: 1, height: 5, background: "rgba(255,255,255,0.06)", borderRadius: 3 }}>
          <div
            style={{
              width: `${item.percent ?? 0}%`,
              height: 5,
              borderRadius: 3,
              background: barTone(item.percent),
              opacity: item.percent == null ? 0.15 : 1,
            }}
          />
        </div>
        <span className="mono" style={{ fontSize: 10.5, minWidth: 46, textAlign: "right", color: barTone(item.percent) }}>
          {item.percent == null ? "n/a" : `${item.percent}%`}
        </span>
        {item.percent == null && <Badge tone="slate">{item.state}</Badge>}
      </div>
      <span className="faint" style={{ fontSize: 10 }}>{item.reason ?? item.meaning}</span>
    </div>
  );
}

export default function DigitalTwinPanel() {
  const twin = usePollingApi(apiEstateTwin, 60000, [], { channels: ["twin"] });
  const doc = (twin.data ?? null) as EstateTwinOverview | null;

  const [query, setQuery] = useState("AES-256");
  const [found, setFound] = useState<EstateTwinSearchResult | null>(null);
  const [impact, setImpact] = useState<EstateTwinImpact | null>(null);
  const [simulation, setSimulation] = useState<EstateTwinSimulation | null>(null);
  const [asset, setAsset] = useState<EstateTwinAssetView | null>(null);
  const [scenario, setScenario] = useState({ kind: "REPLACE_ALGORITHM", from: "RSA", to: "ML-DSA" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const search = async () => {
    if (!query.trim()) return;
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinSearch(query.trim());
    if (result.ok) setFound(result.data as EstateTwinSearchResult);
    else setError("search failed — the API is unavailable, which is not an empty twin");
    setBusy(false);
  };

  /* §25 — the asset screen is the one people actually use: click a result and see
     what the twin knows, how strongly it knows it, and what it does not know. */
  const investigate = async (ref: string) => {
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinAsset(ref);
    if (result.ok) setAsset(result.data as EstateTwinAssetView);
    else setError("asset view failed — an unreachable API is not an asset with no crypto");
    setBusy(false);
  };

  const blast = async () => {
    if (!query.trim()) return;
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinImpact({ algorithm: query.trim(), depth: 3 });
    if (result.ok) setImpact(result.data as EstateTwinImpact);
    else setError("impact failed — no answer is not the same as no impact");
    setBusy(false);
  };

  const simulate = async () => {
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinSimulate({ ...scenario, key_size: undefined, targets: [] });
    if (result.ok) setSimulation(result.data as EstateTwinSimulation);
    else setError("simulation failed — nothing was changed on the live estate");
    setBusy(false);
  };

  const completeness = doc?.completeness;

  /* Four views over one twin. "Live" is the current evidence; the other three are
     the parts spec 94 §24 lists that a BOM panel cannot answer: what moved, what is
     capability vs use, and what a graph store would receive. */
  const [view, setView] = useState<
    "live" | "crypto" | "catalog" | "changes" | "history" | "graph" | "loop" | "intel"
  >("live");
  const [snapshots, setSnapshots] = useState<EstateTwinSnapshotList | null>(null);
  const [comparison, setComparison] = useState<EstateTwinCompare | null>(null);
  const [crypto, setCrypto] = useState<EstateTwinCryptoGraph | null>(null);
  const [exported, setExported] = useState<EstateTwinGraphExport | null>(null);
  const [loadPlan, setLoadPlan] = useState<EstateTwinGraphLoad | null>(null);
  const [simulations, setSimulations] = useState<EstateTwinSimulationList | null>(null);
  /* its own error: the stored-simulation read failing must not overwrite the
     snapshot error, or one broken read would look like two */
  const [simError, setSimError] = useState<string | null>(null);
  const [changeFeed, setChangeFeed] = useState<EstateChangeFeed | null>(null);
  const [changeError, setChangeError] = useState<string | null>(null);
  const [detected, setDetected] = useState<EstateChangeEvent | null>(null);
  const [catalogSummary, setCatalogSummary] = useState<EstateCatalogSummary | null>(null);
  const [catalogAssets, setCatalogAssets] = useState<EstateCatalogAsset[] | null>(null);
  const [catalogFilter, setCatalogFilter] = useState<string>("");
  const [catalogRecord, setCatalogRecord] = useState<EstateCatalogDetail | null>(null);
  const [registry, setRegistry] = useState<EstateCryptoRegistry | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [placement, setPlacement] = useState<EstatePlacement | null>(null);
  const [assetHistory, setAssetHistory] = useState<EstateAssetHistory | null>(null);
  const [historySummary, setHistorySummary] = useState<EstateHistorySummary | null>(null);
  /* its own error again: a missing history must not erase the catalogue record */
  const [historyError, setHistoryError] = useState<string | null>(null);
  /* §26: the durable record, searched across kinds — not just the latest run */
  const [record, setRecord] = useState<EstateSearchResult | null>(null);
  const [recordError, setRecordError] = useState<string | null>(null);
  /* §23: what the twin is holding, classified — and never resolved for you */
  const [conflictsHeld, setConflictsHeld] = useState<EstateConflictSurvey | null>(null);
  /* §2: the loop, and the first phase that does not reach the next one */
  const [loop, setLoop] = useState<EstateLifecycle | null>(null);
  /* §12/§24: weak, unidentified and post-quantum, with capability held apart from use */
  const [intelView, setIntelView] = useState<EstateCryptoIntel | null>(null);
  const [algorithmName, setAlgorithmName] = useState("");
  const [algorithmView, setAlgorithmView] = useState<EstateAlgorithmView | null>(null);
  /* §24: where each certificate chain stops, and what that does not prove */
  const [trustPaths, setTrustPaths] = useState<EstateTrustPaths | null>(null);
  /* §28/§9: the most important question in the product — why does the twin believe
     this edge exists? Answering it for a *selected* edge, not only per asset. */
  const [edgeWhy, setEdgeWhy] = useState<{ key: string; data: EstateTwinWhy | null } | null>(null);

  const capture = async () => {
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinCapture(`captured from the twin panel`);
    if (result.ok) {
      await loadHistory();
    } else {
      setError("capture failed — no snapshot was written");
    }
    setBusy(false);
  };

  const loadHistory = async () => {
    const result = await apiEstateTwinSnapshots();
    if (result.ok) setSnapshots(result.data as EstateTwinSnapshotList);
    else setError("snapshot history unavailable — that is not 'no history'");
  };

  const loadCompare = async (before?: string, after?: string) => {
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinCompare(before, after);
    if (result.ok) setComparison(result.data as EstateTwinCompare);
    else setError("compare unavailable — no comparison is not the same as no change");
    setBusy(false);
  };

  const loadCrypto = async () => {
    const result = await apiEstateTwinCryptoGraph();
    if (result.ok) setCrypto(result.data as EstateTwinCryptoGraph);
    else setError("crypto graph unavailable");
  };

  const loadExport = async () => {
    const result = await apiEstateTwinGraph();
    if (result.ok) setExported(result.data as EstateTwinGraphExport);
    else setError("graph export unavailable");
  };

  /* Readings of stored answers, never of the estate. The label on the section
     carries the distinction so a screenshot cannot lose it. */
  const loadSimulationHistory = async () => {
    const result = await apiEstateTwinSimulations();
    if (result.ok) setSimulations(result.data as EstateTwinSimulationList);
    else setSimError("stored simulations unavailable");
  };

  /* The catalogue is the twin's memory: rows survive observations, so a STALE asset
     is history rather than a deletion and the UI must not filter it away. */
  const loadCatalog = async (filter?: string) => {
    const summary = await apiEstateCatalog();
    if (summary.ok) setCatalogSummary(summary.data as EstateCatalogSummary);
    else setCatalogError("catalogue unavailable — this is not 'no assets'");
    const assets = await apiEstateCatalogAssets(
      filter ? { assetType: filter } : undefined,
    );
    if (assets.ok) {
      setCatalogAssets((assets.data as { assets: EstateCatalogAsset[] }).assets);
      setCatalogError(null);
    } else setCatalogError("catalogue unavailable — this is not 'no assets'");
    const crypto = await apiEstateCryptoRegistry();
    if (crypto.ok) setRegistry(crypto.data as EstateCryptoRegistry);
  };

  const openCatalogAsset = async (identifier: string) => {
    setAssetHistory(null);
    setHistoryError(null);
    const detail = await apiEstateCatalogAsset(identifier);
    if (detail.ok) setCatalogRecord(detail.data as EstateCatalogDetail);
    else setCatalogError("asset not in the catalogue — it may never have been observed");
    const history = await apiEstateAssetHistory(identifier);
    if (history.ok) setAssetHistory(history.data as EstateAssetHistory);
    // 404 here means "no per-fact history", which is not the same as "no facts"
    else setHistoryError("no per-fact history for this asset — not the same as no properties");
  };

  /* The twin's own search answers "what does the latest observation say". This one
     answers "what has the record ever said", across assets, artefacts, edges, evidence,
     facts and detected changes. */
  const searchRecord = async () => {
    const text = query.trim();
    if (!text) return;
    setRecordError(null);
    const result = await apiEstateSearch(text);
    if (result.ok) setRecord(result.data as EstateSearchResult);
    else setRecordError("search unavailable — an empty answer here means the record could not be read");
  };

  const loadConflicts = async () => {
    const result = await apiEstateConflicts();
    if (result.ok) setConflictsHeld(result.data as EstateConflictSurvey);
    else setConflictsHeld(null);
  };

  const loadLoop = async () => {
    const result = await apiEstateLifecycle();
    if (result.ok) setLoop(result.data as EstateLifecycle);
    else setLoop(null);
  };

  const loadIntel = async () => {
    const result = await apiEstateIntel();
    if (result.ok) setIntelView(result.data as EstateCryptoIntel);
    else setIntelView(null);
  };

  const loadTrustPaths = async () => {
    const result = await apiEstateTrustPaths();
    setTrustPaths(result.ok ? (result.data as EstateTrustPaths) : null);
  };

  const loadAlgorithm = async (name: string) => {
    const text = name.trim();
    if (!text) return;
    const result = await apiEstateAlgorithm(text);
    setAlgorithmView(result.ok ? (result.data as EstateAlgorithmView) : null);
  };

  const loadHistorySummary = async () => {
    const result = await apiEstateHistorySummary();
    if (result.ok) setHistorySummary(result.data as EstateHistorySummary);
    else setHistoryError("history summary unavailable");
  };

  /* The change feed: what moved between observations, and what that does not prove. */
  /* §9: select an edge, get its evidence — or the reason it was refused. */
  const askWhy = async (key: string, query: { subject: string; predicate: string; object: string }) => {
    setEdgeWhy({ key, data: null });
    const result = await apiEstateTwinWhy(query);
    setEdgeWhy({ key, data: result.ok ? (result.data as EstateTwinWhy) : null });
  };

  /* The hierarchy above the environment, only where evidence puts something. */
  const loadPlacement = async () => {
    const result = await apiEstateTwinPlacement();
    if (result.ok) setPlacement(result.data as EstatePlacement);
    else setError("placement unavailable");
  };

  const loadChanges = async () => {
    const result = await apiEstateChanges({ unacknowledgedOnly: false });
    if (result.ok) setChangeFeed(result.data as EstateChangeFeed);
    else setChangeError("change feed unavailable — this is not 'nothing changed'");
  };

  const detectNow = async () => {
    setBusy(true);
    setChangeError(null);
    const result = await apiEstateChangesDetect();
    if (result.ok) {
      setDetected(result.data as EstateChangeEvent);
      await loadChanges();
    } else setChangeError("change detection failed — the feed was not updated");
    setBusy(false);
  };

  const acknowledge = async (eventId: string) => {
    setBusy(true);
    const result = await apiEstateChangeAcknowledge(eventId);
    if (result.ok) await loadChanges();
    else setChangeError("could not acknowledge: the change is still unacknowledged");
    setBusy(false);
  };

  /* Deliberately only the plan: writing to a graph store is a CLI/API action. */
  const planLoad = async () => {
    setBusy(true);
    setError(null);
    const result = await apiEstateTwinGraphLoadPlan();
    if (result.ok) setLoadPlan(result.data as EstateTwinGraphLoad);
    else setError("graph load plan unavailable");
    setBusy(false);
  };

  React.useEffect(() => {
    if (view === "history" && snapshots === null) void loadHistory();
    if (view === "history" && simulations === null) void loadSimulationHistory();
    if (view === "crypto" && crypto === null) void loadCrypto();
    if (view === "graph" && exported === null) void loadExport();
    if (view === "changes" && changeFeed === null) void loadChanges();
    if (view === "catalog" && catalogAssets === null) void loadCatalog();
    if (view === "catalog" && historySummary === null) void loadHistorySummary();
    if (view === "live" && conflictsHeld === null) void loadConflicts();
    if (view === "live" && placement === null) void loadPlacement();
    if (view === "loop" && loop === null) void loadLoop();
    if (view === "intel" && intelView === null) void loadIntel();
    if (view === "intel" && trustPaths === null) void loadTrustPaths();
  }, [view]);

  const TABS: Array<{ id: typeof view; label: string }> = [
    { id: "live", label: "Live estate" },
    { id: "crypto", label: "Crypto graph" },
    { id: "catalog", label: "Catalogue" },
    { id: "changes", label: "Changes" },
    { id: "history", label: "History & compare" },
    { id: "graph", label: "Graph export" },
    { id: "loop", label: "Loop" },
    { id: "intel", label: "Intelligence" },
  ];

  return (
    <Panel
      title="Digital twin — the model the six BOMs are projected from"
      sub="placement, description completeness, blast radius and simulation; a simulation runs on a copy and says so"
      className="mt"
    >
      {error && (
        <div className="dim" style={{ fontSize: 11.5, marginTop: 4, marginBottom: 6, color: "var(--red)" }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`btn sm${view === tab.id ? " primary" : ""}`}
            style={{ fontSize: 10.5 }}
            onClick={() => setView(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {!doc && !error && (
        <div className="dim" style={{ fontSize: 12 }}>
          {twin.error ? "no stored estate discovery yet — the twin is NOT_OBSERVED, not empty" : "loading the twin…"}
        </div>
      )}

      {doc && view === "live" && (
        <>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <Badge tone="violet">{doc.projection_id.slice(0, 12)}</Badge>
            <Badge tone="slate">{doc.estate ?? "estate"}</Badge>
            {completeness && (
              <Badge tone={completeness.overall_percent == null ? "slate" : completeness.overall_percent >= 90 ? "green" : "amber"}>
                twin completeness {completeness.overall_percent == null ? "not measured" : `${completeness.overall_percent}%`}
              </Badge>
            )}
            {doc.placement.unplaced_count > 0 && (
              <Badge tone="amber">{doc.placement.unplaced_count} unplaced</Badge>
            )}
            {completeness?.weakest_dimension && (
              <Badge tone="amber">
                weakest {completeness.weakest_dimension.dimension} {completeness.weakest_dimension.percent}%
              </Badge>
            )}
            {completeness && <span className="faint" style={{ fontSize: 10 }}>{completeness.meaning}</span>}
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18, marginTop: 12 }}>
            <div>
              <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>PLACEMENT</div>
              {doc.placement.environments.length === 0 && (
                <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>no asset carries an environment — placement is unknown, not one environment</div>
              )}
              {doc.placement.environments.map((env) => (
                <div key={env.name} style={{ marginTop: 6 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ fontSize: 11.5 }}>{env.name}</span>
                    <Badge tone="slate">{env.assets} assets</Badge>
                    {env.business_systems.length > 0 && <Badge tone="cyan">{env.business_systems.length} systems</Badge>}
                  </div>
                  <div className="faint" style={{ fontSize: 10, marginTop: 2 }}>
                    {env.locations.map((loc) => `${loc.name} (${loc.assets})`).join(" · ")}
                  </div>
                </div>
              ))}
              {doc.placement.unplaced_count > 0 && (
                <div className="dim" style={{ fontSize: 10.5, marginTop: 6, color: "var(--amber)" }}>
                  {doc.placement.unplaced_count} asset(s) carry no environment or location — reported UNPLACED rather than attached to the root
                </div>
              )}

              {/* §4: the levels above the environment, present only where a collector
                  asserted them. What nothing asserts is counted, not drawn empty. */}
              {placement && (
                <div style={{ marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 6 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>
                    HIERARCHY · {placement.levels_observed.join(" → ")}
                  </div>
                  {/* the organisation chart, where any collection asserted it */}
                  {(placement.organizations ?? []).map((org) => (
                    <div key={org.name} className="dim" style={{ fontSize: 10 }}>
                      entity {org.name} · {org.assets} asset(s)
                    </div>
                  ))}
                  {(placement.departments ?? []).map((dept) => (
                    <div key={dept.name} className="dim" style={{ fontSize: 10 }}>
                      department {dept.name}
                      {dept.organization ? ` (${dept.organization})` : ""} · {dept.assets} asset(s)
                    </div>
                  ))}
                  {placement.regions.map((region) => (
                    <div key={region.name} className="dim" style={{ fontSize: 10 }}>
                      region {region.name} · {region.assets} asset(s)
                    </div>
                  ))}
                  {placement.data_centers.map((dc) => (
                    <div key={dc.name} className="dim" style={{ fontSize: 10 }}>
                      site {dc.name} · {dc.assets} asset(s)
                    </div>
                  ))}
                  {placement.cloud_environments.map((cloud) => (
                    <div key={cloud.name} className="dim" style={{ fontSize: 10 }}>
                      cloud {cloud.name} · {cloud.assets} asset(s)
                    </div>
                  ))}
                  {placement.unassigned.map((row) => (
                    <div key={row.level} className="faint" style={{ fontSize: 9.5, color: "var(--amber)" }}>
                      {row.assets} asset(s) with no {row.level.toLowerCase().replace(/_/g, " ")} in any evidence
                    </div>
                  ))}
                  {placement.levels_unobserved.length > 0 && (
                    <div className="faint" style={{ fontSize: 9.5 }}>
                      not observed at all: {placement.levels_unobserved.join(", ")}
                    </div>
                  )}
                </div>
              )}
            </div>

            <div>
              <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>COMPLETENESS</div>
              {conflictsHeld && conflictsHeld.count > 0 && (
              <div style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 6 }}>
                <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>
                  {`CONFLICTS · ${conflictsHeld.real_count} real, ${conflictsHeld.explained_count} explained`}
                </div>
                {conflictsHeld.conflicts.slice(0, 5).map((entry) => (
                  <div key={`${entry.asset_id}:${entry.field}`} style={{ fontSize: 10, marginTop: 3 }}>
                    <Badge tone={entry.classification === "REAL" ? "amber" : "slate"}>
                      {entry.classification}
                    </Badge>{" "}
                    {entry.asset_name ?? entry.asset_id} · {entry.field}
                    <div className="faint" style={{ fontSize: 9.5 }}>
                      {entry.values.map((value) => String(value.value)).join(" vs ")} — {entry.reason}
                    </div>
                  </div>
                ))}
                <div className="faint" style={{ fontSize: 9.5 }}>
                  nothing here is resolved for you: closing a conflict needs a corrected source and a
                  re-collection
                </div>
              </div>
            )}
            {completeness?.dimensions.map((item) => <DimensionRow key={item.dimension} item={item} />)}
              {completeness?.why_not_100.slice(0, 4).map((item) => (
                <div key={item.reason} className="faint" style={{ fontSize: 10, marginTop: 4 }}>
                  <span className="mono" style={{ color: "var(--amber)" }}>{item.count}</span> · {item.reason} — {item.next_action}
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 16 }}>
            <input
              className="input"
              style={{ width: 200, fontSize: 11 }}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              aria-label="search the twin"
              placeholder="algorithm, protocol, key size or name"
            />
            <button type="button" className="btn sm" onClick={() => void search()} disabled={busy}>Search twin</button>
            <button type="button" className="btn sm" onClick={() => void searchRecord()} disabled={busy}>
              Search the record
            </button>
            <button type="button" className="btn sm" onClick={() => void blast()} disabled={busy}>Blast radius</button>
            {busy && <span className="faint" style={{ fontSize: 10.5 }}>working…</span>}
          </div>


          {found && (
            <div style={{ marginTop: 10 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone={found.status === "MATCHED" ? "green" : "slate"}>{found.status}</Badge>
                <span className="faint" style={{ fontSize: 10.5 }}>{found.counts.assets} assets · {found.counts.artifacts} crypto artefacts</span>
                {Object.entries(found.by_asset_type).map(([type, count]) => (
                  <Badge key={type} tone="slate">{type} {count}</Badge>
                ))}
              </div>
              {found.assets.length > 0 && (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 6 }}>
                  {found.assets.slice(0, 12).map((item) => (
                    <button
                      key={item.asset_id}
                      type="button"
                      className="btn sm"
                      style={{ fontSize: 10.5 }}
                      onClick={() => void investigate(item.asset_id)}
                    >
                      {item.name}
                    </button>
                  ))}
                </div>
              )}
              {found.status === "NO_MATCH" && (
                <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>
                  nothing matches {found.query} — that is not "the bank does not use it", it means no collected evidence describes it
                </div>
              )}
              <div className="faint" style={{ fontSize: 10, marginTop: 4 }}>{found.note}</div>
            </div>
          )}

          {recordError && (
            <div className="dim" style={{ fontSize: 10.5, marginTop: 8, color: "var(--amber)" }}>{recordError}</div>
          )}

          {record && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone="violet">record · {record.query}</Badge>
                <span className="faint" style={{ fontSize: 9.5 }}>
                  {record.matched} match(es) across {record.kinds.length} kind(s)
                </span>
                {Object.entries(record.by_kind)
                  .filter(([, count]) => count > 0)
                  .map(([kind, count]) => (
                    <Badge key={kind} tone="slate">{count} {kind.toLowerCase()}</Badge>
                  ))}
              </div>
              {Object.entries(record.groups).map(([kind, group]) => {
                if (!group.count) return null;
                return (
                  <div key={kind} style={{ marginTop: 6 }}>
                    <div className="mono" style={{ fontSize: 9.5, color: "var(--cyan)" }}>
                      {kind}{group.truncated ? ` · first ${group.limit} of ${group.count}` : ""}
                    </div>
                    {group.usage_states && (
                      <div className="faint" style={{ fontSize: 9.5 }}>
                        {Object.entries(group.usage_states)
                          .map(([state, count]) => `${state} ${count}`)
                          .join(" · ")}{" "}
                        — capability is not use
                      </div>
                    )}
                    {group.hits.slice(0, 8).map((hit) => (
                      <div key={`${kind}:${hit.id}`} style={{ fontSize: 10, marginTop: 2 }}>
                        {hit.label}
                        {hit.usage_states && (
                          <span className="faint" style={{ fontSize: 9.5 }}>
                            {" "}· {Object.entries(hit.usage_states).map(([state, count]) => `${state} ${count}`).join(", ")}
                          </span>
                        )}
                        {hit.status === "UNRESOLVED" && <Badge tone="amber">candidate</Badge>}
                        {hit.state === "HISTORICAL" && <Badge tone="slate">historical</Badge>}
                        {hit.severity && <Badge tone={hit.severity === "CRITICAL" ? "red" : "amber"}>{hit.severity}</Badge>}
                        {(hit.kind === "ASSET" || hit.asset_id) && (
                          <button
                            type="button"
                            className="btn sm"
                            style={{ marginLeft: 6, fontSize: 9.5 }}
                            onClick={() => void investigate((hit.asset_id ?? hit.id) as string)}
                          >
                            open
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                );
              })}
              {record.matched === 0 && (
                <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>
                  nothing in the record matches — that is a gap in what has been observed, not proof the
                  bank has none of it
                </div>
              )}
              <div className="faint" style={{ fontSize: 9.5, marginTop: 4 }}>{record.meaning}</div>
            </div>
          )}

          {impact && (
            <div style={{ marginTop: 12 }}>
              <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>IMPACT · {JSON.stringify(impact.selector)}</div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                <Badge tone={impact.status === "MATCHED" ? "green" : "slate"}>{impact.status}</Badge>
                {impact.counts && (
                  <>
                    <Badge tone="violet">{impact.counts.total ?? 0} in radius</Badge>
                    <Badge tone="cyan">{impact.counts.direct ?? 0} direct</Badge>
                    <Badge tone="slate">{impact.counts.business_systems ?? 0} business systems</Badge>
                  </>
                )}
              </div>
              {impact.detail && <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>{impact.detail}</div>}
              {impact.paths?.slice(0, 3).map((entry) => (
                <div key={entry.asset_id} className="faint mono" style={{ fontSize: 10, marginTop: 3 }}>
                  {entry.path.map((hop) => hop.name ?? hop.asset_id).join(" → ")}
                </div>
              ))}
              {!!impact.blockers?.length && (
                <div style={{ marginTop: 6 }}>
                  <span className="mono" style={{ fontSize: 10, color: "var(--amber)" }}>BLIND SPOTS</span>
                  {impact.blockers.slice(0, 4).map((blocker, index) => (
                    <div key={index} className="faint" style={{ fontSize: 10 }}>
                      {String(blocker.kind)} · {String(blocker.detail ?? blocker.reason ?? "")}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {asset && (
            <div style={{ marginTop: 14, borderTop: "1px solid rgba(255,255,255,0.07)", paddingTop: 10 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <span className="mono" style={{ fontSize: 12, color: "var(--cyan)" }}>{asset.asset.name.toUpperCase()}</span>
                <Badge tone="slate">{asset.asset.type}</Badge>
                <Badge tone={asset.placement.placed ? "green" : "amber"}>
                  {asset.placement.placed ? (asset.placement.environment ?? "placed") : "UNPLACED"}
                </Badge>
                {asset.asset.owner && <Badge tone="violet">{asset.asset.owner}</Badge>}
                <Badge tone="cyan">evidence: {asset.evidence.strongest}</Badge>
                <Badge tone="slate">{asset.evidence.count} records</Badge>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 8 }}>
                <div>
                  <div className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>CRYPTOGRAPHY</div>
                  {asset.crypto.artifacts.length === 0 && (
                    <div className="dim" style={{ fontSize: 10.5, marginTop: 3 }}>
                      no cryptographic artefact is evidenced for this asset — that is NOT "it uses no crypto"
                    </div>
                  )}
                  {asset.crypto.artifacts.map((item, index) => (
                    <div key={index} className="faint" style={{ fontSize: 10.5, marginTop: 3 }}>
                      <span className="mono" style={{ color: "var(--fg)" }}>
                        {String(item.algorithm ?? item.protocol ?? "unknown")}
                        {item.key_size ? `-${String(item.key_size)}` : ""}
                      </span>{" "}
                      · {String(item.usage_state)} · {String(item.layer)} · {String(item.evidence_type)}
                    </div>
                  ))}
                  <div className="faint" style={{ fontSize: 9.5, marginTop: 4 }}>{asset.crypto.note}</div>
                </div>

                <div>
                  <div className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>RELATIONSHIPS</div>
                  {asset.relationships.count === 0 && (
                    <div className="dim" style={{ fontSize: 10.5, marginTop: 3 }}>
                      no established relationship — the twin does not draw edges it cannot evidence
                    </div>
                  )}
                  {[...asset.relationships.outgoing, ...asset.relationships.incoming].slice(0, 8).map((item, index) => {
                    /* an edge is a claim: clicking it asks the twin to show its work */
                    const subject = item.direction === "in" ? item.asset_id : asset.asset.asset_id;
                    const object = item.direction === "in" ? asset.asset.asset_id : item.asset_id;
                    const key = `${subject}|${item.predicate}|${object}`;
                    const selected = edgeWhy?.key === key;
                    return (
                      <button
                        key={index}
                        type="button"
                        onClick={() => void askWhy(key, { subject, predicate: item.predicate, object })}
                        className="faint"
                        style={{
                          display: "block", width: "100%", textAlign: "left", cursor: "pointer",
                          background: selected ? "var(--panel-2)" : "transparent",
                          border: 0, padding: "2px 0", fontSize: 10.5, marginTop: 3,
                          color: selected ? "var(--text)" : undefined,
                        }}
                        title="why does the twin believe this relationship?"
                      >
                        <span className="mono" style={{ color: "var(--cyan)" }}>{item.predicate}</span>{" "}
                        {item.name ?? item.asset_id}{" "}
                        <span className="mono" style={{ fontSize: 9.5 }}>
                          ({item.basis ?? "no basis"} · {item.confidence ?? "UNKNOWN"})
                        </span>
                        {selected && edgeWhy?.data && (
                          <span style={{ display: "block", marginTop: 3, color: "var(--dim)" }}>
                            {edgeWhy.data.status === "ESTABLISHED" && (edgeWhy.data.matches?.[0]?.answer
                              ?? "established; evidence listed below")}
                            {edgeWhy.data.status === "ESTABLISHED" && edgeWhy.data.matches?.[0]?.evidence
                              ?.slice(0, 2).map((ev) => (
                                <span key={ev.evidence_id} className="mono" style={{ display: "block", fontSize: 9 }}>
                                  {ev.evidence_type} · {ev.collector ?? "unknown collector"} ·{" "}
                                  {ev.source} · {ev.observed_at ?? "no timestamp"} · {ev.hash.slice(0, 12)}…
                                </span>
                              ))}
                            {edgeWhy.data.status === "NOT_ESTABLISHED" && (
                              <span style={{ color: "var(--amber)" }}>
                                refused: {edgeWhy.data.refused?.[0]?.reason ?? edgeWhy.data.answer}
                              </span>
                            )}
                            {(edgeWhy.data.status === "NO_SUCH_RELATIONSHIP"
                              || edgeWhy.data.status === "UNKNOWN_ASSET") && (
                              <span style={{ color: "var(--amber)" }}>
                                {edgeWhy.data.answer ?? edgeWhy.data.detail}
                              </span>
                            )}
                          </span>
                        )}
                      </button>
                    );
                  })}
                  <div className="mono" style={{ fontSize: 10, color: "var(--cyan)", marginTop: 8 }}>EVIDENCE</div>
                  {asset.evidence.records.slice(0, 4).map((record) => (
                    <div key={record.evidence_id} className="faint" style={{ fontSize: 9.5, marginTop: 2 }}>
                      {record.evidence_type} · {record.collector ?? "unknown collector"} ·{" "}
                      <span className="mono">{record.source}</span> · {record.hash.slice(0, 16)}…
                    </div>
                  ))}
                  {asset.unknown.no_evidence && (
                    <div className="dim" style={{ fontSize: 10, marginTop: 4, color: "var(--amber)" }}>
                      no evidence at all — the twin describes this asset not at all
                    </div>
                  )}
                  {asset.unknown.unresolved_relationships.length > 0 && (
                    <div className="dim" style={{ fontSize: 10, marginTop: 4, color: "var(--amber)" }}>
                      {asset.unknown.unresolved_relationships.length} refused relationship(s) touch this asset
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 16 }}>
            <span className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>SIMULATE</span>
            <select
              className="input"
              style={{ fontSize: 11, width: 190 }}
              value={scenario.kind}
              onChange={(event) => setScenario({ ...scenario, kind: event.target.value })}
              aria-label="simulation kind"
            >
              <option value="REPLACE_ALGORITHM">replace algorithm</option>
              <option value="RETIRE_ALGORITHM">retire algorithm</option>
              <option value="DISABLE_PROTOCOL">disable protocol</option>
              <option value="UPGRADE_COMPONENT">upgrade component</option>
            </select>
            <input
              className="input" style={{ width: 120, fontSize: 11 }} value={scenario.from}
              onChange={(event) => setScenario({ ...scenario, from: event.target.value })} aria-label="from"
            />
            <span className="faint" style={{ fontSize: 10.5 }}>→</span>
            <input
              className="input" style={{ width: 120, fontSize: 11 }} value={scenario.to}
              onChange={(event) => setScenario({ ...scenario, to: event.target.value })} aria-label="to"
            />
            <button type="button" className="btn sm" onClick={() => void simulate()} disabled={busy}>Run simulation</button>
          </div>

          {simulation && (
            <div style={{ marginTop: 10 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone={simulation.status === "SIMULATED" ? "green" : simulation.status === "NO_MATCH" ? "amber" : "slate"}>
                  {simulation.status}
                </Badge>
                {simulation.live_projection_unchanged != null && (
                  <Badge tone={simulation.live_projection_unchanged ? "slate" : "red"}>
                    live twin {simulation.live_projection_unchanged ? "unchanged" : "MODIFIED"}
                  </Badge>
                )}
                {simulation.matched_evidence != null && <Badge tone="cyan">{simulation.matched_evidence} evidence records changed</Badge>}
                {simulation.bom_changes != null && <Badge tone="violet">{simulation.bom_changes ? "BOMs differ" : "BOMs identical"}</Badge>}
              </div>
              {simulation.detail && <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>{simulation.detail}</div>}
              {simulation.bom_diff && (
                <div className="faint" style={{ fontSize: 10, marginTop: 4 }}>
                  {Object.entries(simulation.bom_diff)
                    .filter(([, entry]) => entry.counts.added || entry.counts.removed || entry.counts.changed)
                    .map(([kind, entry]) => `${kind} +${entry.counts.added}/-${entry.counts.removed}/~${entry.counts.changed}`)
                    .join(" · ") || "no BOM component moved"}
                </div>
              )}
              {!!simulation.blockers?.length && (
                <div style={{ marginTop: 6 }}>
                  <span className="mono" style={{ fontSize: 10, color: "var(--amber)" }}>BLOCKERS</span>
                  {simulation.blockers.slice(0, 5).map((blocker, index) => (
                    <div key={index} className="faint" style={{ fontSize: 10 }}>
                      {String(blocker.kind)} · {String(blocker.detail ?? "")}
                    </div>
                  ))}
                </div>
              )}
              {simulation.note && <div className="faint" style={{ fontSize: 10, marginTop: 4 }}>{simulation.note}</div>}
            </div>
          )}
        </>
      )}

      {view === "crypto" && (
        <div style={{ marginTop: 4 }}>
          {!crypto && <div className="dim" style={{ fontSize: 11 }}>{error ?? "loading the crypto graph…"}</div>}
          {crypto && (
            <>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone="violet">{crypto.projection_id.slice(0, 12)}</Badge>
                <Badge tone={crypto.conflict_counts.real ? "red" : "green"}>
                  {crypto.conflict_counts.real} real conflict(s)
                </Badge>
                <Badge tone="slate">{crypto.conflict_counts.explained} explained disagreement(s)</Badge>
                <span className="faint" style={{ fontSize: 10 }}>
                  capability, configuration, runtime and wire facts are drawn on separate planes
                </span>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginTop: 12 }}>
                {["CAPABILITY", "CONFIGURED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED"].map((plane) => (
                  <div key={plane}>
                    <div className="mono" style={{ fontSize: 10, color: "var(--cyan)" }}>{plane}</div>
                    <div className="faint" style={{ fontSize: 9.5, marginBottom: 4 }}>
                      {crypto.plane_meanings[plane]}
                    </div>
                    {(crypto.planes[plane] ?? []).length === 0 && (
                      <div className="dim" style={{ fontSize: 10 }}>nothing on this plane</div>
                    )}
                    {(crypto.planes[plane] ?? []).slice(0, 12).map((item, index) => (
                      <div key={index} className="faint" style={{ fontSize: 10 }}>
                        <span className="mono" style={{ color: "var(--fg)" }}>{item.label}</span>
                        {" · "}{item.asset_name ?? item.asset_id.slice(0, 8)}
                        {" · "}{item.layer}
                      </div>
                    ))}
                    {(crypto.planes[plane] ?? []).length > 12 && (
                      <div className="faint" style={{ fontSize: 9.5 }}>
                        +{(crypto.planes[plane] ?? []).length - 12} more
                      </div>
                    )}
                  </div>
                ))}
              </div>

              {crypto.coexistence.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>
                    CAPABILITY IS NOT USE
                  </div>
                  {crypto.coexistence.slice(0, 5).map((entry, index) => (
                    <div key={index} className="faint" style={{ fontSize: 10, marginTop: 3 }}>
                      <span style={{ color: "var(--fg)" }}>{entry.asset_name}</span> can do{" "}
                      {entry.capability.join(", ")}; seen doing {entry.in_use.join(", ") || "nothing"}.
                      {entry.supported_but_not_observed.length > 0 && (
                        <> Supported but not observed: {entry.supported_but_not_observed.join(", ")}.</>
                      )}
                    </div>
                  ))}
                  <div className="faint" style={{ fontSize: 9.5, marginTop: 4 }}>
                    {crypto.coexistence[0]?.explanation}
                  </div>
                </div>
              )}

              {crypto.conflicts.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--amber)" }}>REAL CONFLICTS</div>
                  {crypto.conflicts.slice(0, 6).map((conflict, index) => (
                    <div key={index} className="dim" style={{ fontSize: 10 }}>
                      {String(conflict.asset_name ?? conflict.asset_id)} · {String(conflict.field)} — two
                      sources on the same plane disagree; not auto-resolved
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {view === "history" && (
        <div style={{ marginTop: 4 }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <button type="button" className="btn sm" onClick={() => void capture()} disabled={busy}>
              Capture snapshot
            </button>
            <button type="button" className="btn sm" onClick={() => void loadCompare()} disabled={busy}>
              Compare two newest
            </button>
            {snapshots && (
              <Badge tone={snapshots.persisted ? "green" : "amber"}>
                {snapshots.persisted ? `${snapshots.count} persisted` : "derived from scan runs (not persisted)"}
              </Badge>
            )}
          </div>
          {snapshots && !snapshots.persisted && (
            <div className="dim" style={{ fontSize: 10.5, marginTop: 6 }}>{snapshots.note}</div>
          )}

          {snapshots && snapshots.snapshots.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {snapshots.snapshots.slice(0, 8).map((snapshot) => (
                <div
                  key={snapshot.id}
                  style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginTop: 4 }}
                >
                  <Badge tone="violet">{snapshot.projection_id.slice(0, 10)}</Badge>
                  <span className="faint" style={{ fontSize: 10 }}>
                    {snapshot.assets} assets · {snapshot.evidence} evidence · {snapshot.relationships} edges
                  </span>
                  <Badge tone="slate">
                    completeness {snapshot.completeness_percent == null ? "n/a" : `${snapshot.completeness_percent}%`}
                  </Badge>
                  {snapshot.observations > 1 && <Badge tone="cyan">seen {snapshot.observations}×</Badge>}
                  {/* §19: same evidence, different rules, is a policy change — not drift */}
                  <Badge tone={snapshot.policy_version ? "slate" : "amber"}>
                    {snapshot.policy_version ?? "policy not recorded"}
                  </Badge>
                  {(snapshot.collector_versions ?? []).length > 0 && (
                    <span className="faint" style={{ fontSize: 9.5 }}>
                      {(snapshot.collector_versions ?? []).slice(0, 3).join(", ")}
                    </span>
                  )}
                  <button
                    type="button"
                    className="btn sm"
                    style={{ fontSize: 10 }}
                    onClick={() => void loadCompare(undefined, snapshot.projection_id)}
                  >
                    compare to newest
                  </button>
                </div>
              ))}
            </div>
          )}

          {comparison && (
            <div style={{ marginTop: 12, borderTop: "1px solid rgba(255,255,255,0.08)", paddingTop: 8 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge
                  tone={
                    comparison.verdict === "NO_CHANGE"
                      ? "green"
                      : comparison.verdict === "NOT_COMPARABLE"
                        ? "slate"
                        : comparison.verdict === "COVERAGE_DEGRADED"
                          ? "red"
                          : "amber"
                  }
                >
                  {comparison.verdict}
                </Badge>
                {comparison.assets && (
                  <Badge tone="slate">
                    assets +{comparison.assets.counts.added ?? 0}/−{comparison.assets.counts.removed ?? 0}/
                    ~{comparison.assets.counts.changed ?? 0}
                  </Badge>
                )}
                {comparison.crypto && (
                  <Badge tone="violet">
                    crypto +{comparison.crypto.counts.added ?? 0}/−{comparison.crypto.counts.removed ?? 0}
                  </Badge>
                )}
                {comparison.coverage && comparison.coverage.counts.degraded > 0 && (
                  <Badge tone="red">{comparison.coverage.counts.degraded} plane(s) degraded</Badge>
                )}
              </div>
              <div className="dim" style={{ fontSize: 10.5, marginTop: 4 }}>{comparison.reason}</div>

              {comparison.coverage?.degraded.map((entry, index) => (
                <div key={index} className="faint" style={{ fontSize: 10, color: "var(--red)" }}>
                  {String(entry.plane)}: {String(entry.before)} → {String(entry.after)} —{" "}
                  {String(entry.reason ?? "no reason recorded")}
                </div>
              ))}
              {comparison.crypto?.promoted.map((entry, index) => (
                <div key={`p${index}`} className="faint" style={{ fontSize: 10, color: "var(--green)" }}>
                  promoted {String(entry.algorithm ?? entry.protocol)} on {String(entry.asset_name)}:{" "}
                  {String(entry.before)} → {String(entry.after)}
                </div>
              ))}
              {comparison.crypto?.demoted.map((entry, index) => (
                <div key={`d${index}`} className="faint" style={{ fontSize: 10, color: "var(--amber)" }}>
                  lost proof for {String(entry.algorithm ?? entry.protocol)} on {String(entry.asset_name)}:{" "}
                  {String(entry.before)} → {String(entry.after)}
                </div>
              ))}
              {comparison.assets?.changed.slice(0, 5).map((entry, index) => (
                <div key={`c${index}`} className="faint" style={{ fontSize: 10 }}>
                  {entry.name} changed: {entry.changed_fields.join(", ")}
                </div>
              ))}
              {comparison.note && <div className="faint" style={{ fontSize: 9.5, marginTop: 4 }}>{comparison.note}</div>}
            </div>
          )}

          {/* Stored simulations, listed as questions asked — not as history of the
              estate. Each row states that on screen, and a superseded answer says so
              rather than showing an impact figure as if it were current. */}
          <div style={{ marginTop: 14, borderTop: "1px solid var(--line)", paddingTop: 10 }}>
            <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
              <Badge tone="slate">Simulations · quarantined</Badge>
              {simulations && <Badge tone="slate">{simulations.count} stored</Badge>}
              <span className="faint" style={{ fontSize: 9.5 }}>
                a simulation is a question asked of a copy — never estate state
              </span>
            </div>
            {!simulations && <div className="dim" style={{ fontSize: 11 }}>{simError ?? "loading stored simulations…"}</div>}
            {simulations && simulations.count === 0 && (
              <div className="dim" style={{ fontSize: 11 }}>
                nothing has been asked of a copy yet — run a simulation in the live view
              </div>
            )}
            {simulations?.simulations.slice(0, 6).map((entry) => (
              <div key={entry.simulation_id} style={{ marginTop: 6 }}>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                  <Badge tone="violet">{entry.kind}</Badge>
                  <Badge tone={entry.superseded ? "amber" : "green"}>
                    {entry.superseded ? "STALE" : "CURRENT"}
                  </Badge>
                  <Badge tone="slate">{entry.matched_evidence} evidence record(s)</Badge>
                  <Badge tone="slate">{entry.affected_assets.length} asset(s)</Badge>
                  {entry.observations > 1 && <Badge tone="slate">asked {entry.observations}×</Badge>}
                  {entry.label && <span className="dim" style={{ fontSize: 10 }}>{entry.label}</span>}
                </div>
                <div className="faint" style={{ fontSize: 9.5, color: entry.superseded ? "var(--amber)" : undefined }}>
                  {entry.freshness}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {view === "catalog" && (
        <div style={{ marginTop: 4 }}>
          {catalogSummary && (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
              <Badge tone="slate">{catalogSummary.assets} asset record(s)</Badge>
              {Object.entries(catalogSummary.assets_by_lifecycle).map(([state, count]) => (
                <Badge key={state} tone={state === "STALE" ? "amber" : "green"}>
                  {count} {state.toLowerCase()}
                </Badge>
              ))}
              <span className="faint" style={{ fontSize: 9.5 }}>
                rows survive observations — stale means &ldquo;not in the latest run&rdquo;, never deleted
              </span>
              {historySummary && (
                <>
                  <Badge tone="slate">
                    {historySummary.observations.current} current fact(s)
                  </Badge>
                  <Badge tone="slate">
                    {historySummary.observations.historical} superseded
                  </Badge>
                  <Badge tone="slate">{historySummary.evidence.total} evidence record(s)</Badge>
                  {historySummary.observations.disputed_facts > 0 && (
                    <Badge tone="amber">
                      {historySummary.observations.disputed_facts} disputed fact(s) — nothing chosen
                    </Badge>
                  )}
                </>
              )}
            </div>
          )}

          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginTop: 8 }}>
            {["", "HSM", "CERTIFICATE", "APPLICATION", "LIBRARY", "LOAD_BALANCER"].map((kind) => (
              <button
                key={kind || "all"}
                type="button"
                className="btn sm"
                onClick={() => {
                  setCatalogFilter(kind);
                  void loadCatalog(kind || undefined);
                }}
              >
                {kind || "All types"}
              </button>
            ))}
            {catalogFilter && <Badge tone="violet">filter: {catalogFilter}</Badge>}
          </div>

          {!catalogAssets && (
            <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
              {catalogError ?? "loading the catalogue…"}
            </div>
          )}
          {catalogAssets && catalogAssets.length === 0 && (
            <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
              no catalogue records for that filter — the catalogue holds what has been observed, so this
              is a statement about collection, not about the bank
            </div>
          )}

          {catalogAssets?.map((asset) => (
            <button
              key={asset.asset_id}
              type="button"
              className="btn sm"
              style={{ display: "block", width: "100%", textAlign: "left", marginTop: 4 }}
              onClick={() => void openCatalogAsset(asset.asset_id)}
            >
              <span className="mono" style={{ fontSize: 9.5, opacity: 0.7 }}>{asset.asset_type}</span>{" "}
              {asset.name}{" "}
              <Badge tone={asset.lifecycle_state === "STALE" ? "amber" : "green"}>{asset.lifecycle_state}</Badge>{" "}
              <span className="faint" style={{ fontSize: 9.5 }}>
                seen {asset.observation_count}× · {asset.evidence_count} evidence record(s)
                {asset.environment ? ` · ${asset.environment}` : ""}
              </span>
            </button>
          ))}

          {catalogRecord && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone="violet">{catalogRecord.asset.asset_type}</Badge>
                <strong>{catalogRecord.asset.name}</strong>
                <Badge tone={catalogRecord.asset.lifecycle_state === "STALE" ? "amber" : "green"}>
                  {catalogRecord.asset.lifecycle_state}
                </Badge>
                <Badge tone="slate">{catalogRecord.counts.evidence} evidence</Badge>
                <Badge tone="slate">{catalogRecord.counts.relationships} edge(s)</Badge>
                {catalogRecord.counts.unresolved > 0 && (
                  <Badge tone="amber">{catalogRecord.counts.unresolved} unresolved candidate(s)</Badge>
                )}
              </div>
              <div className="faint" style={{ fontSize: 9.5, marginTop: 3 }}>
                first seen {catalogRecord.asset.first_seen_at ?? "—"} · last seen{" "}
                {catalogRecord.asset.last_seen_at ?? "—"} · {catalogRecord.asset.observation_count} observation(s)
              </div>

              <div style={{ marginTop: 6 }}>
                {catalogRecord.crypto.map((item) => (
                  <div key={item.artifact_id} style={{ fontSize: 10.5 }}>
                    <span className="mono" style={{ fontSize: 9.5, opacity: 0.75 }}>{item.usage_state}</span>{" "}
                    {item.algorithm ?? item.protocol ?? item.curve ?? "unspecified primitive"}
                    {item.layer ? ` · ${item.layer}` : ""}
                    {item.lifecycle_state === "STALE" && <Badge tone="amber">stale</Badge>}
                  </div>
                ))}
              </div>

              {catalogRecord.relationships.map((edge) => (
                <div key={edge.relationship_id} style={{ fontSize: 10.5, marginTop: 2 }}>
                  <span className="mono" style={{ fontSize: 9.5, opacity: 0.75 }}>{edge.predicate}</span>{" "}
                  → {edge.object_name ?? edge.object_id}
                  <span className="faint" style={{ fontSize: 9.5 }}>
                    {" "}(basis {edge.basis ?? "—"}, {edge.evidence_type ?? "type not stored"},{" "}
                    {edge.evidence_ids.length} evidence)
                  </span>
                </div>
              ))}
              {assetHistory && (
                <div style={{ marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 6 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>
                    {`FACT HISTORY · ${assetHistory.fact_count} fact(s) · a change closes a window, it does not overwrite one`}
                  </div>
                  {assetHistory.facts.map((fact) => (
                    <div key={fact.fact_type} style={{ fontSize: 10, marginTop: 3 }}>
                      <span className="mono" style={{ fontSize: 9.5, opacity: 0.75 }}>
                        {fact.fact_type}
                      </span>{" "}
                      {fact.current_values.join(", ") || "(no longer observed)"}{" "}
                      {fact.state === "CONFLICT" && <Badge tone="amber">CONFLICT</Badge>}{" "}
                      {fact.state === "HISTORICAL" && <Badge tone="slate">historical</Badge>}
                      {fact.timeline
                        .filter((window) => window.state !== "CURRENT")
                        .map((window) => (
                          <div key={window.observation_id} className="faint" style={{ fontSize: 9.5 }}>
                            was {window.value} until {window.last_seen_at ?? "unknown"} (seen{" "}
                            {window.observation_count}×)
                          </div>
                        ))}
                    </div>
                  ))}
                  {assetHistory.conflicted_facts.length > 0 && (
                    <div style={{ fontSize: 9.5, marginTop: 4, color: "var(--amber)" }}>
                      {assetHistory.conflicted_facts.join(", ")} — two values still asserted; the twin
                      reports the disagreement instead of picking one
                    </div>
                  )}
                </div>
              )}
              {historyError && (
                <div className="dim" style={{ fontSize: 9.5, marginTop: 6 }}>{historyError}</div>
              )}

              {catalogRecord.unresolved_candidates.map((edge) => (
                <div key={edge.relationship_id} style={{ fontSize: 10.5, marginTop: 2, color: "var(--amber)" }}>
                  candidate {edge.predicate} → {edge.object_name ?? edge.object_id} — REFUSED:{" "}
                  {edge.reason ?? "no basis"}
                </div>
              ))}
            </div>
          )}

          {registry && registry.algorithms.length > 0 && (
            <div style={{ marginTop: 12, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
              <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                <Badge tone="slate">Algorithm registry</Badge>
                <span className="faint" style={{ fontSize: 9.5 }}>
                  per usage state — capability never counts as use
                </span>
              </div>
              {registry.algorithms.slice(0, 10).map((entry) => (
                <div key={entry.algorithm} style={{ marginTop: 4 }}>
                  <div style={{ fontSize: 10.5 }}>
                    <strong>{entry.algorithm}</strong>{" "}
                    <span className="faint" style={{ fontSize: 9.5 }}>
                      {entry.asset_count} asset(s) ·{" "}
                      {Object.entries(entry.usage_states).map(([state, count]) => `${state} ${count}`).join(", ")}
                      {entry.stale > 0 ? ` · ${entry.stale} stale` : ""}
                    </span>
                  </div>
                  <div className="dim" style={{ fontSize: 9.5 }}>
                    {entry.assets.slice(0, 4).map((item) => item.asset_name).filter(Boolean).join(", ")}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {view === "changes" && (
        <div style={{ marginTop: 4 }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <button type="button" className="btn sm" onClick={() => void detectNow()} disabled={busy}>
              Detect change now
            </button>
            {changeFeed && (
              <>
                <Badge tone="slate">{changeFeed.count} recorded</Badge>
                {changeFeed.unacknowledged > 0 && (
                  <Badge tone="amber">{changeFeed.unacknowledged} not acknowledged</Badge>
                )}
                {changeFeed.by_severity.CRITICAL ? (
                  <Badge tone="red">{changeFeed.by_severity.CRITICAL} critical</Badge>
                ) : null}
              </>
            )}
            <span className="faint" style={{ fontSize: 9.5 }}>
              every event compares two observations — it never re-collects to confirm a change
            </span>
          </div>

          {detected && (
            <div style={{ marginTop: 8, fontSize: 10.5 }}>
              <Badge tone={detected.severity === "CRITICAL" ? "red" : detected.severity === "NONE" ? "slate" : "amber"}>
                {detected.severity}
              </Badge>{" "}
              <span className="dim">{detected.headline}</span>
            </div>
          )}

          {!changeFeed && (
            <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
              {changeError ?? "loading the change feed…"}
            </div>
          )}
          {changeFeed && changeFeed.count === 0 && (
            <div className="dim" style={{ fontSize: 11, marginTop: 6 }}>
              {changeFeed.meaning}
            </div>
          )}

          {changeFeed?.events.map((event) => (
            <div key={event.event_id} style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone={event.severity === "CRITICAL" ? "red" : event.severity === "WARNING" ? "amber" : "slate"}>
                  {event.severity}
                </Badge>
                <Badge tone="slate">{event.verdict}</Badge>
                {event.observations > 1 && <Badge tone="slate">seen {event.observations}×</Badge>}
                {event.acknowledged && <Badge tone="green">acknowledged</Badge>}
                <span className="dim" style={{ fontSize: 10 }}>{event.first_detected_at ?? ""}</span>
              </div>
              <div style={{ fontSize: 11, marginTop: 2 }}>{event.headline}</div>
              {event.changes.slice(0, 8).map((change, index) => (
                <div key={index} style={{ marginTop: 3 }}>
                  <div style={{ fontSize: 10.5 }}>
                    <span className="mono" style={{ fontSize: 9.5, opacity: 0.75 }}>{change.kind}</span>{" "}
                    {change.subject}
                  </div>
                  <div className="dim" style={{ fontSize: 10 }}>{change.detail}</div>
                  {change.means && (
                    <div className="faint" style={{ fontSize: 9.5 }}>{change.means}</div>
                  )}
                </div>
              ))}
              {event.next_action && (
                <div className="dim" style={{ fontSize: 10, marginTop: 3 }}>
                  next: {event.next_action}
                </div>
              )}
              {!event.acknowledged && event.event_id && (
                <button
                  type="button"
                  className="btn sm"
                  style={{ marginTop: 4 }}
                  onClick={() => void acknowledge(event.event_id)}
                  disabled={busy}
                >
                  Acknowledge
                </button>
              )}
            </div>
          ))}

          {changeFeed && changeFeed.limits.length > 0 && (
            <div className="faint" style={{ fontSize: 9.5, marginTop: 10 }}>
              {changeFeed.limits[1] ?? changeFeed.limits[0]}
            </div>
          )}
        </div>
      )}

      {view === "intel" && (
        <div style={{ marginTop: 4 }}>
          {!intelView && <div className="dim" style={{ fontSize: 11 }}>{error ?? "reading the estate's cryptography…"}</div>}
          {intelView && (
            <>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone={intelView.weak.in_use_count > 0 ? "red" : "slate"}>
                  {`${intelView.weak.in_use_count} weak in use`}
                </Badge>
                <Badge tone="amber">{`${intelView.weak.capability_only_count} capability only`}</Badge>
                <Badge tone="amber">{`${intelView.unknown.count} unidentified`}</Badge>
                <Badge tone="violet">{`${intelView.pqc.vulnerable_artifacts} Shor-vulnerable`}</Badge>
                <Badge tone="slate">{`${intelView.pqc.vendor_bound_blocker_count} vendor-bound`}</Badge>
              </div>

              {intelView.weak.entries.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--red)" }}>WEAK</div>
                  {intelView.weak.entries.slice(0, 6).map((entry) => (
                    <div key={`${entry.asset_id}:${entry.algorithm}:${entry.layer}`} style={{ fontSize: 10 }}>
                      <Badge tone={entry.in_use ? "red" : "slate"}>{entry.in_use ? "IN USE" : "CAPABILITY"}</Badge>{" "}
                      {entry.asset_name ?? entry.asset_id} · {entry.algorithm} · {entry.status} · {entry.usage_state} · {entry.layer}
                      {entry.in_use && (
                        <div className="faint" style={{ fontSize: 9.5 }}>
                          verdict from {entry.verdict_source}; the evidence behind the value is in the asset record
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {intelView.unknown.entries.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--amber)" }}>UNIDENTIFIED</div>
                  {intelView.unknown.entries.slice(0, 6).map((entry) => (
                    <div key={`${entry.asset_id}:${entry.algorithm}`} style={{ fontSize: 10 }}>
                      {entry.asset_name ?? entry.asset_id} · {entry.algorithm} ·{" "}
                      {entry.reading === "NOT_AN_ALGORITHM" ? "a version string, not an algorithm" : "unrecognised"}
                    </div>
                  ))}
                </div>
              )}

              <div style={{ marginTop: 8 }}>
                <div className="mono" style={{ fontSize: 10.5, color: "var(--violet)" }}>POST-QUANTUM</div>
                <div className="dim" style={{ fontSize: 10 }}>{intelView.pqc.meaning}</div>
                {intelView.pqc.vendor_bound_blockers.slice(0, 4).map((asset) => (
                  <div key={asset.asset_id} className="faint" style={{ fontSize: 9.5 }}>
                    blocker: {asset.asset_name ?? asset.asset_id} ({asset.asset_type}) · {asset.algorithms.join(", ")}
                  </div>
                ))}
              </div>

              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 10, flexWrap: "wrap" }}>
                <input
                  className="input"
                  style={{ fontSize: 11, maxWidth: 220 }}
                  placeholder="algorithm — e.g. RSA-2048"
                  value={algorithmName}
                  onChange={(event) => setAlgorithmName(event.target.value)}
                />
                <button
                  type="button"
                  className="btn sm"
                  onClick={() => void loadAlgorithm(algorithmName)}
                  disabled={!algorithmName.trim()}
                >
                  Who depends on it
                </button>
              </div>
              {algorithmView && (
                <div style={{ marginTop: 6 }}>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                    <Badge tone="slate">{algorithmView.algorithm}</Badge>
                    <Badge tone="cyan">{`${algorithmView.artifacts} artefact(s)`}</Badge>
                    <Badge tone="amber">{`${algorithmView.in_use} in use`}</Badge>
                    <Badge tone="slate">{`${algorithmView.capability_only} capability only`}</Badge>
                    {algorithmView.quantum_vulnerable && <Badge tone="violet">Shor-vulnerable</Badge>}
                  </div>
                  {!algorithmView.found && (
                    <div className="faint" style={{ fontSize: 9.5 }}>
                      no observation asserts it — not a statement that the estate does not use it
                    </div>
                  )}
                  {Object.entries(algorithmView.by_asset_type_in_use).map(([type, count]) => (
                    <div key={type} style={{ fontSize: 10 }}>
                      {type}: {count} using it
                    </div>
                  ))}
                </div>
              )}

              {trustPaths && trustPaths.count > 0 && (
                <div style={{ marginTop: 10, borderTop: "1px solid var(--line)", paddingTop: 6 }}>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>TRUST PATHS</div>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center", marginTop: 2 }}>
                    <Badge tone="green">{`${trustPaths.rooted_count} rooted`}</Badge>
                    {trustPaths.broken_count > 0 && <Badge tone="red">{`${trustPaths.broken_count} broken`}</Badge>}
                    {trustPaths.unjudged_count > 0 && (
                      <Badge tone="slate">{`${trustPaths.unjudged_count} unjudged`}</Badge>
                    )}
                  </div>
                  {trustPaths.chains.slice(0, 5).map((chain) => (
                    <div key={chain.asset_id} style={{ fontSize: 10, marginTop: 3 }}>
                      <Badge tone={chain.status === "ROOTED" ? "green" : chain.status === "BROKEN" ? "red" : "slate"}>
                        {chain.status}
                      </Badge>{" "}
                      {chain.chain.map((step) => step.asset_name ?? step.asset_id ?? "?").join(" → ")}
                      {chain.status !== "ROOTED" && (
                        <div className="faint" style={{ fontSize: 9.5 }}>{chain.reason}</div>
                      )}
                    </div>
                  ))}
                  <div className="faint" style={{ fontSize: 9.5 }}>
                    no signature is verified and no expiry is checked — this is where the evidence stops
                  </div>
                </div>
              )}

              <div className="faint" style={{ fontSize: 9.5, marginTop: 8 }}>{intelView.next_action}</div>
            </>
          )}
        </div>
      )}

      {view === "loop" && (
        <div style={{ marginTop: 4 }}>
          {!loop && <div className="dim" style={{ fontSize: 11 }}>{error ?? "loading the lifecycle…"}</div>}
          {loop && (
            <>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone={loop.loop_closed ? "green" : "amber"}>
                  {loop.loop_closed ? "LOOP CLOSED" : `BREAKS AT ${loop.first_break}`}
                </Badge>
                <Badge tone="slate">{loop.by_status.CONNECTED} connected</Badge>
                {loop.by_status.PARTIAL > 0 && <Badge tone="amber">{loop.by_status.PARTIAL} partial</Badge>}
                {loop.by_status.NOT_CONNECTED > 0 && (
                  <Badge tone="red">{loop.by_status.NOT_CONNECTED} not connected</Badge>
                )}
                {loop.by_status.NOT_STARTED > 0 && (
                  <Badge tone="slate">{loop.by_status.NOT_STARTED} not started</Badge>
                )}
              </div>
              {loop.phases.map((phase) => (
                <div
                  key={phase.phase}
                  style={{ marginTop: 6, borderTop: "1px solid var(--line)", paddingTop: 4 }}
                >
                  <div style={{ display: "flex", gap: 6, alignItems: "center", flexWrap: "wrap" }}>
                    <Badge
                      tone={
                        phase.status === "CONNECTED"
                          ? "green"
                          : phase.status === "PARTIAL"
                            ? "amber"
                            : phase.status === "NOT_CONNECTED"
                              ? "red"
                              : "slate"
                      }
                    >
                      {phase.status}
                    </Badge>
                    <span className="mono" style={{ fontSize: 10.5 }}>{phase.phase}</span>
                    <span className="dim" style={{ fontSize: 10 }}>{phase.question}</span>
                  </div>
                  <div className="faint" style={{ fontSize: 9.5, marginTop: 2 }}>
                    {phase.detail}
                  </div>
                  {phase.gap && (
                    <div className="faint" style={{ fontSize: 9.5, marginTop: 1 }}>
                      gap: {phase.gap}
                    </div>
                  )}
                </div>
              ))}
              <div className="faint" style={{ fontSize: 9.5, marginTop: 8 }}>{loop.meaning}</div>
            </>
          )}
        </div>
      )}

      {view === "graph" && (
        <div style={{ marginTop: 4 }}>
          {!exported && <div className="dim" style={{ fontSize: 11 }}>{error ?? "loading the graph export…"}</div>}
          {exported && (
            <>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone="violet">{exported.projection_id.slice(0, 12)}</Badge>
                <Badge tone="slate">{exported.counts.asset_nodes} asset nodes</Badge>
                <Badge tone="slate">{exported.counts.evidence_nodes} evidence nodes</Badge>
                {(exported.counts.placement_nodes ?? 0) > 0 && (
                  <Badge tone="slate">{exported.counts.placement_nodes} placement nodes</Badge>
                )}
                <Badge tone="cyan">{exported.counts.relationships} edges</Badge>
                {exported.label_coverage && (
                  <Badge tone="violet">
                    {Object.keys(exported.label_coverage).length} spec labels covered
                  </Badge>
                )}
                {exported.counts.unresolved > 0 && (
                  <Badge tone="amber">{exported.counts.unresolved} unresolved (shipped separately)</Badge>
                )}
              </div>
              <div className="dim" style={{ fontSize: 10.5, marginTop: 6 }}>
                {String(exported.load_notes.not_source_of_truth)}
              </div>
              <div className="faint" style={{ fontSize: 10, marginTop: 4 }}>
                {String(exported.load_notes.edge_identity)}
              </div>
              <pre
                className="mono"
                style={{ fontSize: 9.5, marginTop: 8, maxHeight: 220, overflow: "auto", opacity: 0.8 }}
              >
                {JSON.stringify({ nodes: exported.nodes.slice(0, 2), relationships: exported.relationships.slice(0, 3) }, null, 1)}
              </pre>

              <div style={{ display: "flex", gap: 6, alignItems: "center", marginTop: 10, flexWrap: "wrap" }}>
                <button type="button" className="btn sm" onClick={() => void planLoad()} disabled={busy}>
                  Plan the graph-store load
                </button>
                <span className="faint" style={{ fontSize: 9.5 }}>
                  planning only — writing is `cryptoscan twin graph-load --apply`
                </span>
              </div>
              {loadPlan && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                    <Badge tone={loadPlan.dry_run ? "cyan" : "amber"}>
                      {loadPlan.dry_run ? "DRY RUN — nothing written" : loadPlan.verification}
                    </Badge>
                    <Badge tone="slate">{loadPlan.statements} statement(s)</Badge>
                    <Badge tone="slate">{loadPlan.expected.nodes} node(s)</Badge>
                    <Badge tone="slate">
                      {loadPlan.expected.relationships + loadPlan.expected.unresolved} relationship(s)
                    </Badge>
                    {loadPlan.expected.unresolved > 0 && (
                      <Badge tone="amber">{loadPlan.expected.unresolved} unresolved candidate(s)</Badge>
                    )}
                  </div>
                  <div className="dim" style={{ fontSize: 10, marginTop: 6 }}>
                    {loadPlan.source_of_truth}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </Panel>
  );
}
