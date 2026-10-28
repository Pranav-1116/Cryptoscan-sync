import React, { useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiEstateTwin, apiEstateTwinSearch, apiEstateTwinImpact, apiEstateTwinSimulate, apiEstateTwinAsset,
  apiEstateTwinSnapshots, apiEstateTwinCapture, apiEstateTwinCompare, apiEstateTwinCryptoGraph, apiEstateTwinGraph,
  apiEstateTwinGraphLoadPlan, apiEstateTwinSimulations,
  apiEstateChanges, apiEstateChangesDetect, apiEstateChangeAcknowledge,
  apiEstateCatalog, apiEstateCatalogAssets, apiEstateCatalogAsset, apiEstateCryptoRegistry,
  EstateTwinOverview, EstateTwinSearchResult, EstateTwinImpact, EstateTwinSimulation, EstateTwinAssetView,
  EstateTwinSnapshotList, EstateTwinCompare, EstateTwinCryptoGraph, EstateTwinGraphExport,
  EstateTwinGraphLoad, EstateTwinSimulationList,
  EstateChangeFeed, EstateChangeEvent,
  EstateCatalogSummary, EstateCatalogAsset, EstateCatalogDetail, EstateCryptoRegistry,
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
  const twin = usePollingApi(apiEstateTwin, 60000);
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
  const [view, setView] = useState<"live" | "crypto" | "catalog" | "changes" | "history" | "graph">("live");
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
    const detail = await apiEstateCatalogAsset(identifier);
    if (detail.ok) setCatalogRecord(detail.data as EstateCatalogDetail);
    else setCatalogError("asset not in the catalogue — it may never have been observed");
  };

  /* The change feed: what moved between observations, and what that does not prove. */
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
  }, [view]);

  const TABS: Array<{ id: typeof view; label: string }> = [
    { id: "live", label: "Live estate" },
    { id: "crypto", label: "Crypto graph" },
    { id: "catalog", label: "Catalogue" },
    { id: "changes", label: "Changes" },
    { id: "history", label: "History & compare" },
    { id: "graph", label: "Graph export" },
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
            </div>

            <div>
              <div className="mono" style={{ fontSize: 10.5, color: "var(--cyan)" }}>COMPLETENESS</div>
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
                  {[...asset.relationships.outgoing, ...asset.relationships.incoming].slice(0, 8).map((item, index) => (
                    <div key={index} className="faint" style={{ fontSize: 10.5, marginTop: 3 }}>
                      <span className="mono" style={{ color: "var(--cyan)" }}>{item.predicate}</span>{" "}
                      {item.name ?? item.asset_id}{" "}
                      <span className="mono" style={{ fontSize: 9.5 }}>
                        ({item.basis ?? "no basis"} · {item.confidence ?? "UNKNOWN"})
                      </span>
                    </div>
                  ))}
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
                    {" "}(basis {edge.basis ?? "—"}, {edge.evidence_ids.length} evidence)
                  </span>
                </div>
              ))}
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

      {view === "graph" && (
        <div style={{ marginTop: 4 }}>
          {!exported && <div className="dim" style={{ fontSize: 11 }}>{error ?? "loading the graph export…"}</div>}
          {exported && (
            <>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Badge tone="violet">{exported.projection_id.slice(0, 12)}</Badge>
                <Badge tone="slate">{exported.counts.asset_nodes} asset nodes</Badge>
                <Badge tone="slate">{exported.counts.evidence_nodes} evidence nodes</Badge>
                <Badge tone="cyan">{exported.counts.relationships} edges</Badge>
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
