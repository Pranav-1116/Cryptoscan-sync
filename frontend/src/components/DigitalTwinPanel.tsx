import React, { useState } from "react";
import { Panel, Badge } from "./ui.jsx";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiEstateTwin, apiEstateTwinSearch, apiEstateTwinImpact, apiEstateTwinSimulate, apiEstateTwinAsset,
  EstateTwinOverview, EstateTwinSearchResult, EstateTwinImpact, EstateTwinSimulation, EstateTwinAssetView,
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

  return (
    <Panel
      title="Digital twin — the model the six BOMs are projected from"
      sub="placement, description completeness, blast radius and simulation; a simulation runs on a copy and says so"
      className="mt"
    >
      {!doc && !error && (
        <div className="dim" style={{ fontSize: 12 }}>
          {twin.error ? "no stored estate discovery yet — the twin is NOT_OBSERVED, not empty" : "loading the twin…"}
        </div>
      )}

      {doc && (
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

          {error && <div className="dim" style={{ fontSize: 11.5, marginTop: 8, color: "var(--red)" }}>{error}</div>}

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
    </Panel>
  );
}
