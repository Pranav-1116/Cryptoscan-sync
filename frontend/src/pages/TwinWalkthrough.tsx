import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge } from "../components/ui.jsx";
import TwinGraphCanvas from "../components/TwinGraphCanvas.jsx";
import {
  apiEstateChanges, apiEstateIntel, apiEstateTwin, apiEstateTwinAsset, apiEstateTwinSearch,
  type EstateChangeFeed, type EstateCryptoIntel, type EstateTwinAssetView, type EstateTwinOverview,
} from "../lib/api.js";

/* ─── The thirteen-screen walkthrough, in one canvas ─────────────────────────
   Spec §9 lists thirteen screens. This build has had all thirteen as separate
   routes for a while; what it did not have is the specification's *walkthrough* —
   one canvas where an investigator carries a single asset through all thirteen
   investigations in order, instead of remembering which of thirteen pages holds
   which fact.

   The rule that makes this more than a menu: **every step renders live content
   about the selected asset**, read from the twin's own endpoints, and says so
   when it cannot. A step whose read failed prints the failure — never a zero, and
   never "nothing found". Each step also links to its own full screen, because
   this canvas summarises thirteen investigations; it does not replace them.

   Deliberately absent: nothing on this page writes. The simulation step shows the
   facts a scenario would read and hands the run to `/simulation`, where the
   engine's copy-and-project contract lives.
──────────────────────────────────────────────────────────────────────────── */

type AssetNeighbour = EstateTwinAssetView["relationships"]["outgoing"][number];

interface Step {
  id: string;
  n: number;
  title: string;
  route: string;
  purpose: string;
}

export const WALKTHROUGH_STEPS: Step[] = [
  { id: "overview", n: 1, title: "Twin Overview", route: "/digital-twin", purpose: "Overall estate and coverage" },
  { id: "assets", n: 2, title: "Asset Explorer", route: "/assets", purpose: "Search all discovered assets" },
  { id: "relationships", n: 3, title: "Relationship Graph", route: "/graph", purpose: "Explore dependencies" },
  { id: "crypto", n: 4, title: "Cryptographic Graph", route: "/crypto", purpose: "Algorithm, certificate and provider facts" },
  { id: "network", n: 5, title: "Network Topology", route: "/network", purpose: "Endpoints, paths and network relationships" },
  { id: "hardware", n: 6, title: "Hardware & HSM", route: "/hardware", purpose: "Hardware, firmware and key custody" },
  { id: "vendor", n: 7, title: "Vendor Dependencies", route: "/vendor", purpose: "Vendors, products and deployments" },
  { id: "evidence", n: 8, title: "Evidence Explorer", route: "/evidence", purpose: "Why a fact or relationship exists" },
  { id: "history", n: 9, title: "Historical Twin", route: "/estate-twin", purpose: "Compare previous snapshots" },
  { id: "drift", n: 10, title: "Drift Analysis", route: "/drift", purpose: "Investigate changes" },
  { id: "blast", n: 11, title: "Blast Radius", route: "/what-if", purpose: "Identify affected systems" },
  { id: "simulation", n: 12, title: "Simulation Lab", route: "/simulation", purpose: "Test hypothetical changes" },
  { id: "pqc", n: 13, title: "PQC Impact", route: "/pqc", purpose: "Identify quantum migration blockers" },
];

/* Relationship families that belong to a screen. A neighbour is placed by its own
   asset *type*, never by guessing from the asset's name — an asset whose type the
   twin does not know is counted as unplaced, not filed under "network" because the
   word "edge" appeared in it. */
const NETWORK_TYPES = new Set(["NETWORK_DEVICE", "NETWORK_ENDPOINT", "HOST", "CONTAINER", "LOAD_BALANCER", "FIREWALL", "VPN"]);
const HARDWARE_TYPES = new Set(["HSM", "HARDWARE", "FIRMWARE", "KMS_KEY", "KMS"]);
const VENDOR_TYPES = new Set(["VENDOR", "PRODUCT", "LIBRARY", "PACKAGE"]);

function neighbours(view: EstateTwinAssetView | null): AssetNeighbour[] {
  if (!view) return [];
  return [
    ...view.relationships.outgoing.map((edge) => ({ ...edge, direction: "out" as const })),
    ...view.relationships.incoming.map((edge) => ({ ...edge, direction: "in" as const })),
  ];
}

function ofTypes(rows: AssetNeighbour[], types: Set<string>): AssetNeighbour[] {
  return rows.filter((edge) => types.has(String(edge.type ?? "").toUpperCase()));
}

/* An event's `means` lives on its individual changes, not on the event: the event
   is the bundle, and each claim carries what it does not prove. Printing the first
   one is honest; inventing an event-level summary would not be. */
function changeMeaning(event: EstateChangeFeed["events"][number]): string | null {
  for (const change of event.changes ?? []) {
    if (change.means) return change.means;
  }
  return null;
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 12, padding: "6px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
      <span style={{ fontSize: 11, color: "var(--faint)" }}>{label}</span>
      <span style={{ fontSize: 11, fontWeight: 600, fontFamily: mono ? "var(--mono)" : undefined, textAlign: "right" }}>{value}</span>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <p style={{ margin: 0, fontSize: 11.5, color: "var(--faint)", background: "var(--panel-2)", border: "1px dashed var(--line)", borderRadius: "var(--r)", padding: 12, lineHeight: 1.5 }}>
      {children}
    </p>
  );
}

function EdgeTable({ rows }: { rows: AssetNeighbour[] }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl" style={{ width: "100%" }}>
        <thead><tr><th>Relationship</th><th>Other asset</th><th>Type</th><th>Basis</th></tr></thead>
        <tbody>
          {rows.map((edge, i) => (
            <tr key={`${edge.predicate}|${edge.asset_id}|${i}`}>
              <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{edge.direction === "in" ? "← " : ""}{edge.predicate}</td>
              <td style={{ fontSize: 11 }}>{edge.name ?? edge.asset_id}</td>
              <td style={{ fontSize: 11, color: "var(--faint)" }}>{edge.type ?? "—"}</td>
              <td style={{ fontSize: 11, color: "var(--faint)" }}>{edge.basis ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function TwinWalkthrough() {
  const [step, setStep] = useState<string>("overview");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<EstateTwinAssetView["asset"][]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [overview, setOverview] = useState<EstateTwinOverview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [view, setView] = useState<EstateTwinAssetView | null>(null);
  const [viewError, setViewError] = useState<string | null>(null);
  const [changes, setChanges] = useState<EstateChangeFeed | null>(null);
  const [changesError, setChangesError] = useState<string | null>(null);
  const [intel, setIntel] = useState<EstateCryptoIntel | null>(null);
  const [intelError, setIntelError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void (async () => {
      const twin = await apiEstateTwin();
      if (!live) return;
      if (twin.ok) setOverview(twin.data as EstateTwinOverview);
      else setOverviewError("the twin overview could not be read — that is not 'the estate holds nothing'");
      const drift = await apiEstateChanges();
      if (!live) return;
      if (drift.ok) setChanges(drift.data as EstateChangeFeed);
      else setChangesError("the change feed could not be read — that is not 'nothing changed'");
      const crypto = await apiEstateIntel();
      if (!live) return;
      if (crypto.ok) setIntel(crypto.data as EstateCryptoIntel);
      else setIntelError("crypto intel could not be read — that is not 'no PQC exposure'");
    })();
    return () => { live = false; };
  }, []);

  const search = async () => {
    const needle = query.trim();
    if (!needle) return;
    setResults([]);
    const found = await apiEstateTwinSearch(needle);
    if (!found.ok || !found.data) {
      setViewError("the twin search could not be read — this is not 'no such asset'");
      return;
    }
    setResults(found.data.assets ?? []);
  };

  const open = async (ref: string) => {
    setSelected(ref);
    setView(null);
    setViewError(null);
    const result = await apiEstateTwinAsset(ref);
    if (result.ok) setView(result.data as EstateTwinAssetView);
    else setViewError("the twin could not be read for this asset — that is not 'it has no evidence'");
  };

  const rows = useMemo(() => neighbours(view), [view]);
  const network = useMemo(() => ofTypes(rows, NETWORK_TYPES), [rows]);
  const hardware = useMemo(() => ofTypes(rows, HARDWARE_TYPES), [rows]);
  const vendors = useMemo(() => ofTypes(rows, VENDOR_TYPES), [rows]);
  const otherEdges = useMemo(
    () => rows.filter((edge) => !network.includes(edge) && !hardware.includes(edge) && !vendors.includes(edge)),
    [rows, network, hardware, vendors],
  );
  const active = WALKTHROUGH_STEPS.find((entry) => entry.id === step) ?? WALKTHROUGH_STEPS[0];

  const assetChanges = useMemo(() => {
    if (!changes || !selected) return [];
    return (changes.events ?? []).filter((event) =>
      (event.changes ?? []).some((change) => String(change.subject ?? "").includes(selected)));
  }, [changes, selected]);

  const observedRange = useMemo(() => {
    const stamps = (view?.evidence.records ?? [])
      .map((record) => record.observed_at)
      .filter((stamp): stamp is string => Boolean(stamp))
      .sort();
    if (stamps.length === 0) return null;
    return { first: stamps[0], last: stamps[stamps.length - 1] };
  }, [view]);

  const pqc = useMemo(() => {
    if (!intel || !selected) return null;
    const affected = (intel.pqc?.affected_assets ?? []).filter((item) =>
      String(item.asset_id ?? "").includes(selected));
    const blockers = (intel.pqc?.vendor_bound_blockers ?? []).filter((item) =>
      String(item.asset_id ?? "").includes(selected));
    if (affected.length === 0 && blockers.length === 0) return null;
    return { affected, blockers };
  }, [intel, selected]);

  /* A step is answered from whatever has been read. If nothing has been read, the
     step says that; a panel of zeros over an unread twin is a claim about an estate
     nobody looked at. */
  function body() {
    switch (active.id) {
      case "overview": {
        const summary = (overview?.summary ?? {}) as Record<string, unknown>;
        const completeness = overview?.completeness;
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {overviewError && <Empty>{overviewError}</Empty>}
            {overview && Object.keys(summary).length === 0 && <Empty>The overview returned no summary figures for this estate.</Empty>}
            {Object.entries(summary).slice(0, 10).map(([key, value]) => (
              <Row key={key} label={key.replace(/_/g, " ")} value={typeof value === "object" ? JSON.stringify(value) : String(value)} />
            ))}
            {completeness && (
              <Row label="twin completeness" value={`${completeness.overall_percent ?? "—"}% · ${completeness.overall_label}`} />
            )}
            {completeness?.weakest_dimension && (
              <Empty>
                Weakest dimension: <b>{completeness.weakest_dimension.dimension}</b>
                {completeness.weakest_dimension.percent != null ? ` at ${completeness.weakest_dimension.percent}%` : ""} — {completeness.weakest_dimension.reason}
                {completeness.is_posture_score ? "" : ". This is coverage, not a posture score."}
              </Empty>
            )}
            {overview?.projection_id && <Row label="projection id" value={overview.projection_id.slice(0, 16) + "…"} mono />}
          </div>
        );
      }
      case "assets":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <input
                aria-label="Find an asset"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") void search(); }}
                placeholder="asset id, name or type"
                style={{ flex: 1, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg)", color: "var(--text)", fontSize: 12 }}
              />
              <button onClick={() => void search()} style={{ padding: "7px 12px", borderRadius: "var(--r)", border: "1px solid var(--violet)", background: "var(--violet)", color: "#fff", fontSize: 12, fontWeight: 700, cursor: "pointer" }}>
                Find
              </button>
            </div>
            {results.length === 0 && <Empty>No search run yet — the canvas keeps the asset you pick for all thirteen steps.</Empty>}
            {results.map((asset) => (
              <button
                key={asset.asset_id}
                onClick={() => void open(asset.asset_id)}
                style={{ textAlign: "left", padding: "8px 10px", borderRadius: "var(--r)", border: `1px solid ${selected === asset.asset_id ? "var(--violet)" : "var(--line)"}`, background: "var(--panel-2)", color: "var(--text)", cursor: "pointer", fontSize: 11.5 }}
              >
                <b>{asset.name}</b> <span style={{ fontFamily: "var(--mono)", color: "var(--faint)" }}>{asset.asset_id}</span>
                {asset.type ? ` · ${asset.type}` : ""}
                {asset.environment ? ` · ${asset.environment}` : ""}
              </button>
            ))}
            {view && (
              <div style={{ display: "grid", gap: 6, marginTop: 4 }}>
                <Row label="owner" value={view.asset.owner ?? "not asserted"} />
                <Row label="environment" value={view.asset.environment ?? "not asserted"} />
                <Row label="location" value={view.asset.location ?? "not asserted"} />
                <Row label="placement" value={view.placement.placed ? "placed in the estate chart" : "unplaced — the chart has nothing to hang it on"} />
              </div>
            )}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "relationships":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 — the walkthrough carries one asset through every step.</Empty>}
            {view && <Row label="relationships the twin holds" value={String(view.relationships.count)} />}
            {view && rows.length === 0 && (
              <Empty>This asset has no recorded relationships. That is a fact about the twin's evidence, not proof the asset is isolated.</Empty>
            )}
            {view && rows.length > 0 && <EdgeTable rows={rows} />}
            {viewError && <Empty>{viewError}</Empty>}
            <div style={{ marginTop: 4 }}>
              <TwinGraphCanvas />
            </div>
          </div>
        );
      case "crypto":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read its cryptographic facts.</Empty>}
            {view && (
              <>
                <Row label="artifacts" value={String(view.crypto.artifacts.length)} />
                <Row label="observed in use" value={String(view.crypto.observed.length)} />
                <Row label="capability only" value={String(view.crypto.capability_only.length)} />
                {Object.entries(view.crypto.by_usage_state ?? {}).map(([state, count]) => (
                  <Row key={state} label={state.replace(/_/g, " ").toLowerCase()} value={String(count)} />
                ))}
                {view.crypto.note && <Empty>{view.crypto.note}</Empty>}
              </>
            )}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "network":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read what it reaches over the network.</Empty>}
            {view && network.length === 0 && (
              <Empty>The twin holds no network-typed relationship for this asset — that is not "the asset is not on a network". {otherEdges.length} other relationships are recorded in step 3.</Empty>
            )}
            {view && network.length > 0 && <EdgeTable rows={network} />}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "hardware":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read its hardware and key custody.</Empty>}
            {view && hardware.length === 0 && (
              <Empty>The twin records no HSM, KMS or hardware relationship for this asset. An application can use crypto without a key store the estate can see — that gap is the finding.</Empty>
            )}
            {view && hardware.length > 0 && <EdgeTable rows={hardware} />}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "vendor":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read its vendor dependencies.</Empty>}
            {view && vendors.length === 0 && (
              <Empty>No vendor, product or library relationship is recorded for this asset.</Empty>
            )}
            {view && vendors.length > 0 && <EdgeTable rows={vendors} />}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "evidence":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read the evidence behind it.</Empty>}
            {view && view.unknown.no_evidence && (
              <Empty>No evidence record backs this asset. It exists in the twin because something asserted it — the assertion is not stored here, and that is worth chasing.</Empty>
            )}
            {view && (
              <>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <Badge tone="slate">{view.evidence.count} records</Badge>
                  {Object.entries(view.evidence.by_type ?? {}).map(([type, count]) => (
                    <Badge key={type} tone="violet">{type} · {count}</Badge>
                  ))}
                  {view.evidence.strongest && <Badge tone="green">strongest {view.evidence.strongest}</Badge>}
                </div>
                <div style={{ overflowX: "auto" }}>
                  <table className="tbl" style={{ width: "100%" }}>
                    <thead><tr><th>Type</th><th>Collector</th><th>Source</th><th>Observed</th><th>Hash</th></tr></thead>
                    <tbody>
                      {view.evidence.records.slice(0, 12).map((record) => (
                        <tr key={record.evidence_id}>
                          <td style={{ fontSize: 11 }}>{record.evidence_type}</td>
                          <td style={{ fontSize: 11, color: "var(--faint)" }}>{record.collector ?? "—"}</td>
                          <td style={{ fontSize: 11 }}>{record.source ?? "—"}</td>
                          <td style={{ fontSize: 11 }}>{record.observed_at ? new Date(record.observed_at).toLocaleString() : "—"}</td>
                          <td style={{ fontFamily: "var(--mono)", fontSize: 10.5 }} title={record.hash}>{(record.hash ?? "").slice(0, 12)}…</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {view.evidence.records.length > 12 && <Empty>{view.evidence.records.length - 12} further records are held; the Evidence Explorer lists them all.</Empty>}
                {view.unknown.unresolved_relationships.length > 0 && (
                  <Empty>{view.unknown.unresolved_relationships.length} candidate relationship(s) were refused, not drawn: a refusal is a reason, not an absence.</Empty>
                )}
                {view.unknown.conflicts.length > 0 && (
                  <Empty>{view.unknown.conflicts.length} conflict(s) between records — the twin keeps both and says so rather than picking a winner.</Empty>
                )}
              </>
            )}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "history":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read how long the twin has observed it.</Empty>}
            {overview?.projection_id && <Row label="current projection" value={overview.projection_id.slice(0, 16) + "…"} mono />}
            {view && observedRange && (
              <>
                <Row label="first observation" value={new Date(observedRange.first).toLocaleString()} />
                <Row label="last observation" value={new Date(observedRange.last).toLocaleString()} />
              </>
            )}
            {view && !observedRange && <Empty>None of this asset's evidence records carries a timestamp, so the twin cannot date it.</Empty>}
            <Empty>
              Snapshots are keyed by the evidence they read, so this canvas does not invent a timeline: the chain screen compares stored snapshots and shows what moved between them.
            </Empty>
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "drift":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {changesError && <Empty>{changesError}</Empty>}
            {!selected && <Empty>Pick an asset in step 2 to read the changes that name it.</Empty>}
            {selected && changes && (
              <Row label={`events naming this asset (of ${changes.count})`} value={String(assetChanges.length)} />
            )}
            {selected && changes && assetChanges.length === 0 && (
              <Empty>No stored change event names this asset. That means the twin has not recorded a movement in it — not that its configuration never moved.</Empty>
            )}
            {assetChanges.map((event) => (
              <div key={event.event_id} style={{ padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
                <div style={{ fontSize: 11.5, fontWeight: 700 }}>{event.headline}</div>
                <div style={{ fontSize: 10.5, color: "var(--faint)" }}>
                  {event.severity} · {new Date(event.last_detected_at ?? event.first_detected_at ?? "").toLocaleString()}
                  {event.acknowledged ? " · acknowledged" : " · unacknowledged"}
                </div>
                {changeMeaning(event) && (
                  <div style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 4 }}>{changeMeaning(event)}</div>
                )}
              </div>
            ))}
          </div>
        );
      case "blast":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to read what a change to it would reach.</Empty>}
            {view && (
              <>
                <Row label="depth" value={String(view.neighbourhood.depth)} />
                <Row label="assets reached" value={String(view.neighbourhood.reached)} />
                {view.neighbourhood.truncated && (
                  <Empty>The traversal stopped at its depth limit. {view.neighbourhood.reached} assets are listed; more may lie beyond the cut, and this canvas will not imply it has seen them.</Empty>
                )}
                {view.neighbourhood.reached === 0 && <Empty>Nothing is reachable from this asset through recorded relationships.</Empty>}
                {view.neighbourhood.assets.length > 0 && (
                  <div style={{ overflowX: "auto" }}>
                    <table className="tbl" style={{ width: "100%" }}>
                      <thead><tr><th>Reached</th><th>Type</th><th>Hops</th></tr></thead>
                      <tbody>
                        {view.neighbourhood.assets.slice(0, 25).map((asset) => (
                          <tr key={asset.asset_id}>
                            <td style={{ fontSize: 11 }}>{asset.name ?? asset.asset_id}</td>
                            <td style={{ fontSize: 11, color: "var(--faint)" }}>{asset.type ?? "—"}</td>
                            <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{asset.hops}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {view.neighbourhood.assets.length > 25 && <Empty>{view.neighbourhood.assets.length - 25} more are in the report; the Blast Radius screen lists them.</Empty>}
              </>
            )}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "simulation":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {!view && <Empty>Pick an asset in step 2 to see the facts a scenario would read.</Empty>}
            {view && (
              <>
                <Row label="facts a scenario could edit" value={String(view.crypto.artifacts.length)} />
                <Row label="observed in use" value={String(view.crypto.observed.length)} />
                <Row label="capability only (never edited first)" value={String(view.crypto.capability_only.length)} />
                <Empty>
                  Nothing is run here. A scenario edits a deep copy and projects the BOMs from the copy; the Simulation Lab runs one and reports the diff, and this canvas does not shortcut that.
                </Empty>
              </>
            )}
            {viewError && <Empty>{viewError}</Empty>}
          </div>
        );
      case "pqc":
        return (
          <div style={{ display: "grid", gap: 8 }}>
            {intelError && <Empty>{intelError}</Empty>}
            {!selected && <Empty>Pick an asset in step 2 to read its quantum exposure.</Empty>}
            {selected && intel && !pqc && (
              <Empty>No quantum-vulnerable artifact is recorded for this asset in the twin's inventory. Algorithms this build does not recognise are counted separately as UNKNOWN, not as safe.</Empty>
            )}
            {pqc?.affected.map((item) => (
              <Row key={String(item.asset_id)} label="vulnerable algorithms" value={(item.algorithms ?? []).join(", ")} />
            ))}
            {pqc?.blockers.map((item) => (
              <Row key={`blocker-${String(item.asset_id)}`} label="vendor-bound blocker" value={(item.algorithms ?? []).join(", ")} />
            ))}
            {intel?.pqc?.meaning && <Empty>{intel.pqc.meaning}</Empty>}
            {selected && intel && (intel.pqc?.pqc_algorithms_present ?? []).length > 0 && (
              <Empty>PQC algorithms present in this estate: {intel.pqc.pqc_algorithms_present.join(", ")} — present is not the same as deployed.</Empty>
            )}
          </div>
        );
      default:
        return null;
    }
  }

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--violet) 12%, transparent)", border: "1px solid var(--violet)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--violet)", letterSpacing: ".06em" }}>
          <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--violet)" }} /> OUTPUT · DIGITAL TWIN · THIRTEEN-SCREEN WALKTHROUGH
        </div>
        <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em" }}>One asset, thirteen investigations</h1>
        <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 760 }}>
          The specification's walkthrough, on one canvas: pick an asset and carry it through all thirteen screens in
          order. Each step reads the same twin the full screen reads, and says so when it could not — a panel of
          zeros over an unread twin would be a claim about an estate nobody looked at.
        </p>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "260px minmax(0, 1fr)", gap: 14, alignItems: "start" }}>
        <Panel title="The thirteen steps" sub={`${WALKTHROUGH_STEPS.length} screens · one order`} style={{ padding: "10px 12px" }}>
          <ol style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", gap: 4 }}>
            {WALKTHROUGH_STEPS.map((entry) => {
              const isActive = entry.id === active.id;
              return (
                <li key={entry.id}>
                  <button
                    onClick={() => setStep(entry.id)}
                    aria-current={isActive ? "step" : undefined}
                    style={{ width: "100%", display: "flex", gap: 8, alignItems: "baseline", textAlign: "left", padding: "6px 8px", borderRadius: "var(--r)", cursor: "pointer", border: `1px solid ${isActive ? "var(--violet)" : "transparent"}`, background: isActive ? "color-mix(in srgb, var(--violet) 12%, transparent)" : "transparent", color: "var(--text)" }}
                  >
                    <span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: isActive ? "var(--violet)" : "var(--faint)", minWidth: 16 }}>{String(entry.n).padStart(2, "0")}</span>
                    <span style={{ fontSize: 12, fontWeight: isActive ? 700 : 500 }}>{entry.title}</span>
                  </button>
                </li>
              );
            })}
          </ol>
        </Panel>

        <Panel
          title={`${active.n}. ${active.title}`}
          sub={active.purpose}
          style={{ padding: "12px 14px" }}
        >
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 10 }}>
            <Badge tone="violet">step {active.n} of {WALKTHROUGH_STEPS.length}</Badge>
            {selected && <Badge tone="slate">selected asset {selected}</Badge>}
            <Link to={active.route} style={{ marginLeft: "auto", fontSize: 11, color: "var(--violet)", fontWeight: 700 }}>
              open the full {active.title} screen →
            </Link>
          </div>
          {body()}
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 14, gap: 8 }}>
            <button
              onClick={() => setStep(WALKTHROUGH_STEPS[Math.max(0, active.n - 2)].id)}
              disabled={active.n === 1}
              style={{ padding: "6px 12px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel-2)", color: "var(--text)", fontSize: 11.5, cursor: active.n === 1 ? "not-allowed" : "pointer", opacity: active.n === 1 ? 0.5 : 1 }}
            >
              ← previous
            </button>
            <button
              onClick={() => setStep(WALKTHROUGH_STEPS[Math.min(WALKTHROUGH_STEPS.length - 1, active.n)].id)}
              disabled={active.n === WALKTHROUGH_STEPS.length}
              style={{ padding: "6px 12px", borderRadius: "var(--r)", border: "1px solid var(--violet)", background: "var(--violet)", color: "#fff", fontSize: 11.5, fontWeight: 700, cursor: active.n === WALKTHROUGH_STEPS.length ? "not-allowed" : "pointer", opacity: active.n === WALKTHROUGH_STEPS.length ? 0.5 : 1 }}
            >
              next step →
            </button>
          </div>
        </Panel>
      </div>
    </div>
  );
}
