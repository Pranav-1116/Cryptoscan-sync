import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Badge, Bar, Panel, Ring } from "../components/ui";
import { usePollingApi } from "../lib/apiUi.jsx";
import {
  apiCbomCoverage,
  apiCbomIngest,
  apiCbomPinSnapshot,
  apiCbomQuery,
  apiCbomScanSnapshots,
  apiCbomSnapshot,
  apiCbomSnapshotDiff,
  apiScansRecent,
  apiTechBomLive,
  fmtSnapshotId,
  CbomQueryMatch,
  CbomQuerySummary,
  TechBomState,
} from "../lib/api";
import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import CbomLegacyReview from "../components/CbomLegacyReview";
import HostEvidencePanel from "../components/HostEvidencePanel";
import PortfolioDependencyPanel from "../components/PortfolioDependencyPanel";
import { ICON_SM, IconCaretDown, IconCaretRight, IconCloud, IconComponent, IconCrypto, IconInfo, IconSearch, IconSecurity, IconTarget } from "../components/icons";

/* One row per canonical identity from the unified cross-BOM query.
 * Every field below is echoed from the backend response — nothing is
 * inferred, defaulted or scored on the client. */
interface CbomItem {
  identity: string;
  kind: string;
  label: string;
  boms: string[];
  bom_count: number;
  linked: boolean;
  conflicts: unknown[];
  variations: unknown[];
  present_in: { bom: string; ref: string; values: Record<string, unknown> }[];
}

const LINKAGE_FILTERS = ["ALL", "LINKED", "UNLINKED", "CONFLICTS"] as const;

export default function Cbom() {
  return <PrivateScope><CbomContent /></PrivateScope>;
}

function CbomContent() {
  const current = usePrivateScopeCurrent();
  const selectionGeneration = useRef(0);
  const viewRequest = useRef(0);
  const diffRequest = useRef(0);
  const [refresh, setRefresh] = useState(0);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importName, setImportName] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState("");
  const [importReceipt, setImportReceipt] = useState<any>(null);

  async function importDocument(event: React.FormEvent) {
    event.preventDefault();
    if (!current() || !importFile || !importName.trim() || importBusy) return;
    setImportError(""); setImportReceipt(null);
    if (importFile.size > 1024 * 1024) {
      setImportError("File exceeds the 1 MiB import limit."); return;
    }
    setImportBusy(true);
    let submitted = false;
    try {
      const bom = JSON.parse(await importFile.text());
      if (!current()) return; // Do not submit a draft parsed in an old estate.
      if (!bom || Array.isArray(bom) || typeof bom !== "object") throw new Error("Expected a JSON object");
      submitted = true;
      const result = await apiCbomIngest(bom, importName.trim());
      if (!current()) return;
      if (result.source !== "live" || !result.data?.system?.id || !result.data?.document_sha256) {
        setImportError(`Import not confirmed (${result.error || "invalid receipt"}). Check document/schema and permissions; reload current inventory before retrying. No request is automatically replayed.`);
        return;
      }
      setImportReceipt(result.data);
      setRefresh((value) => value + 1);
    } catch {
      if (current()) setImportError(submitted
        ? "Import outcome unconfirmed. Reload current inventory before retrying."
        : "Invalid JSON document. Choose a CycloneDX JSON object; nothing was submitted.");
    } finally {
      if (current()) setImportBusy(false);
    }
  }
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [search, setSearch] = useState("");
  const [filterLinkage, setFilterLinkage] = useState<string>("ALL");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<any>(null);
  const [components, setComponents] = useState<CbomItem[]>([]);
  const [queryNote, setQueryNote] = useState<string>("");
  // Estate-wide arithmetic from /cbom/query's `summary` — the backend counts
  // every canonical identity, so the headline cards never relabel a filtered
  // subset as the estate total.
  const [querySummary, setQuerySummary] = useState<CbomQuerySummary | null>(null);

  // pinned snapshots (§4.4): one scan's pinned, content-addressed CBOM
  // renderings — the live query above regenerates; these do not
  const [scans, setScans] = useState<{ scan_id: string; status: string; target_location: string }[]>([]);
  const [selectedScan, setSelectedScan] = useState<string>("");
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [snapshotsNote, setSnapshotsNote] = useState<string>("");
  const [snapshotsLoaded, setSnapshotsLoaded] = useState(false);
  const [signOnPin, setSignOnPin] = useState(false);
  const [pinBusy, setPinBusy] = useState(false);
  const [pinResult, setPinResult] = useState<string | null>(null);
  const [openSnapshot, setOpenSnapshot] = useState<any>(null);
  // §5 (round 62): two-pin comparison — the repeated-scan comparability
  // product workflow. "asset_key" joins by the identity spine (estate
  // drift, evidence churn ignored); "bom_ref" is exact per-scan evidence
  // identity (same-scan mutations visible).
  const [diffFor, setDiffFor] = useState<string | null>(null);
  const [diffAgainst, setDiffAgainst] = useState<string | null>(null);
  const [diffData, setDiffData] = useState<any>(null);
  const [diffKeyBy, setDiffKeyBy] = useState<"asset_key" | "bom_ref">("asset_key");
  const [diffBusy, setDiffBusy] = useState(false);

  async function loadSnapshots(scanId: string, generation = selectionGeneration.current) {
    const res = await apiCbomScanSnapshots(scanId);
    if (!current() || generation !== selectionGeneration.current) return;
    if (res.source === "live" && res.data) {
      setSnapshots(Array.isArray(res.data.snapshots) ? res.data.snapshots : []);
      setSnapshotsNote(typeof res.data.note === "string" ? res.data.note : "");
      setSnapshotsLoaded(true);
    } else {
      setSnapshots([]);
      setSnapshotsNote("");
      setSnapshotsLoaded(false);
    }
    setOpenSnapshot(null);
    setDiffFor(null);
    setDiffAgainst(null);
    setDiffData(null);
  }

  useEffect(() => {
    let alive = true;
    async function loadScanChoices() {
      const res = await apiScansRecent(20);
      if (!alive || !current()) return;
      if (res.source === "live" && res.data && Array.isArray(res.data.scans)) {
        setScans(res.data.scans);
      }
    }
    loadScanChoices();
    return () => { alive = false; };
  }, []);

  async function pinSnapshot() {
    if (!current() || !selectedScan || pinBusy) return;
    const generation = selectionGeneration.current;
    setPinBusy(true);
    setPinResult(null);
    const res = await apiCbomPinSnapshot(selectedScan, signOnPin);
    if (!current() || generation !== selectionGeneration.current) return;
    setPinBusy(false);
    if (res.source === "live" && res.data) {
      setPinResult(res.data.note || (res.data.created ? "Snapshot pinned." : "Returned the existing pin."));
      await loadSnapshots(selectedScan, generation);
    } else {
      setPinResult("Pin outcome unconfirmed — reload the selected scan’s pins before retrying.");
    }
  }

  async function loadDiff(targetId: string, againstId: string, keyBy: "asset_key" | "bom_ref") {
    const generation = selectionGeneration.current;
    const request = ++diffRequest.current;
    setDiffBusy(true);
    try {
      const res = await apiCbomSnapshotDiff(targetId, againstId, keyBy);
      if (!current() || generation !== selectionGeneration.current || request !== diffRequest.current) return;
      setDiffFor(targetId);
      setDiffAgainst(againstId);
      if (res.source === "live" && res.data) {
        setDiffData(res.data);
      } else {
        setDiffData({ error: "Diff unavailable — the comparison could not be computed." });
      }
    } finally {
      if (current() && generation === selectionGeneration.current && request === diffRequest.current) setDiffBusy(false);
    }
  }

  async function viewSnapshot(id: string) {
    const generation = selectionGeneration.current;
    const request = ++viewRequest.current;
    if (openSnapshot?.snapshot_id === id) {
      setOpenSnapshot(null);
      return;
    }
    const res = await apiCbomSnapshot(id);
    if (!current() || generation !== selectionGeneration.current || request !== viewRequest.current) return;
    if (res.source === "live" && res.data) {
      setOpenSnapshot(res.data);
    } else {
      setOpenSnapshot({ snapshot_id: id, integrity: "UNAVAILABLE", integrity_note: "Snapshot could not be loaded." });
    }
  }

  useEffect(() => {
    let alive = true;
    async function loadCbom() {
      setLoading(true);
      setOffline(false); setComponents([]); setCoverage(null); setQueryNote("");
      setQuerySummary(null);
      try {
        const [qRes, covRes] = await Promise.all([
          apiCbomQuery(),
          apiCbomCoverage(),
        ]);

        if (!alive || !current()) return;

        // The unified query is the row source. An unreachable or failed
        // query must NOT fall back to fabricated rows — the table stays
        // empty and the page says so.
        if (qRes.source === "live" && qRes.data) {
          const matches: CbomItem[] = (qRes.data.matches || []).map((m: CbomQueryMatch) => ({
            identity: m.identity,
            kind: m.kind,
            label: m.label,
            boms: m.boms || [],
            bom_count: m.bom_count ?? (m.boms || []).length,
            linked: !!m.linked,
            conflicts: m.conflicts || [],
            variations: m.variations || [],
            present_in: m.present_in || [],
          }));
          setComponents(matches);
          setQuerySummary(qRes.data.summary ?? null);
          if (typeof qRes.data.note === "string") setQueryNote(qRes.data.note);
        } else {
          setOffline(true);
        }

        if (covRes.source === "live" && covRes.data) {
          setCoverage(covRes.data);
        }
      } catch (err) {
        console.error("Failed to load CBOM query:", err);
        if (alive && current()) setOffline(true);
      } finally {
        if (alive && current()) setLoading(false);
      }
    }

    loadCbom();
    return () => { alive = false; };
  }, [refresh]);

  const filtered = components.filter((c) => {
    const haystack = `${c.identity} ${c.label} ${c.kind} ${c.boms.join(" ")}`.toLowerCase();
    const matchesSearch = haystack.includes(search.toLowerCase());
    const matchesLinkage =
      filterLinkage === "ALL" ||
      (filterLinkage === "LINKED" && c.linked) ||
      (filterLinkage === "UNLINKED" && !c.linked) ||
      (filterLinkage === "CONFLICTS" && c.conflicts.length > 0);
    return matchesSearch && matchesLinkage;
  });

  const linkedCount = components.filter((c) => c.linked).length;
  const conflictCount = components.reduce((n, c) => n + c.conflicts.length, 0);

  const bomBadge = (bom: string) =>
    ({ cbom: "green", techbom: "cyan", vbom: "cyan", hbom: "orange", nbom: "orange" } as Record<string, any>)[bom] || "neutral";

  /* Same shared Technology BOM state as SBOM / HBOM / VBOM — this page reads
   * the materialized CBOM layer and the query's own summary; it never derives
   * crypto counts of its own. */
  const live = usePollingApi(apiTechBomLive, 15000);
  const techState = (live.data ?? null) as TechBomState | null;
  const cryptoComponents = techState?.layers?.cbom?.components ?? [];
  const cryptoTotal = techState?.layers?.cbom?.count ?? cryptoComponents.length;
  const estateTotal = techState?.total_components ?? 0;
  const cryptoShare = estateTotal ? cryptoTotal / estateTotal : 0;

  const byAlgorithm = useMemo(() => {
    const counts: Record<string, number> = {};
    cryptoComponents.forEach((component) => {
      const algorithm = String(component.algorithm || "").trim();
      if (!algorithm) return; // a blank field is not an "unknown" algorithm
      counts[algorithm] = (counts[algorithm] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [cryptoComponents]);

  const identities = querySummary?.identities ?? null;
  const linkedTotal = querySummary?.linked ?? null;
  const conflictTotal = querySummary?.conflict_count ?? null;
  const linkedPct = identities && linkedTotal != null ? linkedTotal / identities : 0;
  const coveragePct = coverage?.coverage_pct ?? null;
  const heroConflict = (conflictTotal ?? 0) > 0;
  const count = (value: number | null | undefined) => (loading ? "…" : value == null ? "—" : String(value));


  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid var(--accent)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--accent)" }} /> BOMS · CBOM · CRYPTOGRAPHIC ASSETS
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconCrypto size={18} /></span>
            Cryptographic Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Every <b style={{ color: "var(--text)" }}>algorithm, key and protocol</b> in the estate — the CBOM layer of the unified asset model, linked through the cross-BOM identity spine. <span style={{ color: "var(--accent)" }}>One asset model</span>, materialized for crypto-agility.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>CycloneDX 1.6</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>LIVE QUERY · NO INFERENCE</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>{cryptoTotal} crypto assets · snapshot {fmtSnapshotId(techState?.snapshot_id).slice(0, 16)} · v{techState?.state_version ?? 0}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 190, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={linkedPct} label={identities == null ? "—" : `${Math.round(linkedPct * 100)}%`} sub="linked" tone={identities ? "cyan" : "slate"} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>IDENTITY SPINE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 150, lineHeight: 1.4 }}>
                {identities == null ? "No live query result" : `${linkedTotal ?? 0} / ${identities} in 2+ BOMs`}
              </div>
              <div style={{ fontSize: 11, marginTop: 2, color: identities == null ? "var(--faint)" : heroConflict ? "var(--red)" : "var(--green)" }}>
                {identities == null ? "no live query" : heroConflict ? "review disagreements" : "no conflicts"}
              </div>
              <div style={{ marginTop: 6 }}><Bar value={linkedPct} tone={identities ? "cyan" : "slate"} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 190 }}>
            <AuthenticatedDownload path="/api/v1/cbom/portfolio?fmt=cyclonedx16" filename="cryptoscan-cbom-1.6.json" className="btn primary" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Export CycloneDX 1.6 JSON</AuthenticatedDownload>
            <Link to="/dependency-graph" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Dependency graph →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{techState?.fingerprint ? `SHA ${techState.fingerprint.slice(0, 8)}…` : "no hash yet"}</span>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCrypto size={12} /> CBOM COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{techState ? cryptoTotal : "…"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Crypto-asset layer</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={cryptoShare} tone="cyan" />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{estateTotal ? `${Math.round(cryptoShare * 100)}% of ${estateTotal} total assets` : "estate total —"}</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--line-strong)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>IDENTITIES</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{count(identities)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Canonical spine</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--panel-2)", border: "1px solid var(--line)", color: "var(--slate)" }}><IconComponent size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={identities ? 1 : 0} tone={identities ? "cyan" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Estate-wide count — never the filtered rows</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>LINKED IDENTITIES</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: linkedTotal ? "var(--cyan)" : undefined }}>{count(linkedTotal)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>2+ BOMs · association</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: linkedTotal ? "color-mix(in srgb, var(--cyan) 14%, transparent)" : "var(--panel-2)", border: `1px solid ${linkedTotal ? "var(--cyan)" : "var(--line)"}`, color: linkedTotal ? "var(--cyan)" : "var(--faint)" }}><IconSearch size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={linkedPct} tone={linkedTotal ? "cyan" : "slate"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>{identities ? `${Math.round(linkedPct * 100)}% of ${identities} identities` : "no live query"}</div>
          </div>
        </div>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${heroConflict ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>CONFLICTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1, color: heroConflict ? "var(--red)" : undefined }}>{count(conflictTotal)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{conflictTotal == null ? "No live query result" : heroConflict ? "Value disagreements" : "No disagreements"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: heroConflict ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid ${heroConflict ? "var(--red)" : "var(--green)"}`, color: heroConflict ? "var(--red)" : "var(--green)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={identities ? Math.min(1, (conflictTotal ?? 0) / Math.max(1, identities)) : 0} tone={heroConflict ? "red" : "green"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Cross-BOM value disagreements — never averaged</div>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Top algorithms" sub="by crypto-asset count — what the estate actually uses" style={{ padding: "14px 16px" }}>
          {byAlgorithm.length ? byAlgorithm.map(([algorithm, n]) => (
            <div key={algorithm} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
              <span style={{ width: 130, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{algorithm}</span>
              <div style={{ flex: 1 }}><Bar value={cryptoTotal ? n / cryptoTotal : 0} tone="cyan" /></div>
              <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 28, textAlign: "right" }}>{n}</span>
            </div>
          )) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No CBOM components yet</div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>From CBOM layer · algorithm field · {cryptoTotal} assets</div>
        </Panel>
        <Panel title="CBOM coverage" sub="scanned systems reporting cryptography" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: coveragePct ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)", border: `2px solid ${coveragePct ? "var(--accent)" : "var(--line)"}`, display: "grid", placeItems: "center", color: coveragePct ? "var(--accent)" : "var(--faint)", fontSize: 18, fontWeight: 800 }}>{coveragePct == null ? "—" : `${coveragePct}%`}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Cryptography coverage</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{coverage?.with_cbom ?? "—"} of {coverage?.systems ?? "—"} systems report a CBOM</div>
              <div style={{ fontSize: 10, color: coveragePct ? "var(--accent)" : "var(--faint)", marginTop: 2 }}>{coveragePct == null ? "Unknown" : "scans only"}</div>
            </div>
          </div>
          <div style={{ height: 8, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${Math.min(100, Math.max(0, Number(coveragePct) || 0))}%`, background: "var(--accent)" }} />
            <div style={{ flex: 1, background: "var(--panel-2)" }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>● with CBOM</span><span>● no CBOM</span></div>
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Imports are excluded; this is not discovery completeness{coverage?.message ? ` — ${coverage.message}` : "."}</div>
        </Panel>
        <Panel title="Integrity" sub="snapshot + audit trail" style={{ padding: "14px 16px" }}>
          <div style={{ display: "grid", gap: 8 }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Snapshot</span><span style={{ fontFamily: "var(--mono)", fontWeight: 600 }}>{fmtSnapshotId(techState?.snapshot_id).slice(0, 20)}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Version</span><Badge tone="cyan">v{techState?.state_version ?? 0}</Badge></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Crypto assets</span><span style={{ fontFamily: "var(--mono)" }}>{techState ? cryptoTotal : "…"}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Identities</span><span style={{ fontFamily: "var(--mono)" }}>{count(identities)}</span></div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}><span style={{ color: "var(--faint)" }}>Environment</span><Badge tone="slate">{techState?.environment || "—"}</Badge></div>
            <div style={{ padding: "8px 10px", background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontSize: 11, fontFamily: "var(--mono)", wordBreak: "break-all" }}>{techState?.fingerprint || "— no fingerprint yet"}</div>
          </div>
        </Panel>
      </div>

      {offline && !loading && (
        <div className="panel" style={{ padding: "12px 14px", marginBottom: 14, border: "1px solid var(--amber)", borderLeft: "3px solid var(--amber)", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <IconTarget size={14} style={{ color: "var(--amber)" }} />
          <div style={{ fontSize: 12, color: "var(--amber)" }}><strong>Offline</strong> — no live query · table empty · no cache fallback</div>
        </div>
      )}

      <div className="panel" style={{ padding: 0, overflow: "hidden", marginBottom: 18 }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> Identity Inventory</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>CBOM · cross-BOM spine · <span style={{ color: "var(--accent)" }}>every row is a canonical identity, echoed from the query</span></p>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", padding: "4px 8px" }}>
              <IconSearch size={12} style={{ color: "var(--faint)" }} />
              <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="filter identity, kind, BOM…" style={{ background: "transparent", border: 0, color: "var(--text)", fontSize: 12, outline: "none", width: 160, fontFamily: "var(--mono)" }} />
            </div>
            <Badge tone={components.length ? "cyan" : "slate"}>{filtered.length} / {components.length}</Badge>
            {conflictCount > 0 && <Badge tone="red">{conflictCount} conflicts</Badge>}
            {linkedCount > 0 && <Badge tone="cyan">{linkedCount} linked</Badge>}
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap", padding: "8px 18px", borderBottom: "1px solid var(--line)" }}>
          {LINKAGE_FILTERS.map((r) => (
            <button key={r} onClick={() => setFilterLinkage(r)} className="btn sm" style={{ background: filterLinkage === r ? "var(--cyan)" : undefined, color: filterLinkage === r ? "var(--on-accent)" : undefined, fontWeight: filterLinkage === r ? 700 : 500, fontSize: 11, padding: "5px 10px" }}>{r}</button>
          ))}
          <span style={{ fontSize: 11, color: "var(--faint)", marginLeft: "auto" }}>Tap a row → per-BOM observations · PQC sim</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th style={{ width: "36px" }}></th>
                <th>Identity & Label</th>
                <th>Kind</th>
                <th>Source BOMs</th>
                <th>Linkage</th>
                <th>Conflicts</th>
              </tr>
            </thead>
            <tbody>
      <section className="panel" aria-label="Import CBOM metadata" style={{ padding: 16, marginBottom: 16, borderTop: "2px solid var(--accent)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <IconCloud size={14} style={{ color: "var(--accent)" }} />
            <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Import CBOM metadata</h2>
            <Badge tone="slate">DECLARED</Badge><Badge tone="cyan">1 MiB cap</Badge>
          </div>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>Declared ≠ observed · not coverage · timestamps preserved</span>
        </div>
        <p style={{ color: "var(--dim)", fontSize: 12, margin: "0 0 10px" }}>Analyst/CISO import — refreshes matching declarations; missing components not auto-retired.</p>
        <form onSubmit={importDocument} style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "end" }}>
          <label>System name<br /><input aria-label="Import system name" value={importName} maxLength={200} required
            disabled={importBusy} onChange={(event) => setImportName(event.target.value)} /></label>
          <label>CycloneDX JSON (1 MiB maximum)<br /><input aria-label="CBOM JSON file" type="file" accept=".json,application/json"
            disabled={importBusy} onChange={(event) => { setImportFile(event.target.files?.[0] || null); setImportError(""); setImportReceipt(null); }} /></label>
          <button className="btn primary" type="submit" disabled={importBusy || !importFile || !importName.trim()}>
            {importBusy ? "Importing metadata…" : "Import metadata"}
          </button>
        </form>
        {importError && <p role="alert">{importError}</p>}
        {importReceipt && <div role="status" style={{ marginTop: 12 }}>
          <p>Saved metadata: {importReceipt.imported} assets for {importReceipt.system.name}. Not a scan or approval.</p>
          <p style={{ overflowWrap: "anywhere" }}>Document SHA-256: {importReceipt.document_sha256}</p>
          <AuthenticatedDownload path={`/api/v1/cbom/system/${encodeURIComponent(importReceipt.system.id)}?fmt=cyclonedx16`}
            filename="imported-cbom-1.6.json" className="btn outline">Export persisted metadata</AuthenticatedDownload>
        </div>}
      </section>

      <HostEvidencePanel />
      <CbomLegacyReview refresh={refresh} onCommitted={() => setRefresh(value => value + 1)} />

              {filtered.map((item) => {
                const isExpanded = expandedRow === item.identity;
                return (
                  <React.Fragment key={item.identity}>
                    <tr
                      onClick={() => setExpandedRow(isExpanded ? null : item.identity)}
                      style={{ cursor: "pointer", background: isExpanded ? "color-mix(in srgb, var(--accent) 5%, transparent)" : undefined }}
                    >
                      <td style={{ color: "var(--cyan)", fontWeight: 700, fontSize: "14px" }}>
                        {isExpanded ? <IconCaretDown className="ico" size={ICON_SM} /> : <IconCaretRight className="ico" size={ICON_SM} />}
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: "var(--text)", fontFamily: "var(--mono)", fontSize: "13px" }}>{item.identity}</div>
                        <div style={{ fontSize: "11px", color: "var(--dim)" }}>{item.label}</div>
                      </td>
                      <td>
                        <span style={{ fontSize: "12px", fontFamily: "var(--mono)" }}>{item.kind}</span>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                          {item.boms.map((b) => (
                            <Badge key={b} tone={bomBadge(b)}>{b}</Badge>
                          ))}
                        </div>
                      </td>
                      <td>
                        {item.linked ? (
                          <Badge tone="cyan">Linked · {item.bom_count} BOMs</Badge>
                        ) : (
                          <Badge tone="neutral">Single source</Badge>
                        )}
                      </td>
                      <td>
                        {item.conflicts.length > 0 ? (
                          <Badge tone="red">{item.conflicts.length} conflict{item.conflicts.length === 1 ? "" : "s"}</Badge>
                        ) : (
                          <span style={{ fontSize: "12px", color: "var(--dim)" }}>None</span>
                        )}
                      </td>
                    </tr>

                    {/* Expandable per-BOM observation detail — real refs and values */}
                    {isExpanded && (
                      <tr>
                        <td colSpan={6} style={{ padding: "16px 20px 20px 48px", background: "var(--bg-2)", borderBottom: "1px solid var(--line)" }}>
                          <div style={{ fontSize: "12px", fontWeight: 600, color: "var(--faint)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "10px" }}>
                            Observations per BOM
                          </div>
                          <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                            {item.present_in.map((obs, sIdx) => (
                              <div
                                key={sIdx}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  justifyContent: "space-between",
                                  padding: "8px 12px",
                                  background: "var(--panel)",
                                  border: "1px solid var(--line)",
                                  borderRadius: "var(--r)",
                                  fontSize: "12.5px"
                                }}
                              >
                                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                                  <span style={{ color: "var(--dim)" }}>├──</span>
                                  <span style={{ fontWeight: 600, color: "var(--text)" }}>{obs.bom}</span>
                                  <span style={{ fontSize: "11px", background: "var(--bg-2)", padding: "2px 6px", borderRadius: "var(--r)", color: "var(--dim)" }}>{obs.ref}</span>
                                </div>
                                <span style={{ fontFamily: "var(--mono)", fontSize: "11.5px", color: "var(--dim)" }}>
                                  {Object.keys(obs.values || {}).length > 0
                                    ? Object.entries(obs.values).map(([k, v]) => `${k}=${String(v)}`).join(" · ")
                                    : "no comparable values"}
                                </span>
                              </div>
                            ))}
                            {item.variations.length > 0 && (
                              <div style={{ fontSize: "11.5px", color: "var(--amber)" }}>
                                {item.variations.length} value variation{item.variations.length === 1 ? "" : "s"} within a single BOM — not conflicts.
                              </div>
                            )}
                          </div>

                          <div style={{ display: "flex", gap: "10px", marginTop: "14px", justifyContent: "flex-end" }}>
                            <Link to="/what-if" className="btn sm primary" style={{ textDecoration: "none" }}>
                              Run PQC Migration Simulation
                            </Link>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              {filtered.length === 0 && !loading && (
                <tr>
                  <td colSpan={6} style={{ textAlign: "center", padding: "40px", color: "var(--dim)" }}>
                    <div style={{ fontSize: "15px", fontWeight: 600, color: "var(--text)", marginBottom: "4px" }}>
                      No CBOM identities found
                    </div>
                    <div style={{ fontSize: "13px", maxWidth: "480px", margin: "0 auto 16px" }}>
                      {offline
                        ? "No live BOM query result is available."
                        : coverage?.message || "Register systems, then initiate network, host, or container discovery scans."}
                    </div>
                    <Link to="/scanners" className="btn primary" style={{ textDecoration: "none" }}>
                      Launch Discovery Scan
                    </Link>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {queryNote && !loading && (
          <div style={{ fontSize: "11.5px", color: "var(--faint)", padding: "10px 18px", borderTop: "1px solid var(--line)" }}>
            {queryNote}
          </div>
        )}
        <div style={{ padding: "10px 18px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 8, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <Link to="/live-asset-intelligence" style={{ color: "var(--accent)" }}>Technology BOM →</Link>
          <span>·</span>
          <Link to="/dependency-graph" style={{ color: "var(--cyan)" }}>Dependency graph →</Link>
          <span>·</span>
          <Link to="/what-if" style={{ color: "var(--violet)" }}>PQC what-if →</Link>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>ONE asset model · four layers</span>
        </div>
      </div>

      <div className="panel" style={{ padding: 16, marginTop: 16, borderTop: "2px solid var(--accent)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)" }}><IconSecurity size={14} style={{ color: "var(--accent)" }} /></span>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}>Pinned Snapshots</h3>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>SHA-256 content-addressed · scan-bound · verbatim proof</div>
            </div>
            {snapshots.length > 0 && <Badge tone="cyan">{snapshots.length} pins</Badge>}
          </div>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
            <select
              aria-label="Scan"
              value={selectedScan}
              onChange={(e) => {
                selectionGeneration.current++;
                viewRequest.current++; diffRequest.current++;
                setSelectedScan(e.target.value);
                setSnapshots([]); setSnapshotsLoaded(false); setSnapshotsNote("");
                setOpenSnapshot(null); setDiffFor(null); setDiffAgainst(null); setDiffData(null);
                setPinBusy(false); setDiffBusy(false); setPinResult(null);
                if (e.target.value) void loadSnapshots(e.target.value);
                else { setSnapshots([]); setSnapshotsLoaded(false); }
              }}
              style={{ fontSize: 12.5, padding: "6px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--bg-2)", color: "var(--text)", maxWidth: 320 }}
            >
              <option value="">{scans.length ? "Select a scan…" : "No scans available"}</option>
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.scan_id.slice(0, 8)}… · {s.target_location || s.status}
                </option>
              ))}
            </select>
            <label style={{ fontSize: 12, color: "var(--dim)", display: "flex", gap: 4, alignItems: "center" }}>
              <input type="checkbox" checked={signOnPin} onChange={(e) => setSignOnPin(e.target.checked)} />
              sign on pin
            </label>
            <button
              className="btn outline"
              onClick={() => void pinSnapshot()}
              disabled={!selectedScan || pinBusy}
              style={{ fontSize: 12, padding: "7px 14px", borderRadius: "var(--r)" }}
            >
              {pinBusy ? "Pinning…" : "Pin Snapshot"}
            </button>
          </div>
        </div>

        {pinResult && (
          <p style={{ margin: "8px 0 0", fontSize: 12, color: "var(--cyan)" }}>{pinResult}</p>
        )}

        {!selectedScan && (
          <p style={{ margin: "12px 0 0", fontSize: 12.5, color: "var(--dim)" }}>
            Select a scan to pin or inspect its snapshots.
          </p>
        )}
        {selectedScan && !snapshotsLoaded && (
          <p style={{ margin: "12px 0 0", fontSize: 12.5, color: "var(--dim)" }}>
            Snapshots unavailable for this scan — nothing is pinned or shown.
          </p>
        )}
        {selectedScan && snapshotsLoaded && snapshots.length === 0 && (
          <p style={{ margin: "12px 0 0", fontSize: 12.5, color: "var(--dim)" }}>
            No snapshots pinned for this scan yet — pinning freezes the current rendering for export and audit.
          </p>
        )}

        {snapshots.length > 0 && (
          <div style={{ overflowX: "auto", marginTop: "12px" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>Content Hash</th>
                  <th>Signed</th>
                  <th>Generator</th>
                  <th>Components</th>
                  <th>Pinned At</th>
                  <th>Pinned By</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {snapshots.map((s: any, index: number) => (
                  <React.Fragment key={s.snapshot_id}>
                    <tr>
                      <td>
                        <span style={{ fontFamily: "var(--mono)", fontSize: 12 }}>{String(s.content_hash || "").slice(0, 16)}…</span>
                      </td>
                      <td>
                        <Badge variant={s.signed && s.signed !== "none" ? "success" : "neutral"}>
                          {String(s.signed || "none").toUpperCase()}
                        </Badge>
                      </td>
                      <td><span style={{ fontSize: 12 }}>{s.generator || "—"}</span></td>
                      <td><span style={{ fontSize: 12 }}>{s.component_count ?? "—"}</span></td>
                      <td><span style={{ fontSize: 12, color: "var(--dim)" }}>{s.snapshotted_at ? new Date(s.snapshotted_at).toLocaleString() : "—"}</span></td>
                      <td><span style={{ fontSize: 12 }}>{s.created_by || "—"}</span></td>
                      <td>
                        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                          <button
                            className="btn sm"
                            onClick={() => void viewSnapshot(s.snapshot_id)}
                            style={{ fontSize: 11.5, padding: "4px 10px" }}
                          >
                            {openSnapshot?.snapshot_id === s.snapshot_id ? "Hide" : "Verify & View"}
                          </button>
                          {snapshots.length > 1 && index < snapshots.length - 1 && (
                            <button
                              className="btn sm outline"
                              disabled={diffBusy}
                              onClick={() => {
                                if (diffFor === s.snapshot_id) {
                                  setDiffFor(null);
                                  setDiffData(null);
                                } else {
                                  void loadDiff(s.snapshot_id, snapshots[index + 1].snapshot_id, diffKeyBy);
                                }
                              }}
                              style={{ fontSize: 11.5, padding: "4px 10px" }}
                              title={"Compare this pin against the previous (older) pin of the same scan — computed from the two pinned payloads, never stored."}
                            >
                              {diffFor === s.snapshot_id ? "Hide Diff" : "Diff vs Prev Pin"}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {diffFor === s.snapshot_id && diffData && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-2)", borderTop: "1px dashed var(--line)" }}>
                          <div style={{ padding: "10px 4px", display: "grid", gap: 8 }}>
                            <div style={{ fontSize: 12.5, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                              <strong style={{ fontSize: 12 }}>PIN COMPARISON</strong>
                              {diffData.error ? (
                                <span style={{ color: "var(--red)" }}>{diffData.error}</span>
                              ) : (
                                <>
                                  <Badge variant={(diffData.diff?.components?.added?.length || 0) > 0 ? "success" : "neutral"}>
                                    +{diffData.diff?.components?.added?.length ?? 0} added
                                  </Badge>
                                  <Badge variant={(diffData.diff?.components?.removed?.length || 0) > 0 ? "danger" : "neutral"}>
                                    −{diffData.diff?.components?.removed?.length ?? 0} removed
                                  </Badge>
                                  <Badge variant={(diffData.diff?.components?.changed?.length || 0) > 0 ? "warn" : "neutral"}>
                                    {diffData.diff?.components?.changed?.length ?? 0} changed
                                  </Badge>
                                  <Badge variant="neutral">
                                    {diffData.diff?.components?.unchanged ?? 0} unchanged
                                  </Badge>
                                  {diffData.diff?.identical && <Badge variant="success">IDENTICAL</Badge>}
                                  <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
                                    {(["asset_key", "bom_ref"] as const).map((mode) => (
                                      <button
                                        key={mode}
                                        className={`btn sm ${diffKeyBy === mode ? "" : "outline"}`}
                                        disabled={diffBusy}
                                        onClick={() => {
                                          setDiffKeyBy(mode);
                                          if (diffAgainst) void loadDiff(s.snapshot_id, diffAgainst, mode);
                                        }}
                                        style={{ fontSize: 11, padding: "3px 8px" }}
                                        title={mode === "asset_key"
                                          ? "Join components by the identity spine — stable across re-scans; evidence churn is not estate drift."
                                          : "Exact per-scan evidence identity — same-scan mutations visible, cross-scan shows full evidence turnover."}
                                      >
                                        {mode}
                                      </button>
                                    ))}
                                  </div>
                                </>
                              )}
                            </div>
                            {!diffData.error && (
                              <div style={{ fontSize: 11.5, color: "var(--dim)" }}>
                                Target {String(diffData.target?.snapshot_id || s.snapshot_id).slice(0, 10)}… vs baseline {String(diffData.baseline?.snapshot_id || diffAgainst || "").slice(0, 10)}… · keyed by <span style={{ fontFamily: "var(--mono)" }}>{diffData.diff?.components?.key_by || diffKeyBy}</span>
                                {diffKeyBy === "asset_key" ? " (identity spine — same crypto fact across scans is one row; observation-position churn ignored)" : " (per-scan evidence ids — every re-scan mints new rows by design)"}
                                {" "}· computed from the two pinned payloads, never stored.
                              </div>
                            )}
                            {!diffData.error && (diffData.diff?.components?.added?.length > 0 || diffData.diff?.components?.removed?.length > 0) && (
                              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 8 }}>
                                <div>
                                  <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 4 }}>Added (in the newer pin only)</div>
                                  {(diffData.diff?.components?.added || []).map((c: any) => (
                                    <div key={c.key || c["bom-ref"]} style={{ fontSize: 12 }}>
                                      <span style={{ color: "var(--green)" }}>+</span> {c.name || c["bom-ref"]} <span style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(c["bom-ref"] || "").slice(0, 12)}…</span>
                                    </div>
                                  ))}
                                </div>
                                <div>
                                  <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 4 }}>Removed (in the baseline only)</div>
                                  {(diffData.diff?.components?.removed || []).map((c: any) => (
                                    <div key={c.key || c["bom-ref"]} style={{ fontSize: 12 }}>
                                      <span style={{ color: "var(--red)" }}>−</span> {c.name || c["bom-ref"]} <span style={{ color: "var(--faint)", fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(c["bom-ref"] || "").slice(0, 12)}…</span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {!diffData.error && (diffData.diff?.components?.changed?.length > 0) && (
                              <div>
                                <div style={{ fontSize: 11.5, color: "var(--dim)", marginBottom: 4 }}>Changed on surviving components</div>
                                {(diffData.diff?.components?.changed || []).map((c: any) => (
                                  <div key={c.key || c["bom-ref"]} style={{ fontSize: 12, marginBottom: 4 }}>
                                    <strong>{c["bom-ref"]}</strong>
                                    <ul style={{ margin: "2px 0 0 18px", padding: 0 }}>
                                      {(c.changes || []).map((ch: any) => (
                                        <li key={ch.path} style={{ fontSize: 11.5 }}>
                                          <span style={{ fontFamily: "var(--mono)" }}>{ch.path}</span>:{" "}
                                          <span style={{ color: "var(--red)" }}>{String(ch.before)}</span> → <span style={{ color: "var(--green)" }}>{String(ch.after)}</span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                    {openSnapshot?.snapshot_id === s.snapshot_id && (
                      <tr>
                        <td colSpan={7} style={{ background: "var(--bg-2)" }}>
                          <div style={{ padding: "10px 4px", display: "grid", gap: 6 }}>
                            <div style={{ fontSize: 12.5, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                              <Badge variant={openSnapshot.integrity === "OK" ? "success" : openSnapshot.integrity === "MISMATCH" ? "danger" : "neutral"}>
                                INTEGRITY {String(openSnapshot.integrity || "UNKNOWN").toUpperCase()}
                              </Badge>
                              <span style={{ color: "var(--dim)" }}>{openSnapshot.integrity_note}</span>
                            </div>
                            <div style={{ fontSize: 12, color: "var(--dim)" }}>
                              Served verbatim — never regenerated. Verify the scan's evidence chain:{" "}
                              <span style={{ fontFamily: "var(--mono)" }}>{openSnapshot.scan_verify_path}</span>
                            </div>
                            <details>
                              <summary style={{ fontSize: 12, cursor: "pointer", color: "var(--cyan)" }}>Pinned document ({Array.isArray(openSnapshot.payload?.components) ? openSnapshot.payload.components.length : "?"} components)</summary>
                              <pre style={{ fontSize: 11, maxHeight: 320, overflow: "auto", fontFamily: "var(--mono)", color: "var(--text)" }}>
                                {JSON.stringify(openSnapshot.payload, null, 2)}
                              </pre>
                            </details>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
            {snapshotsNote && (
              <div style={{ fontSize: "11.5px", color: "var(--faint)", marginTop: "10px" }}>{snapshotsNote}</div>
            )}
          </div>
        )}
      </div>

      <PortfolioDependencyPanel />
    </div>
  );
}
