import { Link } from "react-router-dom";
import React, { useEffect, useRef, useState } from "react";
import { Badge, Bar, Ring } from "../components/ui";
import {
  apiCbomCoverage,
  apiCbomIngest,
  apiCbomPinSnapshot,
  apiCbomQuery,
  apiCbomScanSnapshots,
  apiCbomSnapshot,
  apiCbomSnapshotDiff,
  apiScansRecent,
} from "../lib/api";
import PrivateScope, { usePrivateScopeCurrent } from "../components/PrivateScope";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import CbomLegacyReview from "../components/CbomLegacyReview";
import HostEvidencePanel from "../components/HostEvidencePanel";
import PortfolioDependencyPanel from "../components/PortfolioDependencyPanel";
import { ICON_SM, IconCaretDown, IconCaretRight, IconComponent, IconSecurity, IconCloud, IconSearch, IconTarget } from "../components/icons";

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
          const matches: CbomItem[] = (qRes.data.matches || []).map((m: any) => ({
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

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "14px 16px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)", marginBottom: 16, flexWrap: "wrap", gap: 12 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)" }}><IconComponent size={16} style={{ color: "var(--accent)" }} /></span>
          <div>
            <div style={{ fontSize: 10, letterSpacing: .12, fontFamily: "var(--mono)", color: "var(--accent)" }}>CYCLONEDX 1.6 · LIVE QUERY · NO INFERENCE</div>
            <h1 style={{ fontSize: 22, fontWeight: 700, margin: "2px 0 2px", lineHeight: 1 }}>Cryptographic Bill of Materials</h1>
            <div style={{ fontSize: 12, color: "var(--dim)" }}>Cross-BOM identity spine — linked, conflicts and coverage at a glance</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          {!loading && components.length > 0 && <div style={{ display: "flex", alignItems: "center", gap: 8 }}><Ring pct={components.length ? linkedCount / components.length : 0} label={`${components.length ? Math.round((linkedCount / components.length) * 100) : 0}%`} sub="linked" tone="cyan" /><div style={{ fontSize: 11, color: "var(--dim)", lineHeight: 1.3 }}>{linkedCount} / {components.length} multi-BOM<br />{conflictCount ? <span style={{ color: "var(--red)" }}>{conflictCount} conflicts</span> : <span style={{ color: "var(--green)" }}>no conflicts</span>}</div></div>}
          <div style={{ display: "flex", gap: 8, flexDirection: "column" }}>
            <AuthenticatedDownload path="/api/v1/cbom/portfolio?fmt=cyclonedx16" filename="cryptoscan-cbom-1.6.json" className="btn outline" style={{ fontSize: 12, padding: "7px 12px", borderRadius: "var(--r)" }}>Export CycloneDX 1.6 JSON</AuthenticatedDownload>
            <Link to="/dependency-graph" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "7px 12px", borderRadius: "var(--r)", textAlign: "center" }}>View Dependency Graph</Link>
          </div>
        </div>
      </div>

      <section className="panel" aria-label="Import CBOM metadata" style={{ padding: 16, marginBottom: 16, borderTop: "2px solid var(--accent)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 8 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <IconCloud size={14} style={{ color: "var(--accent)" }} />
            <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Import CBOM metadata</h2>
            <Badge tone="slate">DECLARED</Badge><Badge tone="cyan">2 MiB cap</Badge>
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

      {offline && !loading && (
        <div className="panel" style={{ padding: "12px 14px", marginBottom: 14, border: "1px solid var(--amber)", borderLeft: "3px solid var(--amber)", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <IconTarget size={14} style={{ color: "var(--amber)" }} />
          <div style={{ fontSize: 12, color: "var(--amber)" }}><strong>Offline</strong> — no live query · table empty · no cache fallback</div>
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 12, marginBottom: 16 }}>
        <div className="panel" style={{ padding: "12px 14px", borderTop: "2px solid var(--line-strong)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: "var(--accent)", width: 6, height: 6, borderRadius: 99 }} />IDENTITIES</div>
          <div style={{ fontSize: 22, fontWeight: 800, margin: "4px 0 2px" }}>{loading ? "…" : components.length}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>Canonical spine</div>
          {!loading && components.length > 0 && <Bar value={1} tone="cyan" />}
        </div>
        <div className="panel" style={{ padding: "12px 14px", borderTop: "2px solid var(--cyan)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: "var(--cyan)", width: 6, height: 6, borderRadius: 99 }} />LINKED</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: "var(--cyan)", margin: "4px 0 2px" }}>{loading ? "…" : linkedCount}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>2+ BOMs · association</div>
          {!loading && <Bar value={components.length ? linkedCount / components.length : 0} tone="cyan" />}
        </div>
        <div className="panel" style={{ padding: "12px 14px", borderTop: conflictCount > 0 ? "2px solid var(--red)" : "2px solid var(--line-strong)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: conflictCount > 0 ? "var(--red)" : "var(--green)", width: 6, height: 6, borderRadius: 99 }} />CONFLICTS</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: conflictCount > 0 ? "var(--red)" : "var(--text)", margin: "4px 0 2px" }}>{loading ? "…" : conflictCount}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>{conflictCount > 0 ? "Value disagreements" : "No disagreements"}</div>
          {!loading && conflictCount > 0 && <Bar value={Math.min(1, conflictCount / Math.max(1, components.length))} tone="red" />}
        </div>
        <div className="panel" style={{ padding: "12px 14px", borderTop: "2px solid var(--accent)" }}>
          <div style={{ fontSize: 10, color: "var(--dim)", letterSpacing: .08, display: "flex", gap: 6, alignItems: "center" }}><span className="dot" style={{ background: "var(--accent)", width: 6, height: 6, borderRadius: 99 }} />COVERAGE</div>
          <div style={{ fontSize: 22, fontWeight: 800, color: "var(--accent)", margin: "4px 0 2px" }}>{loading ? "…" : coverage?.coverage_pct == null ? "—" : `${coverage.coverage_pct}%`}</div>
          <div style={{ fontSize: 11, color: "var(--dim)" }}>{coverage?.with_cbom ?? "—"} / {coverage?.systems ?? "—"} systems · scans only</div>
          {!loading && coverage?.coverage_pct != null && <Bar value={coverage.coverage_pct / 100} tone="cyan" />}
        </div>
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap", marginBottom: 12, padding: "10px 12px", background: "var(--panel)", border: "1px solid var(--line)", borderRadius: "var(--r)" }}>
        <div style={{ position: "relative", flex: "1", minWidth: 240, maxWidth: 420, display: "flex", alignItems: "center", gap: 8 }}>
          <IconSearch size={13} style={{ color: "var(--faint)" }} />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search identity, label, kind or BOM…" style={{ flex: 1, padding: "8px 12px", fontSize: 12.5, background: "var(--bg-2)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: "var(--r)", fontFamily: "var(--mono)" }} />
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {LINKAGE_FILTERS.map((r) => (
            <button key={r} onClick={() => setFilterLinkage(r)} className="btn sm" style={{ background: filterLinkage === r ? "var(--cyan)" : undefined, color: filterLinkage === r ? "var(--on-accent)" : undefined, fontWeight: filterLinkage === r ? 700 : 500, fontSize: 11, padding: "6px 10px" }}>{r}</button>
          ))}
        </div>
      </div>

      <div className="panel" style={{ padding: "14px 16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10, padding: "8px 10px", background: "var(--bg-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}><IconComponent size={14} style={{ color: "var(--accent)" }} /><span style={{ fontSize: 12, fontWeight: 700 }}>Identity inventory</span><Badge tone={components.length ? "cyan" : "slate"}>{filtered.length} / {components.length}</Badge>{conflictCount > 0 && <Badge tone="red">{conflictCount} conflicts</Badge>}{linkedCount > 0 && <Badge tone="cyan">{linkedCount} linked</Badge>}</div>
          <span style={{ fontSize: 11, color: "var(--dim)" }}>Tap row → observations · PQC sim</span>
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
          <div style={{ fontSize: "11.5px", color: "var(--faint)", marginTop: "12px" }}>
            {queryNote}
          </div>
        )}
      </div>

      <div className="panel" style={{ padding: 16, marginTop: 16, borderTop: "2px solid var(--violet)" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)" }}><IconSecurity size={14} style={{ color: "var(--violet)" }} /></span>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700 }}>Pinned Snapshots</h3>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>SHA-256 content-addressed · scan-bound · verbatim proof</div>
            </div>
            {snapshots.length > 0 && <Badge tone="violet">{snapshots.length} pins</Badge>}
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
