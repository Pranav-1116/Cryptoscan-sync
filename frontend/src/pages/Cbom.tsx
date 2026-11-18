import { Link } from "react-router-dom";
import BomCrossNav from "../components/BomCrossNav";
import { CanonicalDetailLink } from "../components/AssetDetail";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Badge, Bar, Panel, Ring, Drawer } from "../components/ui";
import { usePollingApi, useApi } from "../lib/apiUi.jsx";
import {
  apiCbomWorkspaceOverview, apiCbomWorkspaceAssets, apiCbomWorkspaceAssetDetail,
  apiCbomWorkspaceAlgorithms, apiCbomWorkspaceLibraries, apiCbomWorkspaceCertificates,
  apiCbomWorkspaceKeys, apiCbomWorkspaceOperations, apiCbomWorkspaceProtocols,
  apiCbomWorkspacePqc, apiCbomWorkspaceDependencies, apiCbomWorkspaceEvidence,
  apiCbomWorkspaceHistory, apiCbomWorkspaceExport, type CbomCryptoAssetRow,
} from "../lib/api.js";
import {
  apiCbomCoverage,
  apiCbomIngest,
  apiCbomPinSnapshot,
  apiCbomQuery,
  apiCbomScanSnapshots,
  apiCbomSnapshot,
  apiCbomSnapshotDiff,
  apiNetworkTlsScan,
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

const CBOM_TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "CBOM Overview" },
  { id: "assets", label: "Cryptographic Asset Inventory" },
  { id: "algorithms", label: "Algorithm Intelligence" },
  { id: "libraries", label: "Crypto Library & Provider Inventory" },
  { id: "certificates", label: "Certificate & PKI Inventory" },
  { id: "keys", label: "Key Metadata Inventory" },
  { id: "operations", label: "Cryptographic Operations" },
  { id: "protocols", label: "TLS / SSH / IPsec Cryptography" },
  { id: "pqc", label: "PQC Readiness" },
  { id: "dependencies", label: "Crypto Dependencies" },
  { id: "evidence", label: "Evidence & Provenance" },
  { id: "history", label: "CBOM History" },
  { id: "export", label: "Export & Validation" },
];

/* A read that did not return is never an inventory of zero records. */
function WsState({ read, noun, children }: {
  read: { data: Record<string, unknown> | null; running: boolean; source: string; detail?: string | null };
  noun: string;
  children: React.ReactNode;
}) {
  if (read.running && !read.data) return <p className="faint" style={{ fontSize: 12 }}>Reading the {noun}…</p>;
  if (read.source !== "live" || read.data == null)
    return (
      <Panel title={`${noun} not read`} sub={read.source === "live" ? "the read returned nothing" : "the control plane did not answer"}>
        <p role="status" style={{ margin: 0, fontSize: 12, color: "var(--amber)" }}>
          {read.source === "live"
            ? `The ${noun} read returned nothing — nothing is claimed here.`
            : `The ${noun} could not be read${read.detail ? ` — ${read.detail}` : ""}. An unread inventory is not an empty one.`}
        </p>
      </Panel>
    );
  return <>{children}</>;
}

function WsTable({ head, rows, colSpan }: { head: string[]; rows: React.ReactNode[]; colSpan: number }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table className="tbl" style={{ width: "100%" }}>
        <thead><tr>{head.map((h) => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {rows.length ? rows : (
            <tr><td colSpan={colSpan} style={{ padding: 26, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>
              <div style={{ fontWeight: 600, color: "var(--text)" }}>Nothing stored yet</div>
              <div style={{ fontSize: 11.5, marginTop: 4 }}>Empty rows here mean no stored observations — not a healthy zero.</div>
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function UsageBadge({ usage }: { usage: { usage_state: string; basis: string } }) {
  const tone = usage.usage_state === "operation_observed" ? "green"
    : usage.usage_state === "configuration_observed" ? "amber" : "slate";
  return <Badge tone={tone}>{usage.usage_state}</Badge>;
}

function EvidenceBadge({ status }: { status: string }) {
  const tone = status === "MEASURED" ? "green" : status === "CONTRADICTED" ? "red"
    : status === "INFERRED" ? "amber" : status === "IMPORTED" ? "violet" : "slate";
  return <Badge tone={tone}>{status}</Badge>;
}

function PqcBadge({ family }: { family: string }) {
  const tone = family === "MIGRATION_RELEVANT" ? "amber" : family === "QUANTUM_RESISTANT" ? "violet" : "slate";
  return <Badge tone={tone}>{family}</Badge>;
}

export default function Cbom() {
  return <PrivateScope><CbomContent /></PrivateScope>;
}

function CbomContent() {
  const [wsParams, setWsParams] = useSearchParams();
  const active = CBOM_TABS.some((t) => t.id === wsParams.get("tab")) ? wsParams.get("tab") as string : "overview";
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
      <BomCrossNav current="CBOM" />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--accent)" }} /> BOMS · CBOM · CRYPTOGRAPHIC ASSETS
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconCrypto size={18} /></span>
            Cryptographic Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Every algorithm, key and protocol in the estate.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
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

      <CbomNetworkCollect />

      <div role="tablist" aria-label="CBOM sections" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "2px 0 16px" }}>
        {CBOM_TABS.map((t) => (
          <button key={t.id} role="tab" aria-selected={active === t.id} title={t.label}
            onClick={() => setWsParams({ tab: t.id })}
            style={{
              fontSize: 11, padding: "6px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${active === t.id ? "var(--accent)" : "var(--line-strong)"}`,
              background: active === t.id ? "color-mix(in srgb, var(--accent) 14%, transparent)" : "var(--panel-2)",
              color: active === t.id ? "var(--accent)" : "var(--dim)", fontFamily: "var(--mono)", letterSpacing: ".03em",
            }}>{t.label}</button>
        ))}
      </div>

      {active === "overview" && (<>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCrypto size={12} /> CBOM COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{techState ? cryptoTotal : "…"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Crypto-asset layer</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", color: "var(--accent)" }}><IconTarget size={16} /></span>
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
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: linkedTotal ? "color-mix(in srgb, var(--cyan) 14%, transparent)" : "var(--panel-2)", border: `1px solid color-mix(in srgb, ${linkedTotal ? "var(--cyan)" : "var(--line)"} 35%, var(--line))`, color: linkedTotal ? "var(--cyan)" : "var(--faint)" }}><IconSearch size={16} /></span>
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
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: heroConflict ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid color-mix(in srgb, ${heroConflict ? "var(--red)" : "var(--green)"} 35%, var(--line))`, color: heroConflict ? "var(--red)" : "var(--green)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <Bar value={identities ? Math.min(1, (conflictTotal ?? 0) / Math.max(1, identities)) : 0} tone={heroConflict ? "red" : "green"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Cross-BOM value disagreements</div>
          </div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Top algorithms" sub="By asset count" style={{ padding: "14px 16px" }}>
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
            <Badge tone="slate">DECLARED</Badge>
          </div>
        </div>
        <form onSubmit={importDocument} style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "end" }}>
          <label>System name<br /><input aria-label="Import system name" value={importName} maxLength={200} required
            disabled={importBusy} onChange={(event) => setImportName(event.target.value)} /></label>
          <label>CycloneDX JSON (max 1 MiB)<br /><input aria-label="CBOM JSON file" type="file" accept=".json,application/json"
            disabled={importBusy} onChange={(event) => { setImportFile(event.target.files?.[0] || null); setImportError(""); setImportReceipt(null); }} /></label>
          <button className="btn primary" type="submit" disabled={importBusy || !importFile || !importName.trim()}>
            {importBusy ? "Importing metadata…" : "Import metadata"}
          </button>
        </form>
        {importError && <p role="alert">{importError}</p>}
        {importReceipt && <div role="status" style={{ marginTop: 12 }}>
          <p>Saved metadata: {importReceipt.imported} assets for {importReceipt.system.name}. </p>
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
            <span style={{ width: 32, height: 32, borderRadius: 8, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))" }}><IconSecurity size={14} style={{ color: "var(--accent)" }} /></span>
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
            <span title={"Snapshots unavailable for this scan — nothing is pinned or shown."}>{"Snapshots unavailable for this scan"}</span>     </p>
        )}
        {selectedScan && snapshotsLoaded && snapshots.length === 0 && (
          <p style={{ margin: "12px 0 0", fontSize: 12.5, color: "var(--dim)" }}>
            No snapshots pinned yet.
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
      </>)}
      {active === "assets" && <CbomAssets />}
      {active === "algorithms" && <CbomAlgorithms />}
      {active === "libraries" && <CbomLibraries />}
      {active === "certificates" && <CbomCertificates />}
      {active === "keys" && <CbomKeys />}
      {active === "operations" && <CbomOperations />}
      {active === "protocols" && <CbomProtocols />}
      {active === "pqc" && <CbomPqc />}
      {active === "dependencies" && <CbomDependencies />}
      {active === "evidence" && <CbomEvidence />}
      {active === "history" && <CbomHistory />}
      {active === "export" && <CbomExport />}
    </div>
  );
}

/* ── workspace sections (docs/boms/01_PRODUCT_SPEC.md §2 navigation) ─── */

function CbomAssets() {
  const [q, setQ] = useState("");
  const read = useApi(() => apiCbomWorkspaceAssets(q || undefined), [q]);
  const rows = (read.data?.rows ?? []) as CbomCryptoAssetRow[];
  const [selected, setSelected] = useState<CbomCryptoAssetRow | null>(null);
  const detail = useApi(
    () => apiCbomWorkspaceAssetDetail(selected?.asset_id ?? ""),
    [selected?.asset_id],
  );
  return (
    <>
      <Panel title="Cryptographic Asset Inventory" sub="Click an asset for details">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="search by algorithm, location or implementation"
            aria-label="search crypto assets"
            style={{ flex: 1, minWidth: 220, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--panel-2)", color: "var(--text)", fontSize: 12 }} />
          <Badge tone="slate">{read.data?.total ?? (read.source === "live" ? rows.length : "—")} assets</Badge>
        </div>
        <WsState read={read} noun="crypto-asset inventory">
          <WsTable
            head={["Crypto asset", "Algorithm", "Operation", "Implementation", "Location", "Key metadata", "Evidence status", "PQC status", "Last observed"]}
            colSpan={9}
            rows={rows.map((r) => (
              <tr key={r.asset_id} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{r.asset_id.slice(0, 12)}…</span></td>
                <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.algorithm || "—"}{r.mode ? <span style={{ color: "var(--faint)", fontWeight: 400 }}> · {r.mode}</span> : null}</span></td>
                <td><Badge tone="slate">{r.operation || "UNKNOWN"}</Badge></td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.implementation.length ? r.implementation.join(", ") : "—"}</span></td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{r.location || "—"}</span></td>
                <td>
                  <span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {r.key_metadata.size ? <Badge tone="slate">{r.key_metadata.size}-bit</Badge> : null}
                    {r.key_metadata.named_reference ? <Badge tone="slate">named key ref</Badge> : null}
                    {r.key_metadata.hardcoded_material_flag ? <Badge tone="red">HARDCODED KEY FLAG</Badge> : null}
                    {!r.key_metadata.size && !r.key_metadata.named_reference && !r.key_metadata.hardcoded_material_flag
                      ? <span style={{ fontSize: 11, color: "var(--faint)" }}>none collected</span> : null}
                  </span>
                </td>
                <td><EvidenceBadge status={r.evidence_status} /></td>
                <td><PqcBadge family={r.pqc_family} /></td>
                <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{r.last_observed ? String(r.last_observed).slice(0, 19) : "—"}</span></td>
              </tr>
            ))}
          />
        </WsState>
      </Panel>
      {selected && (
        <Drawer title={selected.algorithm || "crypto asset"} sub={selected.location || selected.asset_id} onClose={() => setSelected(null)}>
          <CanonicalDetailLink assetRef={`crypto:${selected.asset_id}`} />
          {!detail.data ? <p className="faint" style={{ fontSize: 12 }}>{detail.running ? "Reading the asset…" : "The asset detail did not return."}</p> : (
            (() => {
              const d = detail.data as Record<string, any>;
              const a: CbomCryptoAssetRow = d.asset ?? selected;
              return (
                <div style={{ display: "grid", gap: 12 }}>
                  <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
                    <div><b>Algorithm</b> {a.algorithm || "—"}{a.mode ? ` · mode ${a.mode}` : ""}{a.key_metadata.size ? ` · ${a.key_metadata.size}-bit` : ""}</div>
                    <div><b>Implementation</b> {a.implementation.length ? a.implementation.join(", ") : "not collected"}</div>
                    <div><b>Operation</b> {a.operation || "UNKNOWN"}</div>
                    <div><b>Location</b> <span style={{ fontFamily: "var(--mono)" }}>{a.location || "—"}</span></div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>KEY METADATA — KEY MATERIAL IS NEVER COLLECTED</div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      {a.key_metadata.size ? <Badge tone="slate">{a.key_metadata.size}-bit</Badge> : <Badge tone="slate">size not collected</Badge>}
                      {a.key_metadata.named_reference ? <Badge tone="slate">named reference present</Badge> : null}
                      {a.key_metadata.hardcoded_material_flag ? <Badge tone="red">HARDCODED KEY MATERIAL FLAGGED AT THIS LOCATION</Badge> : null}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>USAGE — STATES ARE NOT EQUIVALENT</div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12 }}>
                      <UsageBadge usage={a.usage} />
                      <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{a.usage.basis}</span>
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>EVIDENCE</div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 12, marginBottom: 4 }}>
                      <EvidenceBadge status={a.evidence_status} />
                      <span style={{ fontSize: 10.5, color: "var(--faint)" }}>{a.evidence_basis}</span>
                    </div>
                    {(d.evidence ?? []).map((e: Record<string, unknown>, i: number) => (
                      <div key={i} style={{ fontSize: 11, color: "var(--dim)" }}>{String(e.observation_method)} · <span style={{ fontFamily: "var(--mono)" }}>{String(e.evidence_id).slice(0, 12)}…</span></div>
                    ))}
                    {!((d.evidence ?? []).length) && <div style={{ fontSize: 11.5, color: "var(--dim)" }}>No evidence records linked.</div>}
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>ASSOCIATED ASSETS</div>
                    {(d.associated_assets ?? []).map((x: Record<string, unknown>, i: number) => (
                      <div key={i} style={{ fontSize: 11.5, color: "var(--dim)" }}>{String(x.type)} · <span style={{ fontFamily: "var(--mono)" }}>{String(x.ref)}</span></div>
                    ))}
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>PQC MIGRATION RELEVANCE</div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <PqcBadge family={String(d.pqc?.family ?? a.pqc_family)} />
                      <span style={{ fontSize: 11, color: "var(--dim)" }}>{String(d.pqc?.migration_relevance ?? "")}</span>
                    </div>
                  </div>
                  {(d.history ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>HISTORICAL OBSERVATIONS</div>
                      {(d.history ?? []).slice(0, 6).map((h: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                          {String(h.location ?? "")} · first {String(h.first_seen ?? "—").slice(0, 10)} · last {String(h.last_seen ?? "—").slice(0, 10)} · {String(h.observation_count ?? 0)}×
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })()
          )}
        </Drawer>
      )}
    </>
  );
}

function CbomAlgorithms() {
  const read = useApi(apiCbomWorkspaceAlgorithms);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Algorithm Intelligence" sub="Per-algorithm rollups">
      <WsState read={read} noun="algorithm inventory">
        <WsTable head={["Algorithm", "Assets", "Operations", "Key sizes", "Usage states", "PQC family", "Evidence"]} colSpan={7}
          rows={rows.map((r) => (
            <tr key={r.algorithm}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.algorithm}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.assets}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{Object.entries(r.operations ?? {}).map(([k, v]) => `${k} (${v})`).join(", ")}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.key_sizes ?? []).join(", ") || "—"}</span></td>
              <td><span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>{Object.entries(r.usage_states ?? {}).map(([k, v]) => <span key={k}><Badge tone={k === "operation_observed" ? "green" : k === "configuration_observed" ? "amber" : "slate"}>{k}: {String(v)}</Badge>{" "}</span>)}</span></td>
              <td><PqcBadge family={r.pqc_family} /></td>
              <td><span style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>{Object.entries(r.evidence_status ?? {}).map(([k, v]) => <span key={k}><EvidenceBadge status={k} /> {String(v)}</span>)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomLibraries() {
  const read = useApi(apiCbomWorkspaceLibraries);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Crypto Library & Provider Inventory" sub="Libraries recorded on assets">
      <WsState read={read} noun="library inventory">
        <WsTable head={["Library / provider", "Algorithms supported", "Usage state", "Basis", "Assets referencing"]} colSpan={5}
          rows={rows.map((r) => (
            <tr key={r.name}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.name}</span></td>
              <td><span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--dim)" }}>{(r.algorithms ?? []).join(", ") || "—"}</span></td>
              <td><UsageBadge usage={{ usage_state: r.usage_state, basis: r.basis }} /></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.basis}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.crypto_bearing_components}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomCertificates() {
  const read = useApi(apiCbomWorkspaceCertificates);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Certificate & PKI Inventory" sub="Certificates and validity">
      <WsState read={read} noun="certificate inventory">
        <WsTable head={["Subject", "Issuer", "Public key", "Validity", "Expiry", "Revocation", "Renewal", "PQC family"]} colSpan={8}
          rows={rows.slice(0, 200).map((c) => (
            <tr key={c.fingerprint_sha256}>
              <td><span style={{ fontSize: 11.5, fontWeight: 600 }}>{c.subject || <span style={{ color: "var(--faint)" }}>no subject collected</span>}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{c.issuer || "—"}</span></td>
              <td><Badge tone="slate">{c.public_key_algorithm || "?"}{c.public_key_size ? ` ${c.public_key_size}` : ""}</Badge></td>
              <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(c.not_before ?? "—").slice(0, 10)} → {String(c.not_after ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone={c.expiry_status === "EXPIRED" ? "red" : c.days_until_expiry != null && c.days_until_expiry < 30 ? "amber" : "pass"}>{c.expiry_status || "UNKNOWN"}{c.days_until_expiry != null ? ` · ${c.days_until_expiry}d` : ""}</Badge></td>
              <td>{c.revocation_status ? <Badge tone={String(c.revocation_status).toUpperCase().includes("REVOKED") ? "red" : "slate"}>{c.revocation_status}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>not checked</span>}</td>
              <td><Badge tone="slate">{c.renewal_status || "NONE"}</Badge></td>
              <td><PqcBadge family={c.pqc_family} /></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomKeys() {
  const read = useApi(apiCbomWorkspaceKeys);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Key Metadata Inventory" sub="Type, size and parameters — no key material">
      <WsState read={read} noun="key-metadata inventory">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <Badge tone="slate">{String(read.data?.total ?? 0)} with key metadata</Badge>
          {Number(read.data?.hardcoded_flagged ?? 0) > 0 && <Badge tone="red">{String(read.data?.hardcoded_flagged)} hardcoded-material flags</Badge>}
        </div>
        <WsTable head={["Location", "Algorithm", "Size", "Mode", "Named reference", "Hardcoded-material flag"]} colSpan={6}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{r.location}</span></td>
              <td><span style={{ fontSize: 12 }}>{r.algorithm || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.size ? `${r.size}-bit` : "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.mode || "—"}</span></td>
              <td>{r.named_reference ? <Badge tone="slate">{r.named_reference}</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>none</span>}</td>
              <td>{r.hardcoded_material_flag ? <Badge tone="red">FLAGGED</Badge> : <span style={{ fontSize: 11, color: "var(--faint)" }}>no</span>}</td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomOperations() {
  const read = useApi(apiCbomWorkspaceOperations);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Cryptographic Operations" sub="Static references vs observed operations">
      <WsState read={read} noun="operation inventory">
        <WsTable head={["Operation", "Static references", "Observed operations", "Usage state", "Basis"]} colSpan={5}
          rows={rows.map((r) => (
            <tr key={r.operation}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.operation}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.static_references}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.observed_operations}</span></td>
              <td><UsageBadge usage={{ usage_state: r.usage_state, basis: r.basis }} /></td>
              <td><span style={{ fontSize: 10.5, color: "var(--faint)" }}>{r.basis}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomProtocols() {
  const read = useApi(apiCbomWorkspaceProtocols);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="TLS / SSH / IPsec Cryptography" sub="Supported, configured and negotiated">
      <WsState read={read} noun="protocol observations">
        <WsTable head={["Protocol", "Version", "Cipher suite", "Algorithm", "Host", "Seen", "Registry verdict", "Quantum impact"]} colSpan={8}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><Badge tone="violet">{r.protocol}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.tls_version || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{r.cipher_suite || "—"}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.algorithm || "—"}{r.key_size ? ` · ${r.key_size}` : ""}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.hostname || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_seen ?? "—").slice(0, 19)}</span></td>
              <td><Badge tone={r.weak_tls ? "red" : "slate"}>{r.registry_status || "UNKNOWN"}{r.weak_tls ? " · weak" : ""}</Badge></td>
              <td><Badge tone={r.quantum_impact === "CRITICAL" ? "red" : "slate"}>{r.quantum_impact || "NOT_ASSESSED"}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomPqc() {
  const read = useApi(apiCbomWorkspacePqc);
  const families = (read.data?.by_family ?? {}) as Record<string, number>;
  const certKeys = (read.data?.certificate_keys ?? {}) as Record<string, number>;
  const waves = (read.data?.migration_waves ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="PQC Readiness" sub="Algorithm families and migration waves">
      <WsState read={read} noun="PQC assessment">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          {Object.entries(families).map(([k, v]) => <span key={k}><PqcBadge family={k} /> {v}</span>)}
          {Object.entries(certKeys).map(([k, v]) => <span key={k}><Badge tone="slate">certificate · {k}: {v}</Badge></span>)}
        </div>
        {waves.length ? (
          <WsTable head={["Wave", "Title", "Status", "Planned window"]} colSpan={4}
            rows={waves.map((w) => (
              <tr key={String(w.wave_key)}>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(w.wave_key)}</span></td>
                <td><span style={{ fontSize: 12 }}>{String(w.title)}</span></td>
                <td><Badge tone={String(w.status) === "completed" ? "pass" : "amber"}>{String(w.status)}</Badge></td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{String(w.planned_window ?? "—")}</span></td>
              </tr>
            ))} />
        ) : (
          <div style={{ padding: 22, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>
            <div style={{ fontWeight: 600, color: "var(--text)" }}>No migration waves registered.</div>
            <div style={{ fontSize: 11.5, marginTop: 4 }}>Absence of rows is absence of a plan, not a clean estate.</div>
          </div>
        )}
      </WsState>
    </Panel>
  );
}

function CbomDependencies() {
  const read = useApi(apiCbomWorkspaceDependencies);
  const edges = (read.data?.edges ?? []) as Array<Record<string, string>>;
  const roots = (read.data?.roots ?? []) as string[];
  return (
    <Panel title="Crypto Dependencies" sub="Asset → implementation">
      <WsState read={read} noun="dependency inventory">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <Badge tone="violet">{edges.length} edges</Badge>
          <Badge tone="slate">{roots.length} roots</Badge>
          {Number(read.data?.unresolved ?? 0) > 0 && <Badge tone="amber">{String(read.data?.unresolved)} unresolved</Badge>}
        </div>
        <WsTable head={["Source", "Target", "Type"]} colSpan={3}
          rows={edges.slice(0, 300).map((e, i) => (
            <tr key={i}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{e.source}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{e.target}</span></td>
              <td><Badge tone="slate">{e.type}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomEvidence() {
  const read = useApi(apiCbomWorkspaceEvidence);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Evidence & Provenance" sub="How each record was observed">
      <WsState read={read} noun="evidence inventory">
        <WsTable head={["Algorithm", "Observation method", "Observations", "Evidence status", "First seen", "Last seen", "Freshness"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{r.algorithm || "—"}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.observation_method}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.observation_count}</span></td>
              <td><EvidenceBadge status={r.evidence_status} /></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.first_seen ?? "—").slice(0, 10)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_seen ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomHistory() {
  const read = useApi(apiCbomWorkspaceHistory);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="CBOM History" sub="First and last seen per fact">
      <WsState read={read} noun="history">
        <WsTable head={["Algorithm", "Location", "First seen", "Last seen", "Observations", "Freshness"]} colSpan={6}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{r.algorithm || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5, color: "var(--dim)" }}>{r.location || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.first_seen ?? "—").slice(0, 10)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_seen ?? "—").slice(0, 10)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.observation_count}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function CbomExport() {
  const read = useApi(apiCbomWorkspaceExport);
  const formats = (read.data?.formats ?? []) as Array<Record<string, unknown>>;
  const signed = (read.data?.signed_variants ?? []) as string[];
  return (
    <Panel title="Export & Validation" sub="Validate and export">
      <WsState read={read} noun="export inventory">
        <WsTable head={["Format", "Validator", "State"]} colSpan={3}
          rows={formats.map((f, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{String(f.format)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{String(f.validator)}</span></td>
              <td><Badge tone="pass">{String(f.state)}</Badge></td>
            </tr>
          ))} />
        {signed.length > 0 && (
          <div style={{ marginTop: 12, fontSize: 11.5, color: "var(--dim)" }}>
            Signed variants: {signed.map((v) => <Badge key={v} tone="violet">{v}</Badge>)} — the signed export carries an external signature over the exact payload.
          </div>
        )}
      </WsState>
    </Panel>
  );
}

/* ── Live network collection (not a spec tab — an action panel) ──────────
   Enter host:port targets, run the real network TLS scan, and the collected
   certificates/usages land in this workspace's inventories. Counts and
   statuses only — the panel never renders key material. */
function CbomNetworkCollect() {
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState("");
  const [deep, setDeep] = useState(true);
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<{ endpoint: string; status: string }[]>([]);

  async function run() {
    const hosts = targets.split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (!hosts.length) { setError("Add at least one host:port target."); return; }
    setBusy(true); setError(null); setNote(null); setRows([]);
    const res = await apiNetworkTlsScan(hosts, deep ? { scan_versions: true, scan_ciphers: true, check_chain_sent: true } : {});
    setBusy(false);
    if (res.source !== "live" || !res.data) { setError("Scan refused or unreachable — check scope authorization and try again."); return; }
    const findings = Array.isArray(res.data.findings) ? res.data.findings : [];
    const certs = Array.isArray(res.data.certificates) ? res.data.certificates : [];
    const alerts = Array.isArray(res.data.alerts) ? res.data.alerts : [];
    setRows(findings.map((f) => ({
      endpoint: String((f as Record<string, unknown>).endpoint ?? "?"),
      status: String((f as Record<string, unknown>).status ?? "?"),
    })));
    setNote(`Collected ${certs.length} certificate${certs.length === 1 ? "" : "s"} from ${findings.length} endpoint${findings.length === 1 ? "" : "s"}${alerts.length ? ` · ${alerts.length} alert${alerts.length === 1 ? "" : "s"}` : ""} — added to the tabs below and the Network page.`);
  }

  return (
    <Panel style={{ padding: 14, marginBottom: 16, borderTop: "2px solid var(--accent)" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 700, letterSpacing: "0.06em" }}>LIVE NETWORK COLLECTION</div>
          <div style={{ fontSize: 11.5, color: "var(--dim)", marginTop: 2 }}>
            Scan TLS endpoints into this CBOM
          </div>
        </div>
        <button className="btn outline" style={{ fontSize: 12, padding: "6px 12px" }} onClick={() => setOpen(!open)} aria-expanded={open}>
          {open ? "Hide" : "Scan endpoints →"}
        </button>
      </div>
      {open && (
        <div style={{ marginTop: 12 }}>
          <textarea
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            rows={3}
            aria-label="TLS scan targets"
            placeholder={"host:port — one per line or comma-separated\ne.g. 10.0.10.21:443\n      payments-gw.example:8443"}
            style={{ width: "100%", padding: "8px 10px", borderRadius: "var(--r)", border: "1px solid var(--line)", background: "var(--panel-2)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 12 }}
          />
          <div style={{ display: "flex", alignItems: "center", gap: 14, marginTop: 8, flexWrap: "wrap" }}>
            <label style={{ fontSize: 11.5, color: "var(--dim)", display: "flex", alignItems: "center", gap: 6 }}>
              <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} />
              enumerate versions + ciphers (slower, richer)
            </label>
            <button className="btn primary" onClick={() => void run()} disabled={busy} style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>
              {busy ? "Scanning…" : "Run live scan"}
            </button>
          </div>
          {error && <div style={{ marginTop: 10, fontSize: 12, color: "var(--red)" }}>{error}</div>}
          {note && <div style={{ marginTop: 10, fontSize: 12, color: "var(--green)" }}>{note}</div>}
          {rows.length > 0 && (
            <table style={{ width: "100%", marginTop: 10, borderCollapse: "collapse", fontSize: 12 }}>
              <thead><tr style={{ textAlign: "left", color: "var(--faint)", fontSize: 11 }}>
                <th style={{ padding: "4px 8px" }}>Endpoint</th><th style={{ padding: "4px 8px" }}>Probe status</th>
              </tr></thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.endpoint} style={{ borderTop: "1px solid var(--line)" }}>
                    <td style={{ padding: "5px 8px", fontFamily: "var(--mono)", fontSize: 11.5 }}>{r.endpoint}</td>
                    <td style={{ padding: "5px 8px" }}><Badge tone={r.status === "OK" ? "pass" : "fail"}>{r.status}</Badge></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </Panel>
  );
}
