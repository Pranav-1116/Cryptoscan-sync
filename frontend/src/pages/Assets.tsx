import React, { useState, useEffect, useRef } from "react";
import { Badge, Tabs } from "../components/ui";
import { Link } from "react-router-dom";
import { apiFactStore, apiGraphBlastRadiusFromAsset, apiRemediationTasks, FactStoreRow, RemediationTask, tenantFetch } from "../lib/api";
import { IconEstate } from "../components/icons";

// GET /api/v1/assets serializes CryptoAsset columns; only GET /assets/{id}
// adds evidence_ids. Neither endpoint provides a PQC verdict or dependencies.
interface AssetApiRow {
  id: string;
  asset_key?: string | null;
  algorithm?: string | null;
  purpose?: string | null;
  mode?: string | null;
  key_size?: number | null;
  file_path?: string | null;
  owner?: string | null;
  lifecycle_state?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  extra?: { first_seen_at?: string | null; last_seen_at?: string | null; protocol?: string | null } | null;
  evidence_ids?: string[];
  evidence_classification?: {
    strongest_level?: string;
    note?: string | null;
  } | null;
}

interface AssetRecord {
  id: string;
  name: string;
  algorithm: string | null;
  purpose: string | null;
  mode: string | null;
  keySize: number | null;
  protocol: string | null;
  sourcePath: string | null;
  owner: string | null;
  lifecycleState: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  firstObserved: string | null;
  lastObserved: string | null;
  assetKey: string | null;
  evidenceIds: string[];
  evidenceClass: string | null;
  evidenceClassNote: string | null;
}

const observed = (value: unknown): string | null =>
  typeof value === "string" && value.trim() ? value.trim() : null;

function assetRecord(value: unknown): AssetRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const row = value as AssetApiRow;
  const id = observed(row.id);
  if (!id) return null; // Never invent an identifier for an API row.
  const algorithm = observed(row.algorithm);
  const extra = row.extra && typeof row.extra === "object" && !Array.isArray(row.extra) ? row.extra : null;
  return {
    id,
    name: algorithm || id,
    algorithm,
    purpose: observed(row.purpose),
    mode: observed(row.mode),
    keySize: typeof row.key_size === "number" && Number.isFinite(row.key_size) && row.key_size > 0 ? row.key_size : null,
    protocol: observed(extra?.protocol),
    sourcePath: observed(row.file_path),
    owner: observed(row.owner),
    lifecycleState: observed(row.lifecycle_state),
    createdAt: observed(row.created_at),
    updatedAt: observed(row.updated_at),
    firstObserved: observed(extra?.first_seen_at),
    lastObserved: observed(extra?.last_seen_at),
    assetKey: observed(row.asset_key),
    evidenceIds: Array.isArray(row.evidence_ids) ? row.evidence_ids.filter((item): item is string => !!observed(item)) : [],
    evidenceClass: observed(row.evidence_classification?.strongest_level),
    evidenceClassNote: observed(row.evidence_classification?.note),
  };
}

function requestError(status: number, subject: string): string {
  if (status === 401) return `Authentication required to view ${subject}. Sign in and try again.`;
  if (status === 403) return `Access denied to ${subject} for this account or tenant.`;
  return `Unable to load ${subject} (HTTP ${status}).`;
}

/* §4.2 identity spine (round 64): the same five identity fields (missing →
 * "") are the same crypto fact — the canonical join from a crypto asset to
 * its fact row. Prefer the stored key when the asset row carries one;
 * pre-spine rows fall back to the field tuple, which the spine derives
 * from. Either way this is an exact join, never a similarity match. */
function spineJoin(fact: FactStoreRow, asset: AssetRecord): boolean {
  if (asset.assetKey) return fact.asset_key === asset.assetKey;
  const f = fact.fact;
  const norm = (v: unknown) => (v === null || v === undefined ? "" : String(v));
  return norm(f.algorithm) === norm(asset.algorithm)
    && norm(f.purpose) === norm(asset.purpose)
    && norm(f.file_path) === norm(asset.sourcePath)
    && norm(f.key_size) === norm(asset.keySize)
    && norm(f.mode) === norm(asset.mode);
}

const PAGE_SIZE = 100;

function parseAssetPage(body: unknown): { rows: AssetRecord[]; total: number } | { error: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { error: "Asset response is unavailable or invalid." };
  const { assets, total_count } = body as { assets?: unknown; total_count?: unknown };
  if (!Array.isArray(assets) || !Number.isSafeInteger(total_count) || (total_count as number) < 0) {
    return { error: "Asset response is unavailable or invalid." };
  }
  const rows = assets.map(assetRecord).filter((row): row is AssetRecord => row !== null);
  if (rows.length !== assets.length) return { error: "Asset response contains records without valid IDs." };
  return { rows, total: total_count as number };
}

export default function Assets() {
  const [assetsList, setAssetsList] = useState<AssetRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [pageLoading, setPageLoading] = useState(false);
  const [totalCount, setTotalCount] = useState<number | null>(null);
  const [nextPage, setNextPage] = useState<number | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const requestEpoch = useRef(0);
  const paging = useRef(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<AssetRecord | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [searchTerm, setSearchTerm] = useState("");

  const tabNames = ["Overview", "Evidence", "Facts", "Dependencies", "Usage", "History", "Policy", "PQC", "Remediation"];
  /* §5 (round 64): the fact behind the selected asset (joined on the
   * identity spine) and its graph blast radius — loaded on demand per tab. */
  const [fact, setFact] = useState<{ forId: string; row: FactStoreRow | null; candidates: number } | null>(null);
  const [factLoading, setFactLoading] = useState(false);
  const [factError, setFactError] = useState<string | null>(null);
  const [blast, setBlast] = useState<{ forId: string; data: { owning_systems?: string[]; systems?: Array<{ id: string; name?: string; hops: number }>; nodes_visited?: number; backend?: string } | null; unlinked: boolean } | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);
  const [blastError, setBlastError] = useState<string | null>(null);
  /* §5 (round 75): the remediation tasks that reference this asset's
   * evidence — joined server-side through the STORED crypto_asset_evidence
   * link table, loaded on demand per tab. */
  const [assetTasks, setAssetTasks] = useState<{ forId: string; rows: RemediationTask[] } | null>(null);
  const [assetTasksLoading, setAssetTasksLoading] = useState(false);
  const [assetTasksError, setAssetTasksError] = useState<string | null>(null);

  useEffect(() => {
    const resetForScope = () => {
      // Invalidate in-flight list, detail and later-page requests before React re-renders.
      requestEpoch.current += 1;
      paging.current = false;
      setAssetsList([]);
      setSelectedId(null);
      setDetail(null);
      setDetailError(null);
      setDetailLoading(false);
      setListError(null);
      setPageError(null);
      setTotalCount(null);
      setNextPage(null);
      setPageLoading(false);
      setLoading(true);
      setFact(null);
      setFactLoading(false);
      setFactError(null);
      setBlast(null);
      setBlastLoading(false);
      setBlastError(null);
      setAssetTasks(null);
      setAssetTasksLoading(false);
      setAssetTasksError(null);
      setRefreshKey((key) => key + 1);
    };
    window.addEventListener("zelinx:tenant", resetForScope);
    window.addEventListener("zelinx:auth", resetForScope);
    return () => {
      window.removeEventListener("zelinx:tenant", resetForScope);
      window.removeEventListener("zelinx:auth", resetForScope);
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const epoch = requestEpoch.current;
    const current = () => !cancelled && requestEpoch.current === epoch;
    async function fetchAssets() {
      setLoading(true);
      try {
        const res = await tenantFetch(`/api/v1/assets?page=1&page_size=${PAGE_SIZE}`, { signal: AbortSignal.timeout(6000) });
        if (!res.ok) {
          if (current()) setListError(requestError(res.status, "assets"));
          return;
        }
        const parsed = parseAssetPage(await res.json());
        if ("error" in parsed) {
          if (current()) setListError(parsed.error);
          return;
        }
        if (current()) {
          const unique = [...new Map(parsed.rows.map((row) => [row.id, row])).values()];
          if (!unique.length && parsed.total > 0) {
            setListError(`Asset service reports ${parsed.total} assets but returned no records for page 1.`);
            return;
          }
          setAssetsList(unique);
          setSelectedId(unique[0]?.id ?? null);
          setTotalCount(parsed.total);
          setNextPage(parsed.total > PAGE_SIZE ? 2 : null);
          setPageError(unique.length < parsed.rows.length ? "Some asset IDs were repeated in the API response; inventory may be incomplete." : null);
          setListError(null);
        }
      } catch {
        if (current()) setListError("Asset service is offline or unreachable. No inventory data is available.");
      } finally {
        if (current()) setLoading(false);
      }
    }
    fetchAssets();
    return () => { cancelled = true; };
  }, [refreshKey]);

  async function loadMore() {
    if (nextPage === null || paging.current) return;
    paging.current = true;
    setPageLoading(true);
    setPageError(null);
    const epoch = requestEpoch.current;
    const page = nextPage;
    try {
      const res = await tenantFetch(`/api/v1/assets?page=${page}&page_size=${PAGE_SIZE}`, { signal: AbortSignal.timeout(6000) });
      if (requestEpoch.current !== epoch) return;
      if (!res.ok) {
        if (res.status === 401 || res.status === 403) {
          setAssetsList([]);
          setSelectedId(null);
          setDetail(null);
          setListError(requestError(res.status, "assets"));
        } else setPageError(requestError(res.status, `page ${page} of assets`));
        return;
      }
      const parsed = parseAssetPage(await res.json());
      if (requestEpoch.current !== epoch) return;
      if ("error" in parsed) {
        setPageError(`Page ${page}: ${parsed.error}`);
        return;
      }
      if (!parsed.rows.length) {
        setPageError(`Page ${page} returned no assets; inventory may be incomplete. Retry to load the remaining records.`);
        return;
      }
      const seen = new Set(assetsList.map((asset) => asset.id));
      const added = parsed.rows.filter((asset) => {
        if (seen.has(asset.id)) return false;
        seen.add(asset.id);
        return true;
      });
      const shown = assetsList.length + added.length;
      setAssetsList((currentRows) => [...currentRows, ...added]);
      setTotalCount(parsed.total);
      setNextPage(page * PAGE_SIZE < parsed.total ? page + 1 : null);
      if (shown < parsed.total && page * PAGE_SIZE >= parsed.total) {
        setPageError(`Loaded ${shown} distinct assets, but the service reports ${parsed.total}; repeated or missing rows may remain.`);
      }
    } catch {
      if (requestEpoch.current === epoch) setPageError(`Page ${page} of assets is offline or unreachable. Loaded records are incomplete.`);
    } finally {
      if (requestEpoch.current === epoch) {
        paging.current = false;
        setPageLoading(false);
      }
    }
  }

  useEffect(() => {
    if (!selectedId) return;
    const assetId = selectedId;
    const epoch = requestEpoch.current;
    let cancelled = false;
    const current = () => !cancelled && requestEpoch.current === epoch;
    async function fetchDetail() {
      setDetail(null);
      setDetailError(null);
      setDetailLoading(true);
      try {
        const res = await tenantFetch(`/api/v1/assets/${encodeURIComponent(assetId)}`, { signal: AbortSignal.timeout(6000) });
        if (!res.ok) {
          if (current()) setDetailError(requestError(res.status, "asset details and evidence"));
          return;
        }
        const payload: unknown = await res.json();
        const row = assetRecord(payload);
        if (!row || row.id !== assetId || !Array.isArray((payload as AssetApiRow).evidence_ids)) {
          if (current()) setDetailError("Asset detail response is unavailable or invalid.");
          return;
        }
        if (current()) setDetail(row);
      } catch {
        if (current()) setDetailError("Asset details and evidence are offline or unreachable.");
      } finally {
        if (current()) setDetailLoading(false);
      }
    }
    fetchDetail();
    return () => { cancelled = true; };
  }, [selectedId]);

  /* The fact behind this asset (Facts tab): queried server-side by
   * algorithm + file prefix (bounded), then joined on the identity spine
   * — never a whole-estate client-side scan. */
  useEffect(() => {
    if (activeTab !== 2 || !selectedId) return;
    const asset = assetsList.find((row) => row.id === selectedId);
    if (!asset || !asset.algorithm || !asset.sourcePath || fact?.forId === asset.id) return;
    let cancelled = false;
    setFactLoading(true);
    setFactError(null);
    apiFactStore({ algorithm: asset.algorithm, file_prefix: asset.sourcePath, limit: 50 })
      .then((res) => {
        if (cancelled) return;
        setFactLoading(false);
        if (res.source !== "live" || !res.data) {
          const status = /^HTTP (\d+)$/.exec(res.error || "");
          setFactError(status
            ? requestError(Number(status[1]), "the fact store")
            : "The fact store is offline or unreachable.");
          return;
        }
        const rows = Array.isArray(res.data.facts) ? res.data.facts : [];
        const joined = rows.filter((row) => spineJoin(row, asset));
        setFact({ forId: asset.id, row: joined.length ? joined[0] : null, candidates: rows.length });
      });
    return () => { cancelled = true; };
  }, [activeTab, selectedId, assetsList, fact?.forId]);

  /* The remediation tasks referencing this asset (Remediation tab,
   * round 75): tasks bind to evidence records; the server joins them to
   * this asset through the stored asset↔evidence linkage. An empty
   * answer means no task references any of this asset's evidence. */
  useEffect(() => {
    if (activeTab !== 8 || !selectedId || assetTasks?.forId === selectedId) return;
    let cancelled = false;
    setAssetTasksLoading(true);
    setAssetTasksError(null);
    apiRemediationTasks({ asset_id: selectedId, page_size: 20 })
      .then((res) => {
        if (cancelled) return;
        setAssetTasksLoading(false);
        if (res.source === "live" && res.data) {
          setAssetTasks({ forId: selectedId, rows: res.data.tasks ?? [] });
        } else {
          const status = /^HTTP (\d+)$/.exec(res.error || "");
          setAssetTasksError(status
            ? requestError(Number(status[1]), "the remediation tasks")
            : "The remediation task list is offline or unreachable.");
        }
      });
    return () => { cancelled = true; };
  }, [activeTab, selectedId, assetTasks?.forId]);

  /* The graph view of this asset (Dependencies tab): the real blast-radius
   * endpoint fans out from every system linked to the asset. HTTP 404 is
   * the endpoint's "no system links this asset" answer — an honest
   * unknown, never rendered as a zero-impact verdict. */
  useEffect(() => {
    if (activeTab !== 3 || !selectedId || blast?.forId === selectedId) return;
    let cancelled = false;
    setBlastLoading(true);
    setBlastError(null);
    apiGraphBlastRadiusFromAsset(selectedId, 5)
      .then((res) => {
        if (cancelled) return;
        setBlastLoading(false);
        if (res.source === "live" && res.data) {
          setBlast({ forId: selectedId, data: res.data, unlinked: false });
        } else if (res.error === "HTTP 404") {
          setBlast({ forId: selectedId, data: null, unlinked: true });
        } else {
          const status = /^HTTP (\d+)$/.exec(res.error || "");
          setBlastError(status
            ? requestError(Number(status[1]), "the dependency graph")
            : "The dependency graph is offline or unreachable.");
        }
      });
    return () => { cancelled = true; };
  }, [activeTab, selectedId, blast?.forId]);

  const selectedAsset = assetsList.find((asset) => asset.id === selectedId) ?? null;
  const displayedAsset = detail?.id === selectedId ? detail : selectedAsset;
  const filteredAssets = assetsList.filter((asset) => {
    const query = searchTerm.toLowerCase();
    return [asset.name, asset.id, asset.sourcePath, asset.owner].some((field) => field?.toLowerCase().includes(query));
  });

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* 9. Asset Detail Page Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            Cryptographic Asset Record
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>
            {displayedAsset ? displayedAsset.name : "Cryptographic Inventory"}
          </h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            {displayedAsset ? (
              <>ID: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)" }}>{displayedAsset.id}</code> · Source path: <code style={{ fontFamily: "var(--mono)" }}>{displayedAsset.sourcePath ?? "Not observed"}</code></>
            ) : (
              "Cryptographic assets returned by the inventory service."
            )}
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <Link to="/scanners" className="btn primary" style={{ textDecoration: "none" }}>
            + New Discovery Scan
          </Link>
        </div>
      </div>

      {loading ? (
        <div className="panel" style={{ padding: "40px", textAlign: "center", color: "var(--dim)" }} role="status">
          Loading cryptographic asset inventory from backend...
        </div>
      ) : listError ? (
        <div className="panel" style={{ padding: "40px", color: "var(--dim)" }} role="alert">{listError}</div>
      ) : assetsList.length === 0 ? (
        <div className="panel" style={{ padding: "48px 24px", textAlign: "center" }}>
          <div style={{ marginBottom: "12px", lineHeight: 0, color: "var(--faint)" }}><IconEstate size={32} /></div>
          <h3 style={{ fontSize: "18px", fontWeight: 600, margin: "0 0 8px" }}>No cryptographic assets discovered yet</h3>
          <p style={{ color: "var(--dim)", fontSize: "14px", maxWidth: "480px", margin: "0 auto 20px", lineHeight: "1.5" }}>
            No assets were returned by the inventory service. Start a discovery scan to populate this view.
          </p>
          <Link to="/scanners" className="btn primary" style={{ textDecoration: "none", display: "inline-block" }}>
            Start Discovery Scan
          </Link>
        </div>
      ) : (
        <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: "24px" }}>
          {/* Left Column: Asset Selection List */}
          <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
            <div className="panel" style={{ padding: "16px" }}>
              <div style={{ display: "flex", gap: "8px", marginBottom: "12px" }}>
                <input
                  type="search"
                  aria-label="Search assets"
                  placeholder="Search assets..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  style={{
                    flex: 1,
                    background: "var(--bg-2)",
                    border: "1px solid var(--line)",
                    borderRadius: "var(--r)",
                    padding: "6px 10px",
                    color: "var(--text)",
                    fontSize: "13px"
                  }}
                />
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "600px", overflowY: "auto" }}>
                {filteredAssets.map((asset) => {
                  const isSel = selectedId === asset.id;
                  return (
                    <button
                      type="button"
                      key={asset.id}
                      aria-pressed={isSel}
                      onClick={() => setSelectedId(asset.id)}
                      style={{
                        width: "100%", textAlign: "left", color: "var(--text)",
                        padding: "10px 12px",
                        background: isSel ? "color-mix(in srgb, var(--accent) 8%, transparent)" : "transparent",
                        border: isSel ? "1px solid var(--cyan)" : "1px solid var(--line)",
                        borderRadius: "var(--r)",
                        cursor: "pointer",
                        transition: "all 0.15s ease"
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontWeight: 600, fontSize: "13px", color: isSel ? "var(--cyan)" : "var(--text)" }}>{asset.name}</span>
                        <span style={{ display: "flex", gap: "4px" }}>
                          <Badge tone={asset.evidenceClass && asset.evidenceClass !== "UNCLASSIFIED" ? "cyan" : "slate"}>
                            {`Evidence: ${asset.evidenceClass ?? "UNCLASSIFIED"}`}
                          </Badge>
                          <Badge tone="slate">{asset.lifecycleState ?? "Unknown"}</Badge>
                        </span>
                      </div>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "11.5px", color: "var(--dim)" }}>
                        <span>{asset.sourcePath ?? "Source not observed"}</span>
                        <span>{asset.owner ?? "Owner unknown"}</span>
                      </div>
                    </button>
                  );
                })}
                {filteredAssets.length === 0 && <p style={{ color: "var(--dim)" }}>No assets match your search.</p>}
              </div>
              <p style={{ fontSize: "12px", color: "var(--dim)", margin: "12px 0 0" }} role="status">
                Loaded {assetsList.length} of {totalCount} assets{searchTerm ? ` · ${filteredAssets.length} match search` : ""}
              </p>
              {pageError && <p role="alert" style={{ color: "var(--dim)", fontSize: "12px" }}>{pageError}</p>}
              {nextPage !== null && (
                <button type="button" className="btn outline" onClick={loadMore} disabled={pageLoading} style={{ marginTop: "8px" }}>
                  {pageLoading ? "Loading more..." : "Load more assets"}
                </button>
              )}
            </div>
          </div>

          {/* Right Column: Active Asset Detail Tabs */}
          {displayedAsset && (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              <div className="panel" style={{ padding: "20px" }}>
                <Tabs tabs={tabNames} active={activeTab} onChange={setActiveTab} />

                <div style={{ marginTop: "20px" }}>
                  {activeTab === 0 && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", fontSize: "13px" }}>
                      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Lifecycle status</div>
                          <div style={{ marginTop: "2px" }}>{displayedAsset.lifecycleState ?? "Unknown"}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Algorithm & Key Size</div>
                          <div style={{ fontFamily: "var(--mono)", color: "var(--text)", marginTop: "2px" }}>
                            {displayedAsset.algorithm ?? "Unknown"} · {displayedAsset.keySize === null ? "Key size not observed" : `${displayedAsset.keySize} bits`}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Protocol Context</div>
                          <div style={{ marginTop: "2px" }}>{displayedAsset.protocol ?? "Not observed"}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Source path</div>
                          <div style={{ marginTop: "2px", overflowWrap: "anywhere" }}>{displayedAsset.sourcePath ?? "Not observed"}</div>
                        </div>
                      </div>
                      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Quantum Risk Status</div>
                          <div style={{ marginTop: "2px" }}><Badge tone="slate">Not assessed by this endpoint</Badge></div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Owner</div>
                          <div style={{ marginTop: "2px" }}>{displayedAsset.owner ?? "Unknown"}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Created / updated</div>
                          <div style={{ marginTop: "2px" }}>{displayedAsset.createdAt ?? "Unknown"} / {displayedAsset.updatedAt ?? "Unknown"}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>First / last observed</div>
                          <div style={{ marginTop: "2px" }}>{displayedAsset.firstObserved ?? "Not observed"} / {displayedAsset.lastObserved ?? "Not observed"}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Asset identity (spine)</div>
                          <div style={{ marginTop: "2px", overflowWrap: "anywhere", fontFamily: "var(--mono)", fontSize: 11.5 }}>
                            {displayedAsset.assetKey ?? "Not observed"}
                          </div>
                          <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 2 }}>
                            Canonical identity — joins this asset to its evidence, fact and BOM component rows.
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Evidence</div>
                          <div style={{ marginTop: "2px" }}>{detailLoading ? "Loading evidence IDs..." : detailError ?? (detail?.id === selectedId && detail.evidenceIds.length ? `${detail.evidenceIds.length} linked ID(s); integrity not verified` : "Not observed; integrity not verified")}</div>
                        </div>
                        <div>
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Evidence classification</div>
                          <div style={{ marginTop: "2px" }} data-testid="evidence-classification">
                            {displayedAsset.evidenceClass ?? "UNCLASSIFIED"}
                          </div>
                          <div style={{ fontSize: 10.5, color: "var(--faint)", marginTop: 2 }}>
                            {displayedAsset.evidenceClassNote ?? "the evidence level is not recorded: unknown, never promoted"}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {activeTab === 1 && (
                    <div style={{ fontSize: "13px" }}>
                      {detailLoading ? <p role="status">Loading evidence IDs...</p> : detailError ? <p role="alert">{detailError}</p> : detail?.id === selectedId && detail.evidenceIds.length ? (
                        <><p>Evidence IDs associated with this asset. Integrity has not been verified here.</p><ul>{detail.evidenceIds.map((id) => <li key={id}><code style={{ color: "var(--cyan)", overflowWrap: "anywhere" }}>{id}</code></li>)}</ul></>
                      ) : <p>No evidence IDs are associated with this asset in the detail response. Integrity not verified.</p>}
                    </div>
                  )}

                  {activeTab === 2 && (
                    <div style={{ fontSize: "13px" }}>
                      {!displayedAsset.algorithm || !displayedAsset.sourcePath ? (
                        <p role="note" style={{ color: "var(--dim)" }}>
                          The fact join needs this asset's algorithm and source path; at least one is not observed on this row. No fact is inferred.
                        </p>
                      ) : factLoading ? (
                        <p role="status">Querying the fact store by algorithm and file prefix...</p>
                      ) : factError ? (
                        <p role="alert">{factError}</p>
                      ) : fact?.forId === displayedAsset.id ? (
                        fact.row ? (
                          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                            <p style={{ margin: 0 }}>
                              Identity join: <code style={{ fontFamily: "var(--mono)", color: "var(--cyan)", overflowWrap: "anywhere" }}>{fact.row.asset_key ?? "key not derived"}</code>
                              {" "}— the same canonical spine key on the asset row and the fact row. This is the fact behind this asset.
                            </p>
                            <div style={{ padding: "12px", background: "var(--bg-2)", border: "1px solid var(--line)", borderRadius: "var(--r)", display: "flex", flexDirection: "column", gap: "6px" }}>
                              <div style={{ fontFamily: "var(--mono)" }}>
                                {fact.row.fact.algorithm}{fact.row.fact.purpose ? ` · ${fact.row.fact.purpose}` : ""}{fact.row.fact.mode ? ` · ${fact.row.fact.mode}` : ""}{fact.row.fact.key_size != null ? ` · ${fact.row.fact.key_size} bits` : ""}
                              </div>
                              <div>
                                Observed {fact.row.observation_count} time(s)
                                {fact.row.first_seen ? ` · first ${fact.row.first_seen}` : ""}
                                {fact.row.last_seen ? ` · last ${fact.row.last_seen}` : ""}
                              </div>
                              <div>Scanners: {(fact.row.scanners || []).join(", ") || "none recorded"} · Confidences: {(fact.row.confidences || []).join(", ") || "none recorded"}</div>
                              <div>Hardcoded-key observations: {fact.row.hardcoded_key_observations ?? 0}</div>
                              <div>
                                Evidence behind this fact: {fact.row.evidence_count ?? (fact.row.evidence_ids || []).length} row(s)
                                {fact.row.evidence_truncated ? " (inline list truncated — the count is exact)" : ""} — integrity not verified here.
                              </div>
                              <div>
                                Store freshness: {fact.row.fresh === false
                                  ? "stale — evidence activity is newer than the last store rebuild; the live cryptographic facts view is the current reference"
                                  : "current (the rebuild covers the newest evidence activity for this file)"}
                              </div>
                            </div>
                            <p style={{ margin: 0, fontSize: "11.5px", color: "var(--faint)" }}>
                              Served from the materialised fact store — queried server-side by algorithm + file prefix, matched on the identity spine. The store is derived and rebuildable; it is a projection of evidence, not a second truth.
                            </p>
                          </div>
                        ) : (
                          <p role="note" style={{ color: "var(--dim)" }}>
                            No fact row in the store matches this asset's identity ({fact.candidates} candidate row(s) in this file + algorithm). The store materialises facts from evidence — a missing row means the store has not observed this identity tuple, not that the asset was judged fact-free.
                          </p>
                        )
                      ) : (
                        <p style={{ color: "var(--dim)" }}>The fact join loads when this tab is active.</p>
                      )}
                    </div>
                  )}

                  {activeTab === 3 && (
                    <div style={{ fontSize: "13px" }}>
                      {blastLoading ? (
                        <p role="status">Traversing the dependency graph from this asset (asset start)...</p>
                      ) : blastError ? (
                        <p role="alert">{blastError}</p>
                      ) : blast?.forId === displayedAsset.id && blast.unlinked ? (
                        <p role="note" style={{ color: "var(--dim)" }}>
                          This asset is not linked to any system — no SystemAsset rows reference it, so the graph walk has no start. Blast radius is unknown, not zero: system links are declared or adopted relationships (Dependency Graph → Edge Manager), never inferred from co-location.
                        </p>
                      ) : blast?.forId === displayedAsset.id && blast.data ? (
                        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                          <p style={{ margin: 0 }}>
                            Asset start — the walk fans out from every system that uses this asset.
                            {" "}SystemAsset links are declared or adopted relationships, not observed traffic.
                          </p>
                          <div>
                            Owning system(s): {(blast.data.owning_systems || []).join(", ") || "none reported"}
                          </div>
                          <div>
                            Downstream dependents: {(blast.data.systems || []).length} · {blast.data.nodes_visited ?? (blast.data.systems || []).length} node(s) visited
                            {(blast.data.systems || []).length > 0 ? ` · max ${Math.max(...(blast.data.systems || []).map((s) => s.hops ?? 0))} hop(s)` : ""}
                          </div>
                          {(blast.data.systems || []).length > 0 && (
                            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                              {(blast.data.systems || []).map((s) => (
                                <div key={s.id} style={{ fontSize: "12px", padding: "6px 8px", background: "var(--bg-2)", borderRadius: "var(--r)" }}>
                                  ↳ {s.name || s.id} <span style={{ color: "var(--dim)" }}>· {s.hops} hop{s.hops === 1 ? "" : "s"}</span>
                                </div>
                              ))}
                            </div>
                          )}
                          <div style={{ fontSize: "11.5px", color: "var(--faint)" }}>
                            Engine: {blast.data.backend === "memory" ? "deterministic in-process engine" : blast.data.backend || "not reported"} · exact BFS traversal, no inferred edges.
                          </div>
                          <div>
                            <Link
                              to={`/dependency-graph?asset=${encodeURIComponent(displayedAsset.id)}`}
                              className="btn outline"
                              style={{ textDecoration: "none", fontSize: "12px", padding: "6px 12px", borderRadius: "var(--r)" }}
                            >
                              Open in Dependency Graph
                            </Link>
                          </div>
                        </div>
                      ) : (
                        <p style={{ color: "var(--dim)" }}>Blast radius loads when this tab is active.</p>
                      )}
                    </div>
                  )}

                  {activeTab === 8 && (
                    <div style={{ fontSize: "13px" }}>
                      {assetTasksError && <p style={{ color: "var(--amber)" }}>{assetTasksError}</p>}
                      {assetTasksLoading && <p style={{ color: "var(--dim)" }}>Loading remediation tasks…</p>}
                      {!assetTasksError && !assetTasksLoading && assetTasks && assetTasks.rows.length === 0 && (
                        <p style={{ color: "var(--dim)" }}>
                          No remediation tasks reference this asset's evidence. Tasks are created
                          from Priorities or a finding's drawer — not invented here.
                        </p>
                      )}
                      {!assetTasksError && !assetTasksLoading && assetTasks && assetTasks.rows.length > 0 && (
                        <div style={{ display: "grid", gap: "8px" }}>
                          {assetTasks.rows.map((t) => (
                            <div key={t.id} className="spread" style={{ borderBottom: "1px solid var(--line)", paddingBottom: "8px" }}>
                              <span style={{ fontSize: "12.5px" }}>
                                <span className="mono" style={{ fontWeight: 600 }}>{t.rule_id}</span>
                                <span style={{ color: "var(--dim)" }}> · evidence {t.evidence_id}</span>
                                {t.owner && <span style={{ color: "var(--dim)" }}> · {t.owner}</span>}
                              </span>
                              <Badge tone={String(t.status || "").toUpperCase() === "VERIFIED" ? "green" : String(t.status || "").toUpperCase() === "COMPLETED" ? "cyan" : "amber"}>
                                {String(t.status || "—").toUpperCase()}
                              </Badge>
                            </div>
                          ))}
                          <Link
                            to="/remediation"
                            className="btn outline"
                            style={{ textDecoration: "none", fontSize: "12px", padding: "6px 12px", borderRadius: "var(--r)", justifySelf: "start" }}
                          >
                            Open task lifecycle view
                          </Link>
                        </div>
                      )}
                    </div>
                  )}

                  {activeTab >= 4 && activeTab <= 7 && (
                    <div style={{ fontSize: "13px", color: "var(--dim)", padding: "12px 0" }}>
                      No {tabNames[activeTab].toLowerCase()} verdict is provided by this asset endpoint.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
