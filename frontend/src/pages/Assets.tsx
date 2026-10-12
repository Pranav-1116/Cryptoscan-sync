import React, { useState, useEffect, useRef } from "react";
import { Badge, Tabs } from "../components/ui";
import { Link } from "react-router-dom";
import { tenantFetch } from "../lib/api";
import { IconEstate } from "../components/icons";

// GET /api/v1/assets serializes CryptoAsset columns; only GET /assets/{id}
// adds evidence_ids. Neither endpoint provides a PQC verdict or dependencies.
interface AssetApiRow {
  id: string;
  algorithm?: string | null;
  key_size?: number | null;
  file_path?: string | null;
  owner?: string | null;
  lifecycle_state?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  extra?: { first_seen_at?: string | null; last_seen_at?: string | null; protocol?: string | null } | null;
  evidence_ids?: string[];
}

interface AssetRecord {
  id: string;
  name: string;
  algorithm: string | null;
  keySize: number | null;
  protocol: string | null;
  sourcePath: string | null;
  owner: string | null;
  lifecycleState: string | null;
  createdAt: string | null;
  updatedAt: string | null;
  firstObserved: string | null;
  lastObserved: string | null;
  evidenceIds: string[];
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
    keySize: typeof row.key_size === "number" && Number.isFinite(row.key_size) && row.key_size > 0 ? row.key_size : null,
    protocol: observed(extra?.protocol),
    sourcePath: observed(row.file_path),
    owner: observed(row.owner),
    lifecycleState: observed(row.lifecycle_state),
    createdAt: observed(row.created_at),
    updatedAt: observed(row.updated_at),
    firstObserved: observed(extra?.first_seen_at),
    lastObserved: observed(extra?.last_seen_at),
    evidenceIds: Array.isArray(row.evidence_ids) ? row.evidence_ids.filter((item): item is string => !!observed(item)) : [],
  };
}

function requestError(status: number, subject: string): string {
  if (status === 401) return `Authentication required to view ${subject}. Sign in and try again.`;
  if (status === 403) return `Access denied to ${subject} for this account or tenant.`;
  return `Unable to load ${subject} (HTTP ${status}).`;
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

  const tabNames = ["Overview", "Evidence", "Dependencies", "Usage", "History", "Policy", "PQC"];

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
                        <Badge tone="slate">{asset.lifecycleState ?? "Unknown"}</Badge>
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
                          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase" }}>Evidence</div>
                          <div style={{ marginTop: "2px" }}>{detailLoading ? "Loading evidence IDs..." : detailError ?? (detail?.id === selectedId && detail.evidenceIds.length ? `${detail.evidenceIds.length} linked ID(s); integrity not verified` : "Not observed; integrity not verified")}</div>
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
                    <div style={{ fontSize: "13px", color: "var(--dim)" }}>
                      Dependencies are not provided by this asset endpoint. No dependency relationship is verified here.
                    </div>
                  )}

                  {activeTab >= 3 && (
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
