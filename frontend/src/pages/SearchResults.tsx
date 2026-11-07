import React, { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Panel, PageHead } from "../components/ui.jsx";
import { activeTenantId, apiAlgorithmCatalog, apiProtocolCatalog, apiHardwareCatalog, apiRuntimeFindings, apiAssetsSearch, apiVendors, apiCertificateEstate, apiFindings, type ApiResult } from "../lib/api.js";
import { IconCrypto, IconNetwork, IconHardware, IconWarn, IconEstate, ICON_MD, type Icon } from "../components/icons";

/* Full search results page — queries the LIVE catalogs and the runtime
   findings store. There is no local/demo index: with an empty estate the
   catalogs (algorithms/protocols/hardware) still return real reference data,
   while findings return zero until a scan runs. */

interface Item { name: string; to: string; meta: string }
interface Group { label: string; icon: Icon; items: Item[] }
interface SourceBoundary { label: string; reason: string }

/** A source that was not searched is not a source with no results (gap
 *  analysis §A: "search results preserve tenant and permission boundaries"). */
function boundaryFor(label: string, res: ApiResult<unknown>): SourceBoundary {
  const detail = String(res.detail || res.error || "");
  const denied = /denied|forbidden|403|unauthor|401/i.test(detail);
  return {
    label,
    reason: denied
      ? `access denied for this account or tenant — not searched (${detail})`
      : `unreachable — not searched (${detail || "no response"})`,
  };
}

export default function SearchResults() {
  const [q, setQ] = useState("");
  const [input, setInput] = useState("");
  const [groups, setGroups] = useState<Group[]>([]);
  const [boundaries, setBoundaries] = useState<SourceBoundary[]>([]);
  const [loading, setLoading] = useState(false);
  const { search } = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const term = new URLSearchParams(search).get("q") ?? "";
    setQ(term);
    setInput(term);
  }, [search]);

  const submit = () => {
    if (input.trim()) navigate(`/search-results?q=${encodeURIComponent(input.trim())}`);
  };

  useEffect(() => {
    if (!q.trim()) { setGroups([]); setBoundaries([]); return; }
    let cancelled = false;
    setLoading(true);
    (async () => {
      const term = q.trim();
      const [alg, proto, hw, find, assets, vendors, certs, evidence] = await Promise.all([
        apiAlgorithmCatalog({ q: term }),
        apiProtocolCatalog(),
        apiHardwareCatalog(),
        apiRuntimeFindings(100, term),
        apiAssetsSearch(term),
        apiVendors(term),
        apiCertificateEstate(term),
        apiFindings({ q: term, page_size: 25 }),
      ]);
      const out: Group[] = [];
      const boundaries: SourceBoundary[] = [];
      if (assets.source !== "live") boundaries.push(boundaryFor("Assets (estate)", assets));
      if (alg.source !== "live") boundaries.push(boundaryFor("Algorithms", alg));
      if (proto.source !== "live") boundaries.push(boundaryFor("Protocols", proto));
      if (hw.source !== "live") boundaries.push(boundaryFor("Hardware", hw));
      if (find.source !== "live") boundaries.push(boundaryFor("Findings (runtime)", find));
      if (vendors.source !== "live") boundaries.push(boundaryFor("Vendors", vendors));
      if (certs.source !== "live") boundaries.push(boundaryFor("Certificates", certs));
      if (evidence.source !== "live") boundaries.push(boundaryFor("Evidence (register)", evidence));
      // §5 (round 62): real asset search — SERVER-side, across the whole
      // estate (asset id, identity spine, algorithm, file location), not a
      // client-side filter of loaded rows. Reference-catalog matches below
      // are reference data; these are OBSERVED inventory.
      const assetRows = ((assets.data as any)?.assets ?? []) as any[];
      const assetTotal = Number((assets.data as any)?.total_count ?? assetRows.length) || assetRows.length;
      if (assetRows.length) {
        out.push({ label: `Assets (estate, ${assetTotal} match${assetTotal === 1 ? "" : "es"})`, icon: IconEstate, items: assetRows.slice(0, 25).map((a: any) => ({
          name: `${a.algorithm ?? "UNKNOWN"}${a.file_path ? ` · ${String(a.file_path).split("/").pop()}` : ""}`,
          to: "/assets", meta: a.lifecycle_state ?? "",
        })) });
      }
      const algRows = (alg.data?.algorithms ?? []) as any[];
      if (algRows.length) {
        out.push({ label: "Algorithms", icon: IconCrypto, items: algRows.slice(0, 25).map((a) => ({
          name: `${a.name ?? a.algorithm ?? a.id}${a.family ? ` · ${a.family}` : ""}`,
          to: "/catalog", meta: a.status ?? a.quantum_status ?? "",
        })) });
      }
      const protoRows = ((proto.data as any)?.protocols ?? (proto.data as any)?.items ?? []) as any[];
      const pHits = protoRows.filter((p) => JSON.stringify(p).toLowerCase().includes(term.toLowerCase()));
      if (pHits.length) {
        out.push({ label: "Protocols", icon: IconNetwork, items: pHits.slice(0, 25).map((p) => ({
          name: p.name ?? p.protocol ?? p.id, to: "/protocols", meta: p.status ?? p.category ?? "",
        })) });
      }
      const hwRows = ((hw.data as any)?.devices ?? (hw.data as any)?.items ?? (hw.data as any)?.hardware ?? []) as any[];
      const hHits = hwRows.filter((h) => JSON.stringify(h).toLowerCase().includes(term.toLowerCase()));
      if (hHits.length) {
        out.push({ label: "Hardware", icon: IconHardware, items: hHits.slice(0, 25).map((h) => ({
          name: h.name ?? h.model ?? h.id, to: "/hardware", meta: h.category ?? h.status ?? "",
        })) });
      }
      // §5 (round 65): runtime findings are searched SERVER-side across the
      // whole store (the term goes to the API), not filtered from the first
      // 100 recent rows in the browser — so older matches are found too.
      const fRows = ((find.data as any)?.findings ?? []) as any[];
      const fTotal = Number((find.data as any)?.total_count ?? fRows.length) || fRows.length;
      if (fRows.length) {
        out.push({ label: `Findings (runtime, ${fTotal} match${fTotal === 1 ? "" : "es"})`, icon: IconWarn, items: fRows.slice(0, 25).map((f) => ({
          name: `${f.hostname ?? f.process_name ?? f.algorithm ?? f.id}${f.algorithm ? ` · ${f.algorithm}` : ""}`,
          to: "/runtime", meta: f.status ?? f.kind ?? "",
        })) });
      }
      // §A: "Global asset, vendor, certificate and evidence search" — each
      // group is server-side term search over its whole store, same as assets.
      const vendorRows = ((vendors.data as any)?.vendors ?? []) as any[];
      if (vendorRows.length) {
        out.push({ label: `Vendors (${vendorRows.length} match${vendorRows.length === 1 ? "" : "es"})`, icon: IconEstate, items: vendorRows.slice(0, 25).map((v: any) => ({
          name: v.name ?? v.id, to: "/vbom",
          meta: [v.vendor_type, v.criticality].filter(Boolean).join(" · "),
        })) });
      }
      const certRows = ((certs.data as any)?.certificates ?? []) as any[];
      const certTotal = Number((certs.data as any)?.total_count ?? certRows.length) || certRows.length;
      if (certRows.length) {
        out.push({ label: `Certificates (${certTotal} match${certTotal === 1 ? "" : "es"})`, icon: IconCrypto, items: certRows.slice(0, 25).map((c: any) => ({
          name: c.subject ?? c.fingerprint_sha256 ?? c.id, to: "/certificates",
          meta: c.issuer ?? "",
        })) });
      }
      const evRows = ((evidence.data as any)?.findings ?? []) as any[];
      const evTotal = Number((evidence.data as any)?.total_count ?? evRows.length) || evRows.length;
      if (evRows.length) {
        out.push({ label: `Evidence (register, ${evTotal} match${evTotal === 1 ? "" : "es"})`, icon: IconWarn, items: evRows.slice(0, 25).map((e: any) => ({
          name: `${e.evidence_id ?? e.id}${e.algorithm ? ` · ${e.algorithm}` : ""}`, to: "/findings",
          meta: e.file_path ?? "",
        })) });
      }
      if (!cancelled) { setGroups(out); setBoundaries(boundaries); }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [q]);

  const total = groups.reduce((n, g) => n + g.items.length, 0);

  return (
    <>
      <PageHead
        crumb="search"
        title={q ? `Results for “${q}”` : "Search"}
        sub={q ? (loading ? "searching live catalogs…" : `${total} matches across algorithms, protocols, hardware and findings`) : "Type a query in the header search box"}
        right={q ? <span className="mono faint" style={{ fontSize: 12 }}>{total} RESULTS</span> : undefined}
      />
      {q && (
        <div className="row" style={{ marginBottom: 16 }}>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
            placeholder="search again…"
            style={{
              flex: 1, maxWidth: 420, background: "color-mix(in srgb, var(--bg) 80%, transparent)", border: "1px solid var(--line-strong)",
              borderRadius: "var(--r)", color: "var(--text)", fontFamily: "var(--mono)", fontSize: 14, padding: "9px 14px", outline: "none",
            }}
          />
          <button className="btn sm" onClick={submit}>Search</button>
        </div>
      )}
      {total === 0 && q && !loading && (
        <Panel title="No matches" sub={`nothing found for “${q}”`}>
          <div className="dim" style={{ fontSize: 13.5 }}>
            Try an algorithm (RSA, AES, ML-KEM), a protocol, a hardware class, or a finding id. Findings appear only after a real scan.
          </div>
        </Panel>
      )}
      {q && !loading && boundaries.length > 0 && (
        <Panel title="Search boundaries" sub="sources this search could not read" className="mt">
          <div className="dim" style={{ fontSize: 12.5, marginBottom: 8 }}>
            Results are scoped to tenant <span className="mono">{activeTenantId() ?? "unknown"}</span>.
            A source that was not searched is not a source with no results.
          </div>
          {boundaries.map((b) => (
            <div key={b.label} data-testid="search-boundary" style={{ fontSize: 12.5, padding: "4px 0" }}>
              <strong>{b.label}</strong> — {b.reason}
            </div>
          ))}
        </Panel>
      )}
      {q && !loading && boundaries.length === 0 && groups.length > 0 && (
        <div className="dim" style={{ fontSize: 11, marginBottom: 10 }}>
          Results scoped to tenant <span className="mono">{activeTenantId() ?? "unknown"}</span> · every source answered within this tenant boundary.
        </div>
      )}
      {groups.map((g, gi) => (
        <Panel key={g.label} title={<span className="ico-row"><g.icon className="ico" size={ICON_MD} /><span>{g.label}</span></span>} sub={`${g.items.length} matches`} className="mt" style={gi === 0 ? { marginTop: 0 } : undefined}>
          <div style={{ display: "flex", flexDirection: "column" }}>
            {g.items.map((it, i) => (
              <Link key={`${it.name}-${i}`} to={it.to} style={{ display: "flex", justifyContent: "space-between", gap: 14, padding: "7px 10px", borderRadius: "var(--r)", color: "var(--text)" }}>
                <span>{it.name}</span>
                <span className="mono faint" style={{ fontSize: 12 }}>{it.meta}</span>
              </Link>
            ))}
          </div>
        </Panel>
      ))}
    </>
  );
}
