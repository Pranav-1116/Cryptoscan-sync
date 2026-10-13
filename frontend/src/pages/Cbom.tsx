import { Link } from "react-router-dom";
import React, { useEffect, useState } from "react";
import { Badge } from "../components/ui";
import { apiCbomQuery, apiCbomCoverage } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import PortfolioDependencyPanel from "../components/PortfolioDependencyPanel";
import { ICON_SM, IconCaretDown, IconCaretRight } from "../components/icons";

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
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [search, setSearch] = useState("");
  const [filterLinkage, setFilterLinkage] = useState<string>("ALL");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [coverage, setCoverage] = useState<any>(null);
  const [components, setComponents] = useState<CbomItem[]>([]);
  const [queryNote, setQueryNote] = useState<string>("");

  useEffect(() => {
    let alive = true;
    async function loadCbom() {
      setLoading(true);
      try {
        const [qRes, covRes] = await Promise.all([
          apiCbomQuery(),
          apiCbomCoverage(),
        ]);

        if (!alive) return;

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
        if (alive) setOffline(true);
      } finally {
        if (alive) setLoading(false);
      }
    }

    loadCbom();
    return () => { alive = false; };
  }, []);

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
      {/* CBOM Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "24px", flexWrap: "wrap", gap: "16px" }}>
        <div>
          <div style={{ fontSize: "12px", fontFamily: "var(--mono)", color: "var(--cyan)", letterSpacing: "0.1em", textTransform: "uppercase" }}>
            CycloneDX 1.5 Cryptographic Specification
          </div>
          <h1 style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0 6px" }}>Cryptographic Bill of Materials</h1>
          <p style={{ margin: 0, fontSize: "13.5px", color: "var(--dim)" }}>
            Cross-BOM identity inventory from live query results — no client-side inference.
          </p>
        </div>

        <div style={{ display: "flex", gap: "10px" }}>
          <AuthenticatedDownload
            path="/api/v1/cbom"
            filename="cryptoscan-cbom.json"
            className="btn outline"
            style={{ fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            Export CycloneDX 1.5 JSON
          </AuthenticatedDownload>
          <Link
            to="/dependency-graph"
            className="btn primary"
            style={{ textDecoration: "none", fontSize: "12px", padding: "8px 14px", borderRadius: "var(--r)" }}
          >
            View Dependency Graph
          </Link>
        </div>
      </div>

      {offline && !loading && (
        <div className="panel" style={{ padding: "14px 18px", marginBottom: "18px", border: "1px solid var(--amber)", color: "var(--amber)", fontSize: "13px" }}>
          BOM sources are unreachable. The table below is empty because no live query result is available — nothing is shown from cache or guesswork.
        </div>
      )}

      {/* Stats bar */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "14px", marginBottom: "20px" }}>
        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Identities
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, margin: "4px 0" }}>
            {loading ? "..." : components.length}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Distinct canonical identities across all BOMs
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Linked Identities
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: "var(--cyan)", margin: "4px 0" }}>
            {loading ? "..." : linkedCount}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Present in 2 or more BOMs (association, not asset identity)
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Cross-BOM Conflicts
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: conflictCount > 0 ? "var(--red)" : "var(--text)", margin: "4px 0" }}>
            {loading ? "..." : conflictCount}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Unambiguous value disagreements between BOMs
          </div>
        </div>

        <div className="panel" style={{ padding: "16px" }}>
          <div style={{ fontSize: "11px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>
            Coverage Percentage
          </div>
          <div style={{ fontSize: "26px", fontWeight: 700, color: "var(--cyan)", margin: "4px 0" }}>
            {loading ? "..." : `${coverage?.coverage_pct ?? 0}%`}
          </div>
          <div style={{ fontSize: "12px", color: "var(--dim)" }}>
            Systems with active CBOMs: {coverage?.with_cbom ?? 0} / {coverage?.systems ?? 0}
          </div>
        </div>
      </div>

      {/* Search & Linkage Filter */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "16px", flexWrap: "wrap", marginBottom: "16px" }}>
        <div style={{ position: "relative", flex: "1", minWidth: "260px", maxWidth: "420px" }}>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search identity, label, kind or BOM…"
            style={{
              width: "100%", padding: "9px 14px", fontSize: "13px",
              background: "var(--bg-2)", color: "var(--text)",
              border: "1px solid var(--line)", borderRadius: "var(--r)",
              fontFamily: "var(--mono)"
            }}
          />
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          {LINKAGE_FILTERS.map((r) => (
            <button
              key={r}
              onClick={() => setFilterLinkage(r)}
              className="btn sm"
              style={{
                background: filterLinkage === r ? "var(--cyan)" : undefined,
                color: filterLinkage === r ? "var(--on-accent)" : undefined,
                fontWeight: filterLinkage === r ? 700 : 500
              }}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* CBOM Table with Expandable Rows */}
      <div className="panel" style={{ padding: "20px" }}>
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

      <PortfolioDependencyPanel />
    </div>
  );
}
