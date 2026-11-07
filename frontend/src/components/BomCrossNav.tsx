import React from "react";
import { Link, useLocation } from "react-router-dom";

/** Six-BOM navigation and the cross-BOM relationship vocabulary (gap
 *  analysis §A: "cross-BOM relationships are navigable").
 *
 *  The six BOMs are one estate seen from six angles. This strip:
 *  - navigates between the six BOM views, carrying the current ?focus= term
 *    so a component followed from SBOM is the same term in CBOM and NBOM;
 *  - names the cross-BOM relationship this BOM participates in (software
 *    component → crypto library, endpoint → certificate → algorithm, …) with
 *    the counterpart view as a real link;
 *  - never claims a relationship it cannot name: each link here is the
 *    roadmap's declared vocabulary, not an inferred edge.
 */

export const BOM_VIEWS: ReadonlyArray<{ id: string; label: string; path: string }> = [
  { id: "sbom", label: "SBOM", path: "/sbom" },
  { id: "cbom", label: "CBOM", path: "/cbom" },
  { id: "hbom", label: "HBOM", path: "/hbom" },
  { id: "nbom", label: "NBOM", path: "/nbom" },
  { id: "vbom", label: "VBOM", path: "/vbom" },
  { id: "techbom", label: "TechBOM", path: "/live-asset-intelligence" },
];

export const CROSS_BOM_RELATIONSHIPS: ReadonlyArray<{
  from: string; to: string; relationship: string; toPath: string;
}> = [
  { from: "SBOM", to: "CBOM", relationship: "software component → crypto library", toPath: "/cbom" },
  { from: "CBOM", to: "NBOM", relationship: "library → algorithm → operation", toPath: "/nbom" },
  { from: "HBOM", to: "TechBOM", relationship: "hardware → HSM → application", toPath: "/live-asset-intelligence" },
  { from: "NBOM", to: "CBOM", relationship: "endpoint → certificate → algorithm", toPath: "/cbom" },
  { from: "VBOM", to: "TechBOM", relationship: "vendor → product → deployed asset", toPath: "/live-asset-intelligence" },
  { from: "TechBOM", to: "SBOM", relationship: "all technology assets and systems", toPath: "/sbom" },
];

export default function BomCrossNav({ current }: { current: string }) {
  const location = useLocation();
  const focus = new URLSearchParams(location.search).get("focus")?.trim() || "";
  const focusQuery = focus ? `?focus=${encodeURIComponent(focus)}` : "";
  const here = current.toUpperCase();

  return (
    <nav aria-label="Cross-BOM navigation" style={{
      display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
      padding: "8px 10px", border: "1px solid var(--line)",
      borderRadius: "var(--r)", marginBottom: 12, background: "var(--panel-2)",
    }}>
      {BOM_VIEWS.map((bom) => (
        <Link
          key={bom.id}
          to={`${bom.path}${focusQuery}`}
          aria-current={here === bom.label ? "page" : undefined}
          style={{
            fontSize: 11, fontWeight: here === bom.label ? 700 : 400,
            color: here === bom.label ? "var(--cyan)" : "var(--dim)",
            textDecoration: "none", borderBottom: here === bom.label ? "1px solid var(--cyan)" : "none",
          }}
        >
          {bom.label}
        </Link>
      ))}
      <span style={{ fontSize: 10, color: "var(--faint)" }}>
        {CROSS_BOM_RELATIONSHIPS.filter((r) => r.from === here).map((r, i) => (
          <React.Fragment key={r.to}>
            {i > 0 ? " · " : ""}
            <Link to={`${r.toPath}${focusQuery}`} style={{ color: "var(--dim)" }}>
              {r.relationship} → {r.to}
            </Link>
          </React.Fragment>
        ))}
      </span>
      {focus && (
        <span data-testid="bom-focus" style={{ fontSize: 10, color: "var(--amber)" }}>
          cross-BOM focus: <strong>{focus}</strong> — the same term is carried
          across every BOM view
        </span>
      )}
    </nav>
  );
}
