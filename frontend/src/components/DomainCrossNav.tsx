import React from "react";
import { Link } from "react-router-dom";

/** Asset Discovery workspace navigation: the six domains answer one question —
 *  what is in this estate — so they are tabs of one workspace rather than six
 *  unrelated destinations. Each tab is a real route; nothing here invents a
 *  relationship between the domains (that vocabulary lives on the graph).
 */

export const DOMAIN_VIEWS: ReadonlyArray<{ id: string; label: string; path: string }> = [
  { id: "assets", label: "Assets", path: "/assets" },
  { id: "applications", label: "Applications", path: "/dev-sec-ops" },
  { id: "certificates", label: "Certificates", path: "/certificates" },
  { id: "network", label: "Network", path: "/network" },
  { id: "cloud", label: "Cloud", path: "/cloud" },
  { id: "hardware", label: "Hardware", path: "/hardware" },
];

export default function DomainCrossNav({ current }: { current: string }) {
  return (
    <nav aria-label="Asset discovery domains" style={{
      display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center",
      padding: "8px 10px", border: "1px solid var(--line)",
      borderRadius: "var(--r)", marginBottom: 12, background: "var(--panel-2)",
    }}>
      <span style={{ fontSize: 10, color: "var(--faint)" }}>Asset discovery</span>
      {DOMAIN_VIEWS.map((domain) => (
        <Link
          key={domain.id}
          to={domain.path}
          aria-current={current === domain.id ? "page" : undefined}
          style={{
            fontSize: 11, fontWeight: current === domain.id ? 700 : 400,
            color: current === domain.id ? "var(--cyan)" : "var(--dim)",
            textDecoration: "none",
            borderBottom: current === domain.id ? "1px solid var(--cyan)" : "none",
          }}
        >
          {domain.label}
        </Link>
      ))}
    </nav>
  );
}
