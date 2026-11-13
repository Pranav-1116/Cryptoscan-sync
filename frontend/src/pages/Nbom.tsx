import React, { useCallback, useEffect, useState, useMemo } from "react";
import BomCrossNav from "../components/BomCrossNav";
import { CanonicalDetailLink } from "../components/AssetDetail";
import { Link, useSearchParams } from "react-router-dom";
import { Panel, Badge, Bar, Ring, Drawer } from "../components/ui";
import { useApi } from "../lib/apiUi.jsx";
import {
  apiNbomLive, NbomCascadeEntry, NbomComponent, NbomResponse,
  apiNbomWorkspaceOverview, apiNbomWorkspaceEndpoints, apiNbomWorkspaceEndpointDetail,
  apiNbomWorkspaceAssets, apiNbomWorkspaceServices, apiNbomWorkspaceTls,
  apiNbomWorkspaceSsh, apiNbomWorkspaceIpsec, apiNbomWorkspaceCertificates,
  apiNbomWorkspaceDependencies, apiNbomWorkspaceChanges, apiNbomWorkspaceEvidence,
  apiNbomWorkspaceHistory, apiNbomWorkspaceExport, type NbomEndpointRow,
} from "../lib/api.js";
import { IconCrypto, IconHardware, IconTarget, IconClock, IconSecurity, IconWarn, IconSearch, IconInfo, IconCertificate } from "../components/icons";

/* NBOM — Network Bill of Materials — visualized.
 * The CBOM covers cryptography in source. This covers what is exposed
 * on the wire — listeners, certs, cipher suites, tunnels — ranked by
 * severity × blast radius so the top row is the single change that
 * removes most risk. */

const SEV_TONE: Record<string, string> = {
  critical: "red", high: "orange", medium: "amber", low: "blue", info: "slate",
};

function prop(component: NbomComponent, key: string): string | undefined {
  // CycloneDX allows a component with no properties array. Reading `.find` off
  // it threw and blanked the whole page — one sparse component, no NBOM.
  const properties = component.properties;
  if (!Array.isArray(properties)) return undefined;
  return properties.find((p) => p.name === `cryptoscan:${key}`)?.value;
}

const NBOM_TABS: Array<{ id: string; label: string }> = [
  { id: "overview", label: "NBOM Overview" },
  { id: "assets", label: "Network Asset Inventory" },
  { id: "endpoints", label: "Endpoint Inventory" },
  { id: "services", label: "Service & Port Inventory" },
  { id: "tls", label: "TLS Intelligence" },
  { id: "ssh", label: "SSH Intelligence" },
  { id: "ipsec", label: "IPsec / VPN Intelligence" },
  { id: "certificates", label: "Certificate Exposure" },
  { id: "dependencies", label: "Network Dependencies" },
  { id: "changes", label: "Network Change History" },
  { id: "evidence", label: "Evidence & Provenance" },
  { id: "history", label: "NBOM History" },
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

function NegotiationBadge({ negotiation }: { negotiation: { state: string; basis: string } }) {
  return negotiation.state === "OBSERVED"
    ? <Badge tone="pass">observed</Badge>
    : <Badge tone="slate">unknown</Badge>;
}

function NegotiatedValue({ value }: { value: string }) {
  return value === "unknown"
    ? <span style={{ fontSize: 11, fontStyle: "italic", color: "var(--faint)" }}>unknown</span>
    : <span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{value}</span>;
}

export default function Nbom() {
  const [wsParams, setWsParams] = useSearchParams();
  const active = NBOM_TABS.some((t) => t.id === wsParams.get("tab")) ? wsParams.get("tab") as string : "overview";
  const [data, setData] = useState<NbomResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<NbomCascadeEntry | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await apiNbomLive();
    // `call()` reports through `source`/`data`, never `ok`: gating on `ok` was
    // always false, so a working endpoint rendered as "no network inventory".
    if (res.source === "live" && res.data) {
      setData(res.data);
      setError(null);
    } else {
      // A failed read is not an empty network. Say which one happened.
      setError(res.detail || res.error || "The NBOM read did not return");
      setData(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => { void load(); }, [load]);

  const summary = data?.summary;
  const components = data?.nbom.components ?? [];
  const sev = summary?.by_severity ?? {};
  const critical = sev.critical ?? 0;
  const high = sev.high ?? 0;
  const totalFindings = (Object.values(sev) as number[]).reduce((a, b) => a + (Number(b) || 0), 0);

  const analytics = useMemo(() => {
    const byKind: Record<string, number> = {};
    components.forEach((c) => {
      const k = prop(c, "kind") || "unknown";
      byKind[k] = (byKind[k] || 0) + 1;
    });
    const sortedKind = Object.entries(byKind).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const unobserved = summary?.unobserved ?? 0;
    const observed = components.length - unobserved;
    return { byKind: sortedKind, unobserved, observed };
  }, [components, summary]);

  // The share of wire components the scan actually observed. There is no
  // server-side posture score, and a client must not invent one.
  const observedPct = components.length ? analytics.observed / components.length : null;
  const ringTone = !data ? "slate" : critical ? "red" : high ? "amber" : "slate";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      <BomCrossNav current="NBOM" />
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid var(--accent)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: !data ? "var(--slate)" : critical ? "var(--red)" : "var(--green)" }} /> BOMS · NBOM · NETWORK EXPOSURE
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconCrypto size={18} /></span>
            Network Bill of Materials
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            What is <b style={{ color: "var(--text)" }}>exposed on the wire</b> — listeners, certificates, cipher suites, tunnels — with the dependency graph answering <span style={{ color: "var(--accent)" }}>what breaks when one component is replaced</span>.
          </p>
          <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
            <span className="kicker" style={{ fontSize: 10 }}>SEVERITY × BLAST RADIUS</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span className="kicker" style={{ fontSize: 10 }}>SCANNER-DERIVED</span>
            <span style={{ color: "var(--line-strong)" }}>·</span>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>not declared — probed</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={observedPct ?? 0} label={loading ? "…" : data ? String(components.length) : "—"} sub="components" tone={ringTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>WIRE COMPONENTS</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{!data ? "NBOM not read" : critical ? `${critical} critical by server severity` : high ? `${high} high by server severity` : components.length ? "No critical/high severity returned" : "NBOM returned no components"}</div>
              <div style={{ marginTop: 6 }}><Bar value={observedPct ?? 0} tone={ringTone} /></div>
              <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>{observedPct == null ? "no components to probe" : `${Math.round(observedPct * 100)}% probed by the scanner`}</div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Link to="/live-scanners" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Scan operations →</Link>
            <Link to="/dependency-graph" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Dependency graph →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{summary?.unobserved ? `${summary.unobserved} unobserved` : components.length ? "all observed" : "—"}</span>
          </div>
        </div>
      </div>

      <div role="tablist" aria-label="NBOM sections" style={{ display: "flex", gap: 6, flexWrap: "wrap", margin: "2px 0 16px" }}>
        {NBOM_TABS.map((t) => (
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
      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconTarget size={12} /> WIRE COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : data ? components.length.toLocaleString() : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Listeners · certs · tunnels</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid var(--accent)", color: "var(--accent)" }}><IconHardware size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{analytics.observed} observed</span><span style={{ color: analytics.unobserved ? "var(--amber)" : "var(--green)" }}>{analytics.unobserved ? `${analytics.unobserved} unobserved` : "all probed"}</span></div>
            <Bar value={components.length ? analytics.observed / components.length : 0} tone={analytics.unobserved ? "amber" : "green"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Scanner-found — not declared</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${critical ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconWarn size={12} /> CRITICAL FINDINGS</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: critical ? "var(--red)" : data ? "var(--text)" : "var(--slate)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : data ? critical : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{totalFindings} total findings</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: critical ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid ${critical ? "var(--red)" : "var(--green)"}`, color: critical ? "var(--red)" : "var(--green)" }}><IconSecurity size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{critical ? `${Math.round((critical / Math.max(1, totalFindings)) * 100)}% of findings` : "no critical"}</span><span style={{ color: critical ? "var(--red)" : "var(--green)" }}>{critical ? "patch now" : "clear"}</span></div>
            <Bar value={totalFindings ? critical / totalFindings : 0} tone={critical ? "red" : "green"} />
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${analytics.unobserved ? "var(--amber)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconClock size={12} /> UNOBSERVED</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: analytics.unobserved ? "var(--amber)" : "var(--dim)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : data ? analytics.unobserved : "—"}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Never successfully probed</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: analytics.unobserved ? "color-mix(in srgb, var(--amber) 12%, transparent)" : "color-mix(in srgb, var(--green) 12%, transparent)", border: `1px solid ${analytics.unobserved ? "var(--amber)" : "var(--green)"}`, color: analytics.unobserved ? "var(--amber)" : "var(--green)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
              <Badge tone={analytics.unobserved ? "amber" : "green"}>{analytics.unobserved ? "probe gaps" : "fully probed"}</Badge>
              {analytics.unobserved ? <Badge tone="slate">unknown ≠ healthy</Badge> : null}
            </div>
            <Bar value={components.length ? analytics.unobserved / components.length : 0} tone={analytics.unobserved ? "amber" : "green"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Unknown — not healthy until observed</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)", background: "color-mix(in srgb, var(--violet) 4%, var(--panel))" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>MIGRATION PRIORITY</div>
              <div style={{ fontSize: 15, fontWeight: 800, margin: "8px 0 2px", color: "var(--violet)", lineHeight: 1.2 }}>{summary?.migration_priority?.length ?? 0} ranked</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Severity × blast radius</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid var(--violet)", color: "var(--violet)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, height: 8, background: "var(--bg-2)", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: critical ? "45%" : high ? "35%" : "12%", height: "100%", background: "var(--red)", opacity: .9 }} />
              <div style={{ width: high ? "30%" : "25%", height: "100%", background: "var(--amber)", opacity: .9 }} />
              <div style={{ flex: 1, height: "100%", background: "var(--violet)", opacity: .7 }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>{critical} critical</span><span>{high} high</span><span>rest</span></div>
          </div>
        </div>
      </div>

      {/* Severity distribution 5-col grid visual */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 10, marginBottom: 14 }}>
        {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
          const n = sev[s] ?? 0;
          const has = n > 0;
          const tone = SEV_TONE[s];
          const pct = totalFindings ? n / totalFindings : 0;
          return (
            <div key={s} className="panel" style={{ padding: "12px 14px", borderTop: `2px solid ${has ? `var(--${tone})` : "var(--line)"}`, textAlign: "center" }}>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", textTransform: "uppercase" }}>{s}</div>
              <div style={{ fontSize: 22, fontWeight: 800, fontFamily: "var(--mono)", color: has ? `var(--${tone})` : "var(--dim)", margin: "6px 0 4px" }}>{n}</div>
              <Bar value={pct} tone={has ? tone : "slate"} />
              <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>{totalFindings ? `${Math.round(pct * 100)}%` : "—"}</div>
            </div>
          );
        })}
      </div>

      {/* Analytics strip */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Network surface by kind" sub="top listener / cert / tunnel types on the wire" style={{ padding: "14px 16px" }}>
          {analytics.byKind.length ? analytics.byKind.map(([kind, n]) => {
            const pct = n / Math.max(1, components.length);
            return (
              <div key={kind} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                <span style={{ width: 110, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{kind}</span>
                <div style={{ flex: 1 }}><Bar value={pct} tone={kind === "certificate" ? "violet" : "cyan"} /></div>
                <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 36, textAlign: "right" }}>{n}</span>
              </div>
            );
          }) : <div style={{ fontSize: 12, color: "var(--dim)", padding: "8px 0" }}>No wire components inventoried yet</div>}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>Source: live network scan · not declared inventory</div>
        </Panel>

        <Panel title="Blast-radius signal" sub="how far a replacement propagates" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: totalFindings ? "color-mix(in srgb, var(--red) 12%, transparent)" : "color-mix(in srgb, var(--green) 12%, transparent)", border: `2px solid ${totalFindings ? "var(--red)" : "var(--green)"}`, display: "grid", placeItems: "center", color: totalFindings ? "var(--red)" : "var(--green)", fontSize: 18, fontWeight: 800 }}>{summary?.migration_priority?.[0]?.affected_count ?? 0}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Largest blast radius</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>{summary?.migration_priority?.[0]?.name?.slice(0, 40) ?? "no priority yet"}</div>
              <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 2 }}>{summary?.migration_priority?.length ?? 0} components ranked</div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--red)" }}>{critical + high}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>CRITICAL+HIGH</div></div>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--amber)" }}>{sev.medium ?? 0}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>MEDIUM</div></div>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800 }}>{sev.info ?? 0}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>INFO</div></div>
          </div>
        </Panel>

        <Panel title="Observation health" sub="probed vs never-seen on the wire" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <span style={{ flex: 1, padding: "8px 10px", borderRadius: "var(--r)", background: "color-mix(in srgb, var(--green) 10%, transparent)", border: "1px solid var(--green)", textAlign: "center" }}><div style={{ fontSize: 11, color: "var(--dim)" }}>Observed</div><div style={{ fontSize: 18, fontWeight: 800, color: "var(--green)" }}>{analytics.observed}</div></span>
            <span style={{ flex: 1, padding: "8px 10px", borderRadius: "var(--r)", background: analytics.unobserved ? "color-mix(in srgb, var(--amber) 10%, transparent)" : "var(--panel-2)", border: `1px solid ${analytics.unobserved ? "var(--amber)" : "var(--line)"}`, textAlign: "center" }}><div style={{ fontSize: 11, color: "var(--dim)" }}>Unobserved</div><div style={{ fontSize: 18, fontWeight: 800, color: analytics.unobserved ? "var(--amber)" : "var(--green)" }}>{analytics.unobserved}</div></span>
          </div>
          <div style={{ height: 8, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${components.length ? (analytics.observed / components.length) * 100 : 0}%`, background: "var(--green)" }} />
            <div style={{ flex: 1, background: "var(--amber)" }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>● probed</span><span>● never-seen (unknown)</span></div>
        </Panel>
      </div>

      {/* Migration priority */}
      <div className="panel" style={{ padding: 0, overflow: "hidden", marginBottom: 18 }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> Migration Priority</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Ranked by <b style={{ color: "var(--text)" }}>severity × blast radius</b> — top row removes the most risk · needs the dependency graph</p>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Badge tone={critical ? "red" : "green"}>{critical} critical</Badge>
            <Badge tone="violet">{summary?.migration_priority?.length ?? 0} ranked</Badge>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th><span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><IconCrypto size={12} /> Component</span></th>
                <th>Kind</th>
                <th>Severity</th>
                <th>Blast radius</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {(summary?.migration_priority ?? []).map((m) => {
                const tone = SEV_TONE[m.worst_severity || ""] || "slate";
                const maxRadius = Math.max(1, ...((summary?.migration_priority ?? []).map(x => x.affected_count)));
                const pct = m.affected_count / maxRadius;
                return (
                  <tr key={m.ref}>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
                        <span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: `color-mix(in srgb, var(--${tone}) 14%, transparent)`, border: `1px solid var(--${tone})`, color: `var(--${tone})`, fontSize: 9 }}>NB</span>
                        <span className="mono" style={{ fontWeight: 700, fontSize: 12 }}>{m.name ?? m.ref}</span>
                      </span>
                    </td>
                    <td><span style={{ padding: "3px 8px", borderRadius: 99, background: "var(--panel-2)", border: "1px solid var(--line)", fontSize: 11 }}>{Object.keys(m.by_kind ?? {}).join(", ") || "—"}</span></td>
                    <td>{m.worst_severity ? <Badge tone={tone}>{m.worst_severity}</Badge> : <span style={{ color: "var(--faint)", fontSize: 11 }}>—</span>}</td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 120 }}>
                        <div style={{ flex: 1, minWidth: 60 }}><Bar value={pct} tone={tone} /></div>
                        <span style={{ fontFamily: "var(--mono)", fontWeight: 700, fontSize: 12 }}>{m.affected_count}</span>
                      </div>
                    </td>
                    <td><button className="btn sm" onClick={() => setSelected(m)} style={{ fontSize: 11.5, padding: "4px 10px" }}>trace →</button></td>
                  </tr>
                );
              })}
              {(summary?.migration_priority ?? []).length === 0 && !loading && (
                <tr>
                  <td colSpan={5} style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}>
                    <div style={{ fontSize: 22 }}>◈</div>
                    <div style={{ fontWeight: 600, marginTop: 8, color: "var(--text)" }}>No findings to prioritize</div>
                    <div style={{ fontSize: 12, marginTop: 4 }}>{error ?? "Run a network scan in Operations to populate the NBOM — flat inventory cannot produce this ranking"}</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--red)", display: "inline-block" }} /> critical</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--amber)", display: "inline-block" }} /> high/medium</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--green)", display: "inline-block" }} /> observed</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>NEED DEPENDENCY GRAPH · NOT FLAT INVENTORY</span>
        </div>
      </div>

      {/* Blast radius detail */}
      {selected && (
        <div className="panel" style={{ padding: 0, overflow: "hidden", marginBottom: 18 }}>
          <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "color-mix(in srgb, var(--violet) 6%, var(--panel-2))" }}>
            <div>
              <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--violet)" }} /> Blast radius — {selected.name ?? selected.ref}</h3>
              <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Everything that must change if this component is replaced · {selected.affected.length} affected</p>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <Badge tone="violet">{selected.affected.length} affected</Badge>
              <button className="btn sm outline" onClick={() => setSelected(null)} style={{ fontSize: 11.5 }}>close ×</button>
            </div>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table className="tbl" style={{ width: "100%" }}>
              <thead><tr><th>Affected component</th><th>Kind</th><th>Status</th></tr></thead>
              <tbody>
                {selected.affected.map((a) => (
                  <tr key={a.ref}>
                    <td><span className="mono" style={{ fontWeight: 600 }}>{a.name}</span><span style={{ fontSize: 10, color: "var(--faint)", fontFamily: "var(--mono)", marginLeft: 6 }}>{a.ref.slice(0, 12)}…</span></td>
                    <td><Badge tone={a.kind === "certificate" ? "violet" : "slate"}>{a.kind ?? "—"}</Badge></td>
                    <td><Badge tone="amber">must change</Badge></td>
                  </tr>
                ))}
                {!selected.affected.length && (
                  <tr><td colSpan={3} style={{ padding: 20, textAlign: "center", color: "var(--dim)", fontSize: 12 }}>Nothing depends on this — it can be replaced in isolation.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {!loading && error && (
        <div role="status" style={{ padding: "10px 14px", marginBottom: 14, background: "color-mix(in srgb, var(--amber) 8%, transparent)", border: "1px solid var(--amber)", borderRadius: "var(--r)", fontSize: 12, color: "var(--amber)" }}>
          NBOM not read: {error}. Every figure above is a dash, because no network inventory was returned — an empty page is not an empty network.
        </div>
      )}

      {/* Inventory */}
      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> Wire Inventory</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11, color: "var(--dim)" }}>Every component on the wire · <span style={{ color: "var(--accent)" }}>observed ≠ healthy — unobserved is unknown</span></p>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Badge tone="green">{analytics.observed} observed</Badge>
            <Badge tone={analytics.unobserved ? "amber" : "green"}>{analytics.unobserved} unobserved</Badge>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead><tr><th>Component</th><th>Kind</th><th>Detail</th><th>Observed</th><th>Findings</th></tr></thead>
            <tbody>
              {components.slice(0, 100).map((c) => {
                const kind = prop(c, "kind") ?? "—";
                const observed = prop(c, "observed") !== "False";
                const detail = prop(c, "tls_version") ?? prop(c, "public_key_algorithm") ?? prop(c, "encryption") ?? prop(c, "protocol") ?? "—";
                // A component the scanner returned without a findings array is
                // "no findings recorded", not a TypeError that blanks the page.
                const findings = c["cryptoscan:findings"] ?? [];
                const worst = findings[0]?.severity;
                return (
                  <tr key={c["bom-ref"]} style={{ background: !observed ? "color-mix(in srgb, var(--amber) 5%, transparent)" : undefined }}>
                    <td><span className="mono" style={{ fontWeight: 600, fontSize: 12 }}>{c.name}</span></td>
                    <td><Badge tone={kind === "certificate" ? "violet" : kind === "listener" ? "cyan" : "slate"}>{kind}</Badge></td>
                    <td><span className="mono" style={{ fontSize: 11 }}>{detail}</span></td>
                    <td>{observed ? <Badge tone="green">observed</Badge> : <Badge tone="slate">unobserved</Badge>}</td>
                    <td>{worst ? <Badge tone={SEV_TONE[worst] ?? "slate"}>{findings.length} findings</Badge> : <span style={{ color: "var(--faint)", fontSize: 11 }}>—</span>}</td>
                  </tr>
                );
              })}
              {components.length > 100 && (
                <tr><td colSpan={5} style={{ padding: 12, textAlign: "center", color: "var(--faint)", fontSize: 11 }}>Showing 100 of {components.length} — full inventory available via export</td></tr>
              )}
              {!components.length && !loading && (
                <tr><td colSpan={5} style={{ padding: 28, textAlign: "center", color: "var(--dim)" }}><div style={{ fontWeight: 600, color: "var(--text)" }}>Nothing on the wire yet</div><div style={{ fontSize: 12, marginTop: 4 }}>Run a network scan — this inventory is scanner-derived, not declared</div></td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--green)", display: "inline-block" }} /> observed</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--amber)", display: "inline-block" }} /> unobserved</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>{components.length} components · scanner truth</span>
        </div>
      </div>
      </>)}
      {active === "assets" && <NbomAssets />}
      {active === "endpoints" && <NbomEndpoints />}
      {active === "services" && <NbomServices />}
      {active === "tls" && <NbomProtocol kind="tls" label="TLS Intelligence" />}
      {active === "ssh" && <NbomProtocol kind="ssh" label="SSH Intelligence" />}
      {active === "ipsec" && <NbomProtocol kind="ipsec" label="IPsec / VPN Intelligence" />}
      {active === "certificates" && <NbomCertificates />}
      {active === "dependencies" && <NbomDependencies />}
      {active === "changes" && <NbomChanges />}
      {active === "evidence" && <NbomEvidence />}
      {active === "history" && <NbomHistory />}
      {active === "export" && <NbomExport />}
    </div>
  );
}

/* ── workspace sections (docs/boms/01_PRODUCT_SPEC.md §4 navigation) ─── */

function NbomEndpoints() {
  const [q, setQ] = useState("");
  const read = useApi(() => apiNbomWorkspaceEndpoints(q || undefined), [q]);
  const rows = (read.data?.rows ?? []) as NbomEndpointRow[];
  const [selected, setSelected] = useState<NbomEndpointRow | null>(null);
  const detail = useApi(
    () => apiNbomWorkspaceEndpointDetail(selected?.endpoint ?? ""),
    [selected?.endpoint],
  );
  return (
    <>
      <Panel title="Endpoint Inventory" sub="negotiated TLS facts appear only where a handshake was observed — elsewhere the value is unknown">
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <input value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="search by endpoint or service"
            aria-label="search endpoints"
            style={{ flex: 1, minWidth: 220, padding: "7px 10px", borderRadius: "var(--r)", border: "1px solid var(--line-strong)", background: "var(--panel-2)", color: "var(--text)", fontSize: 12 }} />
          <Badge tone="slate">{read.data?.total ?? (read.source === "live" ? rows.length : "—")} endpoints</Badge>
        </div>
        <WsState read={read} noun="endpoint inventory">
          <WsTable
            head={["Endpoint", "Port", "Protocol", "Service", "TLS version", "Cipher suite", "Certificate", "Source", "First / last observed"]}
            colSpan={9}
            rows={rows.map((r) => (
              <tr key={r.endpoint} style={{ cursor: "pointer" }} onClick={() => setSelected(r)}>
                <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.endpoint}</span></td>
                <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.port ?? "—")}</span></td>
                <td><Badge tone="slate">{r.protocol || "—"}</Badge></td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.service || "NOT_COLLECTED"}</span></td>
                <td><NegotiatedValue value={r.tls_version} /></td>
                <td><NegotiatedValue value={r.cipher_suite} /></td>
                <td>{r.certificate
                  ? <Badge tone="violet">{String(r.certificate.subject || r.certificate.fingerprint_sha256 || "").slice(0, 24)}</Badge>
                  : <span style={{ fontSize: 11, color: "var(--faint)" }}>none served</span>}</td>
                <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.source}</span></td>
                <td><span style={{ fontSize: 10.5, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(r.first_observed ?? "—").slice(0, 10)} → {String(r.last_observed ?? "—").slice(0, 10)}</span></td>
              </tr>
            ))}
          />
        </WsState>
      </Panel>
      {selected && (
        <Drawer title={selected.endpoint} sub={`${selected.protocol || "—"} · port ${String(selected.port ?? "—")}`} onClose={() => setSelected(null)}>
          <CanonicalDetailLink assetRef={`net:${selected.endpoint}`} />
          {!detail.data ? <p className="faint" style={{ fontSize: 12 }}>{detail.running ? "Reading the endpoint…" : "The endpoint detail did not return."}</p> : (
            (() => {
              const d = detail.data as Record<string, any>;
              const e: NbomEndpointRow = d.endpoint ?? selected;
              return (
                <div style={{ display: "grid", gap: 12 }}>
                  <div style={{ display: "grid", gap: 6, fontSize: 12 }}>
                    <div><b>Endpoint</b> {e.endpoint} · <b>Service</b> {e.service || "NOT_COLLECTED"}</div>
                    <div><b>Source</b> {e.source}</div>
                    <div><b>First observed</b> {String(e.first_observed ?? "—").slice(0, 19)} · <b>Last observed</b> {String(e.last_observed ?? "—").slice(0, 19)}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>NEGOTIATED CRYPTOGRAPHY</div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                      <NegotiationBadge negotiation={e.negotiation} />
                      <span style={{ fontSize: 11.5 }}>TLS <NegotiatedValue value={e.tls_version} /> · <NegotiatedValue value={e.cipher_suite} /></span>
                    </div>
                    <div style={{ fontSize: 10.5, color: "var(--faint)" }}>{e.negotiation.basis}</div>
                  </div>
                  {(d.observations ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>RUNTIME SESSION OBSERVATIONS</div>
                      {(d.observations ?? []).map((o: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>
                          {String(o.tls_version ?? "—")} · {String(o.cipher_suite ?? "—")} · {String(o.observation_count ?? 0)}× · last {String(o.last_seen ?? "—").slice(0, 19)}
                        </div>
                      ))}
                    </div>
                  )}
                  {d.certificate_detail ? (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>CERTIFICATE METADATA</div>
                      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {Object.entries(d.certificate_detail).map(([k, v]) => <Badge key={k} tone="slate">{k}: {String(v)}</Badge>)}
                      </div>
                    </div>
                  ) : (
                    <div style={{ fontSize: 11.5, color: "var(--dim)" }}>No certificate metadata collected for this endpoint.</div>
                  )}
                  {(d.dependencies ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>DEPENDENCIES</div>
                      {(d.dependencies ?? []).map((x: Record<string, unknown>, i: number) => (
                        <div key={i} style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--dim)" }}>{String(x.type)} → {String(x.target)}</div>
                      ))}
                    </div>
                  )}
                  <div>
                    <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)", marginBottom: 6 }}>EVIDENCE</div>
                    <div style={{ fontSize: 11.5, color: "var(--dim)" }}>{String(d.evidence?.method ?? "")} · {String(d.evidence?.runs ?? 0)} run(s)</div>
                    <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4 }}>{String(d.related?._note ?? "")}</div>
                  </div>
                </div>
              );
            })()
          )}
        </Drawer>
      )}
    </>
  );
}

function NbomAssets() {
  const read = useApi(apiNbomWorkspaceAssets);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Network Asset Inventory" sub="host-level rollup over the stored probes">
      <WsState read={read} noun="host inventory">
        <WsTable head={["Host", "Endpoints", "Ports", "Protocols", "Observed", "Unknown negotiation", "Last observed"]} colSpan={7}
          rows={rows.slice(0, 200).map((r) => (
            <tr key={r.host}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.host}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.endpoints}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{(r.ports ?? []).join(", ")}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{Object.entries(r.protocols ?? {}).map(([k, v]) => `${k} (${v})`).join(", ")}</span></td>
              <td><Badge tone="pass">{r.observed}</Badge></td>
              <td><Badge tone="slate">{r.unknown_negotiation} unknown</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomServices() {
  const read = useApi(apiNbomWorkspaceServices);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Service & Port Inventory" sub="identified services as the collector recorded them">
      <WsState read={read} noun="service inventory">
        <WsTable head={["Endpoint", "Host", "Port", "Service", "Protocol", "Negotiation", "Last observed"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.endpoint}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.host || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.port ?? "—")}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.service || "NOT_COLLECTED"}</span></td>
              <td><Badge tone="slate">{r.protocol || "—"}</Badge></td>
              <td><NegotiationBadge negotiation={{ state: r.negotiation_state, basis: "" }} /></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomProtocol({ kind, label }: { kind: "tls" | "ssh" | "ipsec"; label: string }) {
  const read = useApi(() => kind === "tls" ? apiNbomWorkspaceTls() : kind === "ssh" ? apiNbomWorkspaceSsh() : apiNbomWorkspaceIpsec(), [kind]);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title={label} sub="supported, configured and negotiated are kept apart — unknown where the collector cannot establish it">
      <WsState read={read} noun={label.toLowerCase()}>
        <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
          <Badge tone="pass">{String(read.data?.observed ?? 0)} observed</Badge>
          <Badge tone="slate">{String(read.data?.unknown ?? 0)} unknown</Badge>
        </div>
        <WsTable head={["Endpoint", "Host", "Port", "TLS version", "Cipher suite", "Negotiation", "Probe status", "Last observed"]} colSpan={8}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.endpoint}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.host || "—"}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.port ?? "—")}</span></td>
              <td><NegotiatedValue value={r.tls_version} /></td>
              <td><NegotiatedValue value={r.cipher_suite} /></td>
              <td><NegotiationBadge negotiation={r.negotiation} /></td>
              <td><Badge tone="slate">{r.status || "—"}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomCertificates() {
  const read = useApi(apiNbomWorkspaceCertificates);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Certificate Exposure" sub="certificates served on the wire, joined to the certificate store only where the fingerprint matches">
      <WsState read={read} noun="certificate exposure">
        <WsTable head={["Endpoint", "Subject", "Issuer", "Public key", "Expiry", "In store", "Last observed"]} colSpan={7}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.endpoint}</span></td>
              <td><span style={{ fontSize: 11.5 }}>{r.subject || <span style={{ color: "var(--faint)" }}>no subject collected</span>}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.issuer || "—"}</span></td>
              <td><Badge tone="slate">{r.public_key_algorithm || "?"}{r.public_key_size ? ` ${r.public_key_size}` : ""}</Badge></td>
              <td><Badge tone={r.expiry_status === "EXPIRED" ? "red" : "slate"}>{r.expiry_status || "UNKNOWN"}</Badge></td>
              <td>{r.in_store ? <Badge tone="pass">joined</Badge> : <Badge tone="slate">probe only</Badge>}</td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomDependencies() {
  const read = useApi(apiNbomWorkspaceDependencies);
  const edges = (read.data?.edges ?? []) as Array<Record<string, string>>;
  const roots = (read.data?.roots ?? []) as string[];
  return (
    <Panel title="Network Dependencies" sub="edges come from stored relationships only — exposed_on and served_by, never guessed links">
      <WsState read={read} noun="dependency inventory">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 12 }}>
          <Badge tone="violet">{edges.length} edges</Badge>
          <Badge tone="slate">{roots.length} roots</Badge>
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

function NbomChanges() {
  const read = useApi(apiNbomWorkspaceChanges);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Network Change History" sub="newest run wins per endpoint; every run that recorded it is observation history">
      <WsState read={read} noun="change history">
        <WsTable head={["Endpoint", "Current scan run", "Recorded", "Runs observed"]} colSpan={4}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.endpoint}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.scan_run_id ?? "—").slice(0, 12)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.recorded_at ?? "—").slice(0, 19)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{r.runs}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomEvidence() {
  const read = useApi(apiNbomWorkspaceEvidence);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="Evidence & Provenance" sub="the collection method is named — a probe without a successful handshake is recorded as exactly that">
      <WsState read={read} noun="evidence inventory">
        <WsTable head={["Endpoint", "Source", "Method", "Probe status", "Last observed", "Freshness"]} colSpan={6}
          rows={rows.slice(0, 200).map((r, i) => (
            <tr key={i}>
              <td><span style={{ fontWeight: 700, fontSize: 12 }}>{r.endpoint}</span></td>
              <td><span style={{ fontSize: 11 }}>{r.source}</span></td>
              <td><span style={{ fontSize: 11, color: "var(--dim)" }}>{r.method}</span></td>
              <td><Badge tone="slate">{r.status || "—"}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.last_observed ?? "—").slice(0, 10)}</span></td>
              <td><Badge tone={r.freshness === "CURRENT" ? "pass" : r.freshness === "STALE" ? "amber" : "slate"}>{r.freshness}</Badge></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomHistory() {
  const read = useApi(apiNbomWorkspaceHistory);
  const rows = (read.data?.rows ?? []) as Array<Record<string, any>>;
  return (
    <Panel title="NBOM History" sub="stored scan runs — probed and ok counts as the run recorded them">
      <WsState read={read} noun="scan history">
        <WsTable head={["Scan run", "Target kind", "Verdict", "Probed", "OK", "Created"]} colSpan={6}
          rows={rows.slice(0, 100).map((r) => (
            <tr key={r.scan_run_id}>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.scan_run_id).slice(0, 12)}…</span></td>
              <td><Badge tone="slate">{r.target_kind || "—"}</Badge></td>
              <td><Badge tone={r.verdict === "OK" ? "pass" : r.verdict ? "amber" : "slate"}>{r.verdict || "UNKNOWN"}</Badge></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.probed ?? "—")}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11 }}>{String(r.ok ?? "—")}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 10.5 }}>{String(r.created_at ?? "—").slice(0, 19)}</span></td>
            </tr>
          ))} />
      </WsState>
    </Panel>
  );
}

function NbomExport() {
  const read = useApi(apiNbomWorkspaceExport);
  const formats = (read.data?.formats ?? []) as Array<Record<string, unknown>>;
  return (
    <Panel title="Export & Validation" sub="the NBOM exports as the scanner recorded it — endpoints the collector could not establish stay unknown in the document too">
      <WsState read={read} noun="export inventory">
        <WsTable head={["Format", "Validator", "State"]} colSpan={3}
          rows={formats.map((f, i) => (
            <tr key={i}>
              <td><span style={{ fontSize: 12, fontWeight: 600 }}>{String(f.format)}</span></td>
              <td><span style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--dim)" }}>{String(f.validator)}</span></td>
              <td><Badge tone="pass">{String(f.state)}</Badge></td>
            </tr>
          ))} />
        <div style={{ marginTop: 12, fontSize: 11.5, color: "var(--dim)" }}>
          Live document: <Link to="/live-asset-intelligence" style={{ color: "var(--accent)" }}>NBOM export →</Link>
        </div>
      </WsState>
    </Panel>
  );
}
