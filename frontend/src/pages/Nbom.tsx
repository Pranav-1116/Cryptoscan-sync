import React, { useCallback, useEffect, useState, useMemo } from "react";
import { Link } from "react-router-dom";
import { Panel, Badge, Bar, Ring } from "../components/ui";
import { apiNbomLive, NbomCascadeEntry, NbomComponent, NbomResponse } from "../lib/api.js";
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
  return component.properties.find((p) => p.name === `cryptoscan:${key}`)?.value;
}

export default function Nbom() {
  const [data, setData] = useState<NbomResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<NbomCascadeEntry | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await apiNbomLive();
    if (res.ok && res.data) {
      setData(res.data);
      setError(null);
    } else {
      setError(res.error || "No network inventory available yet.");
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

  const posturePct = components.length ? Math.max(0, 1 - (critical ? critical / Math.max(1, components.length) : 0)) : 0;
  const ringTone = critical ? "red" : high ? "amber" : components.length ? "green" : "slate";

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 460px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid var(--accent)", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: critical ? "var(--red)" : "var(--green)" }} /> BOMS · NBOM · NETWORK EXPOSURE
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
            <Ring pct={posturePct} label={loading ? "…" : String(components.length)} sub="components" tone={ringTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>WIRE POSTURE</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 130, lineHeight: 1.4 }}>{critical ? `${critical} critical need rotation` : high ? `${high} high need hardening` : components.length ? "No critical exposure" : "No wire inventory yet"}</div>
              <div style={{ marginTop: 6 }}><Bar value={posturePct} tone={ringTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <Link to="/live-scanners" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Scan operations →</Link>
            <Link to="/dependency-graph" className="btn outline" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center", border: "1px solid var(--line-strong)", background: "var(--panel-2)" }}>Dependency graph →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{summary?.unobserved ? `${summary.unobserved} unobserved` : components.length ? "all observed" : "—"}</span>
          </div>
        </div>
      </div>

      {/* KPI cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconTarget size={12} /> WIRE COMPONENTS</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : components.length.toLocaleString()}</div>
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
              <div style={{ fontSize: 32, fontWeight: 800, color: critical ? "var(--red)" : "var(--green)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : critical}</div>
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
              <div style={{ fontSize: 32, fontWeight: 800, color: analytics.unobserved ? "var(--amber)" : "var(--green)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : analytics.unobserved}</div>
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
                const worst = c["cryptoscan:findings"][0]?.severity;
                return (
                  <tr key={c["bom-ref"]} style={{ background: !observed ? "color-mix(in srgb, var(--amber) 5%, transparent)" : undefined }}>
                    <td><span className="mono" style={{ fontWeight: 600, fontSize: 12 }}>{c.name}</span></td>
                    <td><Badge tone={kind === "certificate" ? "violet" : kind === "listener" ? "cyan" : "slate"}>{kind}</Badge></td>
                    <td><span className="mono" style={{ fontSize: 11 }}>{detail}</span></td>
                    <td>{observed ? <Badge tone="green">observed</Badge> : <Badge tone="slate">unobserved</Badge>}</td>
                    <td>{worst ? <Badge tone={SEV_TONE[worst] ?? "slate"}>{c["cryptoscan:findings"].length} findings</Badge> : <span style={{ color: "var(--faint)", fontSize: 11 }}>—</span>}</td>
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
    </div>
  );
}
