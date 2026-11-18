import { Link } from "react-router-dom";
import React, { useEffect, useMemo, useState } from "react";
import { Badge, Panel, Bar, Ring, Kpi } from "../components/ui";
import { apiTechBomLive, apiBankingRoadmap, apiBankingHndl } from "../lib/api";
import AuthenticatedDownload from "../components/AuthenticatedDownload";
import { IconCertificate, IconCrypto, IconHardware, IconTarget, IconClock, IconSecurity, IconTrendUp, IconTrendDown, IconInfo, IconWarn } from "../components/icons";

export default function Pqc() {
  const [loading, setLoading] = useState(true);
  const [techBom, setTechBom] = useState<any>(null);
  const [roadmap, setRoadmap] = useState<any>(null);
  const [hndl, setHndl] = useState<any>(null);

  useEffect(() => {
    let alive = true;
    async function loadPqc() {
      setLoading(true);
      try {
        const [tbRes, rmRes, hndlRes] = await Promise.all([
          apiTechBomLive(),
          apiBankingRoadmap(),
          apiBankingHndl(5),
        ]);
        if (alive) {
          if (tbRes.source === "live" && tbRes.data) setTechBom(tbRes.data);
          if (rmRes.source === "live" && rmRes.data) setRoadmap(rmRes.data);
          if (hndlRes.source === "live" && hndlRes.data) setHndl(hndlRes.data);
        }
      } catch (err) {
        console.error("Failed to load PQC readiness data:", err);
      } finally {
        if (alive) setLoading(false);
      }
    }
    loadPqc();
    return () => { alive = false; };
  }, []);

  // Each of the three reads stands on its own: a failed BOM read does not make
  // the roadmap's numbers zero, and an unread roadmap does not mean the estate
  // has no weak legacy primitives.
  const tbOk = techBom != null;
  const rmOk = roadmap != null;
  const hndlOk = hndl != null;
  const totalComponents: number | null = tbOk ? techBom?.total_components ?? null : null;
  const weakLegacy: number | null = rmOk ? roadmap?.weak_legacy_instances ?? null : null;
  const totalInScope: number | null = rmOk ? roadmap?.total_in_scope ?? null : null;
  const phases: any[] = roadmap?.phases || [];
  const hndlTotal: number | null = hndlOk ? hndl?.total ?? null : null;
  const hndlAtRisk = hndl?.at_risk;
  const missing = [!tbOk ? "Technology BOM" : null, !rmOk ? "IR 8547 roadmap" : null, !hndlOk ? "HNDL model" : null].filter(Boolean) as string[];

  // Shares of the in-scope instances the roadmap actually counted. No score is
  // invented: "readiness" is the measured share that is not weak legacy.
  const weakPct = totalInScope && weakLegacy != null ? Math.min(1, weakLegacy / totalInScope) : null;
  const hndlPct = totalInScope && hndlTotal != null ? Math.min(1, hndlTotal / totalInScope) : null;
  const readinessPct = weakPct == null ? null : Math.max(0, 1 - weakPct);
  const readinessTone = readinessPct == null ? "slate" : readinessPct > 0.7 ? "green" : readinessPct > 0.4 ? "amber" : "red";
  const phasedTotal = useMemo(() => phases.reduce((s: number, p: any) => s + (p.instance_count || 0), 0), [phases]);
  const num = (v: number | null | undefined) => (v == null ? "—" : v.toLocaleString());
  const share = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(v * 100)}%`);

  return (
    <div className="page" style={{ maxWidth: "1280px", margin: "0 auto", padding: "10px 0 60px" }}>
      {/* Header — visual */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16, flexWrap: "wrap", gap: 16 }}>
        <div style={{ flex: "1 1 420px", minWidth: 280 }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "4px 10px", borderRadius: 999, background: "color-mix(in srgb, var(--accent) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", fontSize: 11, fontFamily: "var(--mono)", color: "var(--accent)", letterSpacing: "0.06em" }}>
            <span style={{ width: 6, height: 6, borderRadius: 99, background: "var(--accent)" }} /> NIST FIPS 203 / 204 / 205 · CNSA 2.0 ALIGNED
          </div>
          <h1 style={{ fontSize: 26, fontWeight: 800, margin: "8px 0 6px", letterSpacing: "-0.02em", display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ width: 34, height: 34, borderRadius: 10, display: "grid", placeItems: "center", background: "var(--accent)", color: "var(--on-accent)" }}><IconSecurity size={18} /></span>
            Post-Quantum Readiness
          </h1>
          <p style={{ margin: 0, fontSize: 13.5, color: "var(--dim)", lineHeight: 1.5, maxWidth: 620 }}>
            Quantum vulnerability, HNDL exposure and hybrid PQC transition.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
          <Panel style={{ padding: "10px 14px", minWidth: 160, display: "flex", alignItems: "center", gap: 12 }}>
            <Ring pct={readinessPct ?? 0} label={readinessPct == null ? "—" : `${Math.round(readinessPct * 100)}%`} sub="ready" tone={readinessTone} />
            <div>
              <div style={{ fontSize: 11, letterSpacing: ".08em", color: "var(--faint)" }}>ESTATE READINESS</div>
              <div style={{ fontSize: 12, color: "var(--dim)", maxWidth: 120, lineHeight: 1.4 }}>{weakLegacy == null ? "roadmap not read" : weakLegacy === 0 ? "No weak legacy in scope" : `${weakLegacy} weak instances need migration`}</div>
              <div style={{ marginTop: 6 }}><Bar value={readinessPct ?? 0} tone={readinessTone} /></div>
            </div>
          </Panel>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            <AuthenticatedDownload path="/api/v1/banking/roadmap" filename="ir-8547-roadmap.json" className="btn outline" style={{ fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)" }}>
              Export IR 8547 Roadmap
            </AuthenticatedDownload>
            <Link to="/cbom" className="btn primary" style={{ textDecoration: "none", fontSize: 12, padding: "8px 14px", borderRadius: "var(--r)", textAlign: "center" }}>Filter CBOM →</Link>
            <span style={{ fontSize: 11, color: "var(--faint)", textAlign: "center" }}>{num(totalInScope)} in scope · {rmOk ? `${phasedTotal.toLocaleString()} phased` : "phases not read"}</span>
          </div>
        </div>
      </div>

      {!loading && missing.length > 0 && (
        <p role="status" style={{ margin: "0 0 14px", fontSize: 11.5, color: "var(--amber)" }}>
          Not read in this load: {missing.join(", ")}. Their figures below show —, not zero.
        </p>
      )}

      {/* Top 4 metric cards — visual */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginBottom: 18 }}>
        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--accent)" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconHardware size={12} /> TOTAL IN-SCOPE CRYPTOGRAPHY</div>
              <div style={{ fontSize: 32, fontWeight: 800, margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : num(totalInScope)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>{rmOk ? "Counted by the IR 8547 roadmap" : "roadmap not read"}</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--accent) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--accent) 35%, var(--line))", color: "var(--accent)" }}><IconTarget size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{num(totalComponents)} components in the Technology BOM</span><span style={{ color: "var(--accent)" }}>● inventory</span></div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>
              {tbOk
                ? "Components across all four BOM layers — the denominator the roadmap counts against"
                : "Technology BOM not read in this load"}
            </div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${weakLegacy == null ? "var(--line-strong)" : weakLegacy > 0 ? "var(--red)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconWarn size={12} /> WEAK LEGACY PRIMITIVES</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: weakLegacy == null ? "var(--slate)" : weakLegacy > 0 ? "var(--red)" : "var(--green)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : num(weakLegacy)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>DES / 3DES / RC4 / MD5 / SHA-1</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: weakLegacy ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--green) 14%, transparent)", border: `1px solid color-mix(in srgb, ${weakLegacy ? "var(--red)" : "var(--green)"} 35%, var(--line))`, color: weakLegacy ? "var(--red)" : "var(--green)" }}>{weakLegacy ? <IconTrendUp size={16} /> : <IconSecurity size={16} />}</span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 6 }}><span>{weakPct == null ? "share not read" : weakLegacy ? `${Math.round(weakPct * 100)}% of in-scope instances` : "clean"}</span><span style={{ color: weakLegacy ? "var(--red)" : weakLegacy == null ? "var(--slate)" : "var(--green)" }}>{weakLegacy == null ? "not read" : weakLegacy ? "action needed" : "no action"}</span></div>
            <Bar value={weakPct ?? 0} tone={weakLegacy == null ? "slate" : weakLegacy ? "red" : "green"} />
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: `2px solid ${hndlTotal == null ? "var(--line-strong)" : hndlAtRisk ? "var(--red)" : hndlTotal ? "var(--amber)" : "var(--green)"}` }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)", display: "flex", alignItems: "center", gap: 6 }}><IconCrypto size={12} /> HNDL CONFIDENTIALITY RISK</div>
              <div style={{ fontSize: 32, fontWeight: 800, color: hndlTotal == null ? "var(--slate)" : hndlAtRisk ? "var(--red)" : hndlTotal ? "var(--amber)" : "var(--green)", margin: "6px 0 2px", fontFamily: "var(--mono)", lineHeight: 1 }}>{loading ? "…" : num(hndlTotal)}</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>Harvest-Now-Decrypt-Later records</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: hndlAtRisk ? "color-mix(in srgb, var(--red) 14%, transparent)" : "color-mix(in srgb, var(--amber) 12%, transparent)", border: `1px solid color-mix(in srgb, ${hndlAtRisk ? "var(--red)" : "var(--amber)"} 35%, var(--line))`, color: hndlAtRisk ? "var(--red)" : "var(--amber)" }}><IconClock size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
              <Badge tone={hndlTotal == null ? "slate" : hndlAtRisk ? "red" : hndlTotal ? "amber" : "green"}>{hndlTotal == null ? "NOT READ" : hndlAtRisk ? "AT RISK" : hndlTotal ? "EXPOSED" : "CLEAR"}</Badge>
              {hndl && hndl.assessment_complete === false && <Badge tone="slate">classification not supplied</Badge>}
              {(hndl?.by_exposure?.critical ?? 0) > 0 ? <Badge tone="red">{hndl.by_exposure.critical} critical</Badge> : null}
            </div>
            <Bar value={hndlPct ?? 0} tone={hndlPct == null ? "slate" : hndlAtRisk ? "red" : "amber"} />
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 6 }}>Long-lived confidentiality horizon</div>
          </div>
        </div>

        <div className="panel" style={{ padding: 0, overflow: "hidden", borderTop: "2px solid var(--violet)", background: "color-mix(in srgb, var(--violet) 4%, var(--panel))" }}>
          <div style={{ padding: "16px 16px 10px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ fontSize: 10, letterSpacing: ".08em", color: "var(--faint)" }}>TRANSITION ANCHOR</div>
              <div style={{ fontSize: 18, fontWeight: 800, margin: "8px 0 2px", color: "var(--violet)" }}>NIST IR 8547</div>
              <div style={{ fontSize: 12, color: "var(--dim)" }}>2030 Deprecation · 2035 Disallowance</div>
            </div>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--violet) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--violet) 35%, var(--line))", color: "var(--violet)" }}><IconCertificate size={16} /></span>
          </div>
          <div style={{ padding: "0 16px 12px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, height: 8, background: "var(--bg-2)", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ flex: 1, height: "100%", background: "var(--violet)", opacity: .9 }} />
              <div style={{ flex: 1, height: "100%", background: "var(--accent)", opacity: .9 }} />
              <div style={{ flex: 1, height: "100%", background: "var(--red)", opacity: .85 }} />
            </div>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>2027 purge</span><span>2030 replace</span><span>2035 disallow</span></div>
            <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 2 }}>
              <span title={"Schematic of the standard's milestones — the segment widths are equal, not estate proportions"}>{"Schematic of the standard's milestones"}</span></div>
          </div>
        </div>
      </div>

      {/* HNDL + Inventory visual strip */}
      {hndl && (hndlTotal ?? 0) > 0 && (
        <div className="panel" style={{ padding: "14px 16px", marginBottom: 18, borderLeft: "3px solid var(--amber)", background: "color-mix(in srgb, var(--amber) 4%, var(--panel))" }}>
          <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ width: 32, height: 32, borderRadius: 999, display: "grid", placeItems: "center", background: "var(--amber)", color: "#000" }}><IconClock size={14} /></span>
              <div>
                <div style={{ fontSize: 12, fontWeight: 700, color: "var(--amber)" }}>HNDL Risk · Harvest-Now-Decrypt-Later</div>
                <div style={{ fontSize: 11, color: "var(--dim)" }}>{hndlTotal} long-retention records with confidentiality beyond quantum horizon</div>
              </div>
            </div>
            <div style={{ flex: "1 1 180px", minWidth: 160 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--dim)", marginBottom: 4 }}><span>exposure</span><span>{share(hndlPct)} of scope</span></div>
              <Bar value={hndlPct ?? 0} tone="amber" />
            </div>
            <Badge tone={hndlAtRisk ? "red" : "amber"}>{hndlAtRisk ? "RETENTION > HORIZON" : "MONITORED"}</Badge>
          </div>
          {hndl?.by_expiry && (
            <div style={{ display: "flex", gap: 8, marginTop: 12, flexWrap: "wrap" }}>
              {Object.entries(hndl.by_expiry as Record<string, number>).slice(0, 5).map(([k, v]) => (
                <span key={k} style={{ padding: "4px 10px", borderRadius: 999, background: "var(--panel-2)", border: "1px solid var(--line)", fontSize: 11 }}><b style={{ color: "var(--text)", fontFamily: "var(--mono)" }}>{String(v)}</b> <span style={{ color: "var(--dim)" }}>{k}</span></span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Migration Roadmap — visual timeline */}
      <div className="panel" style={{ padding: 0, marginBottom: 18, overflow: "hidden" }}>
        <div style={{ padding: "16px 18px 12px", display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--accent)" }} /> NIST IR 8547 Migration Roadmap</h3>
            <p style={{ margin: "4px 0 0", fontSize: 12, color: "var(--dim)" }}>Deterministic timeline — instance counts from verified estate · <b style={{ color: "var(--text)" }}>{phasedTotal.toLocaleString()}</b> total phased instances</p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 11, color: "var(--dim)" }}>progress</span>
            <div style={{ width: 100, height: 8, background: "var(--bg-2)", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
              <div style={{ width: `${phases.length ? Math.round((phases.filter((p: any) => (p.instance_count || 0) === 0).length / phases.length) * 100) : 0}%`, height: "100%", background: "var(--green)" }} />
            </div>
            <Badge tone="green">{phases.filter((p: any) => (p.instance_count || 0) === 0).length}/{phases.length} clear</Badge>
          </div>
        </div>

        {/* Timeline connector */}
        {phases.length > 0 && (
          <div style={{ padding: "14px 18px 4px" }}>
            <div style={{ position: "relative", height: 36, display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 8%" }}>
              <div style={{ position: "absolute", left: "8%", right: "8%", top: "50%", height: 2, background: "var(--line-strong)", transform: "translateY(-50%)" }} />
              {phases.map((p: any, idx: number) => {
                const tone = p.instance_count > 10 ? "var(--red)" : p.instance_count > 0 ? "var(--amber)" : "var(--green)";
                const bg = p.instance_count > 0 ? "var(--panel-2)" : "var(--green)";
                return (
                  <div key={idx} style={{ position: "relative", zIndex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
                    <div style={{ width: 28, height: 28, borderRadius: 99, background: bg, border: `2px solid ${tone}`, color: p.instance_count > 0 ? tone : "#fff", display: "grid", placeItems: "center", fontSize: 11, fontWeight: 800 }}>{idx + 1}</div>
                    <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--faint)", background: "var(--panel)", padding: "1px 6px", borderRadius: 99, border: "1px solid var(--line)" }}>{p.deadline || "∞"}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 14, padding: "12px 18px 18px" }}>
          {phases.map((p: any, idx: number) => {
            const pct = phasedTotal ? (p.instance_count || 0) / Math.max(1, phasedTotal) : 0;
            const tone = p.instance_count > 20 ? "red" : p.instance_count > 0 ? "amber" : "green";
            const isDone = (p.instance_count || 0) === 0;
            return (
              <div key={idx} style={{ padding: 14, background: isDone ? "color-mix(in srgb, var(--green) 6%, var(--panel-2))" : "var(--panel-2)", border: `1px solid ${isDone ? "var(--green)" : "var(--line)"}`, borderTop: `2px solid ${isDone ? "var(--green)" : tone === "red" ? "var(--red)" : "var(--amber)"}`, borderRadius: "var(--r)", display: "flex", flexDirection: "column", gap: 8, position: "relative", overflow: "hidden" }}>
                {isDone && <span style={{ position: "absolute", top: 8, right: 8, fontSize: 14, color: "var(--green)" }}>✓</span>}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: isDone ? "var(--green)" : "var(--cyan)", fontWeight: 800, letterSpacing: ".06em" }}>Phase {p.phase}</span>
                  <Badge tone={p.deadline && p.deadline <= 2027 ? "amber" : p.deadline && p.deadline <= 2030 ? "red" : "slate"}>{p.deadline ? `Target: ${p.deadline}` : "Continuous"}</Badge>
                </div>
                <div style={{ fontSize: 13.5, fontWeight: 700, color: "var(--text)", lineHeight: 1.3, minHeight: 32 }}>{p.title}</div>
                {p.action && <div style={{ fontSize: 11.5, color: "var(--dim)", lineHeight: 1.4 }}>{p.action}</div>}
                <div style={{ marginTop: "auto", paddingTop: 10, borderTop: "1px dashed var(--line)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                    <span style={{ fontSize: 11, color: "var(--dim)" }}>Instances in Scope</span>
                    <span style={{ fontSize: 18, fontWeight: 800, fontFamily: "var(--mono)", color: isDone ? "var(--green)" : tone === "red" ? "var(--red)" : "var(--amber)" }}>{p.instance_count ?? 0}</span>
                  </div>
                  <Bar value={pct} tone={isDone ? "green" : tone} />
                  <div style={{ fontSize: 10, color: "var(--faint)", marginTop: 4 }}>{pct ? `${Math.round(pct * 100)}% of phased total` : isDone ? "cleared" : "no instances"}</div>
                </div>
              </div>
            );
          })}
          {phases.length === 0 && !loading && (
            <div style={{ padding: 28, textAlign: "center", color: "var(--dim)", gridColumn: "1 / -1", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px dashed var(--line-strong)" }}>
              <div style={{ fontSize: 22 }}>◈</div>
              <div style={{ fontWeight: 600, marginTop: 8, color: "var(--text)" }}>No migration phases calculated yet</div>
              <div style={{ fontSize: 12, marginTop: 4 }}>Run discovery scans to classify estate cryptography and generate IR 8547 phases.</div>
            </div>
          )}
        </div>
      </div>

      {/* Analytics strip — 3 panels, all from the roadmap read. Nothing here is a
          modelled mix: the estate model counts instances per IR 8547 phase and the
          weak-legacy share; it does not classify hybrid vs pure-PQC keys, so that
          cell says so instead of showing a made-up percentage. */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14, marginBottom: 18 }}>
        <Panel title="Instances per migration phase" sub="counted by the roadmap read" style={{ padding: "14px 16px" }}>
          {phases.length === 0 && (
            <div style={{ fontSize: 12, color: "var(--dim)", lineHeight: 1.5 }}>
              {rmOk ? "The roadmap returned no phases." : "The IR 8547 roadmap was not read in this load."}
            </div>
          )}
          {phases.map((p: any, idx: number) => {
            const c = p.instance_count ?? 0;
            const v = phasedTotal ? c / phasedTotal : 0;
            return (
              <React.Fragment key={idx}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}>
                  <span style={{ width: 90, fontSize: 11, color: "var(--dim)", fontFamily: "var(--mono)" }}>{p.phase} · {p.deadline ?? "∞"}</span>
                  <div style={{ flex: 1 }}><Bar value={v} tone={c === 0 ? "slate" : c > 10 ? "red" : "amber"} /></div>
                  <span style={{ fontSize: 11, fontFamily: "var(--mono)", color: "var(--text)", minWidth: 56, textAlign: "right" }}>{c} · {Math.round(v * 100)}%</span>
                </div>
                {/* traceability (gap analysis §A: plans traceable to assets and
                    rules): every migration line names the rule that placed it
                    and links its applications to the inventory. */}
                {Array.isArray(p.items) && p.items.length > 0 && (
                  <ul data-testid={`phase-items-${p.phase}`} style={{ margin: "0 0 10px 100px", paddingLeft: 12, fontSize: 10.5, color: "var(--dim)", listStyle: "disc" }}>
                    {p.items.map((item: any, j: number) => (
                      <li key={j}>
                        <Link to={`/cbom?focus=${encodeURIComponent(item.family ?? "")}`} style={{ color: "var(--cyan)", textDecoration: "none" }}>
                          {item.family}{item.key_size ? ` ${item.key_size}` : ""}
                        </Link>
                        {" "}· rule: <span style={{ fontFamily: "var(--mono)" }}>{item.transition ?? "not reported"}</span>
                        {item.deadline != null ? <> · deadline {item.deadline}{item.overdue ? " (overdue)" : ""}</> : null}
                        {" "}· {item.instances} instance(s)
                        {Array.isArray(item.applications) && item.applications.length > 0 && (
                          <> · applications: {item.applications.map((app: string, k: number) => (
                            <React.Fragment key={app}>{k > 0 ? ", " : ""}<Link to={`/assets?q=${encodeURIComponent(app)}`} style={{ color: "var(--cyan)" }}>{app}</Link></React.Fragment>
                          ))}</>
                        )}
                      </li>
                    ))}
                  </ul>
                )}
              </React.Fragment>
            );
          })}
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 4, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
            Share of the {phasedTotal} instances the roadmap placed. A phase with 0 has nothing left in it.
          </div>
          {/* traceability: the plan names the rule basis it was generated under */}
          <div data-testid="plan-anchor" style={{ fontSize: 10.5, color: "var(--dim)", marginTop: 6 }}>
            plan anchor: {rmOk ? roadmap?.anchor ?? "not reported" : "roadmap not read"}
            {rmOk && roadmap?.deadline_basis ? <> · basis: <span style={{ fontFamily: "var(--mono)" }}>{roadmap.deadline_basis}</span></> : null}
            {rmOk && roadmap?.regulatory_approval === false ? " · not a regulatory mandate" : null}
          </div>
        </Panel>

        <Panel title="Transition momentum" sub="in-scope instances that are not weak legacy" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}>
            <div style={{ width: 54, height: 54, borderRadius: 999, background: readinessPct == null ? "var(--panel-2)" : readinessPct > 0.7 ? "color-mix(in srgb, var(--green) 14%, transparent)" : "color-mix(in srgb, var(--amber) 14%, transparent)", border: `2px solid ${readinessTone === "slate" ? "var(--line)" : readinessTone === "green" ? "var(--green)" : readinessTone === "amber" ? "var(--amber)" : "var(--red)"}`, display: "grid", placeItems: "center", color: readinessTone === "slate" ? "var(--slate)" : readinessTone === "green" ? "var(--green)" : readinessTone === "amber" ? "var(--amber)" : "var(--red)", fontSize: 18, fontWeight: 800 }}>{readinessPct == null ? "—" : `${Math.round(readinessPct * 100)}%`}</div>
            <div>
              <div style={{ fontSize: 12, fontWeight: 700 }}>Not weak legacy</div>
              <div style={{ fontSize: 11, color: "var(--dim)" }}>
                {weakPct == null || totalInScope == null || weakLegacy == null
                  ? "roadmap not read"
                  : `${(totalInScope - weakLegacy).toLocaleString()} of ${totalInScope.toLocaleString()} in scope`}
              </div>
              <div style={{ fontSize: 10, color: weakLegacy ? "var(--amber)" : weakLegacy == null ? "var(--slate)" : "var(--green)", marginTop: 2 }}>
                {weakLegacy == null ? "no figure returned" : weakLegacy ? `${weakLegacy} weak instances remain` : "nothing weak in scope"}
              </div>
            </div>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, textAlign: "center" }}>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--green)" }}>{rmOk ? phases.filter((p: any) => (p.instance_count || 0) === 0).length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>DONE</div></div>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800, color: "var(--amber)" }}>{rmOk ? phases.filter((p: any) => (p.instance_count || 0) > 0).length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>ACTIVE</div></div>
            <div style={{ padding: "8px 6px", background: "var(--panel-2)", borderRadius: "var(--r)", border: "1px solid var(--line)" }}><div style={{ fontSize: 16, fontWeight: 800 }}>{rmOk ? phases.length : "—"}</div><div style={{ fontSize: 10, color: "var(--faint)" }}>TOTAL</div></div>
          </div>
        </Panel>

        <Panel title="What the estate model does not classify" sub="so it is not read as a readiness score" style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <span style={{ flex: 1, padding: "8px 10px", borderRadius: "var(--r)", background: weakLegacy == null ? "var(--panel-2)" : "color-mix(in srgb, var(--red) 8%, transparent)", border: `1px solid ${weakLegacy == null ? "var(--line)" : "var(--red)"}`, textAlign: "center" }}><div style={{ fontSize: 11, color: "var(--dim)" }}>Weak legacy</div><div style={{ fontSize: 18, fontWeight: 800, color: weakLegacy == null ? "var(--slate)" : "var(--red)" }}>{share(weakPct)}</div></span>
            <span style={{ flex: 1, padding: "8px 10px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", textAlign: "center" }}><div style={{ fontSize: 11, color: "var(--dim)" }}>Hybrid keys</div><div style={{ fontSize: 18, fontWeight: 800, color: "var(--slate)" }}>—</div></span>
            <span style={{ flex: 1, padding: "8px 10px", borderRadius: "var(--r)", background: "var(--panel-2)", border: "1px solid var(--line)", textAlign: "center" }}><div style={{ fontSize: 11, color: "var(--dim)" }}>Pure PQC</div><div style={{ fontSize: 18, fontWeight: 800, color: "var(--slate)" }}>—</div></span>
          </div>
          <div style={{ height: 8, display: "flex", borderRadius: 99, overflow: "hidden", border: "1px solid var(--line)" }}>
            <div style={{ width: `${(weakPct ?? 0) * 100}%`, background: "var(--red)" }} />
            <div style={{ flex: 1, background: "var(--slate)", opacity: 0.35 }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--faint)", marginTop: 6 }}><span>● weak legacy</span><span>● everything else (not classified)</span></div>
          <div style={{ fontSize: 11, color: "var(--faint)", marginTop: 8, borderTop: "1px solid var(--line)", paddingTop: 8 }}>
            <span title={"No collector reports a per-key hybrid/PQC split, so this page does not print one. The estate-evidence PQC read is where that question is answered, once discovery has run."}>{"No collector reports a per-key hybrid/PQC split, so this page does not print one."}</span>
          </div>
        </Panel>
      </div>

      {/* Taxonomy — visual table */}
      <div className="panel" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ padding: "14px 18px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, borderBottom: "1px solid var(--line)", background: "var(--bg-2)" }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, display: "flex", alignItems: "center", gap: 8 }}><IconInfo size={14} style={{ color: "var(--accent)" }} /> Standard Reference: Quantum Vulnerability Taxonomy</h3>
            <p style={{ margin: "4px 0 0", fontSize: 11.5, color: "var(--dim)" }}>Official NIST / CNSA 2.0 transition matrix — <span style={{ color: "var(--accent)" }}>what breaks, when, and what replaces it</span></p>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <Badge tone="red">3 disallowed</Badge>
            <Badge tone="amber">1 deprecated</Badge>
            <Badge tone="green">1 secure</Badge>
          </div>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th><span style={{ display: "inline-flex", gap: 6, alignItems: "center" }}><IconCrypto size={12} /> Algorithm Family</span></th>
                <th>Math Problem</th>
                <th>Quantum Threat</th>
                <th>PQ Replacement</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--red) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--red) 35%, var(--line))", color: "var(--red)", fontSize: 10 }}>RSA</span><b>RSA (1024-4096)</b></span></td>
                <td><span style={{ padding: "3px 8px", borderRadius: 99, background: "var(--panel-2)", border: "1px solid var(--line)", fontSize: 11 }}>Integer Factorization</span></td>
                <td><span style={{ fontSize: 11, color: "var(--red)" }}>Shor's (poly-time)</span> <Bar value={1} tone="red" /></td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>ML-DSA-65 / ML-KEM</td>
                <td><Badge tone="red">DISALLOWED POST-2035</Badge></td>
              </tr>
              <tr>
                <td><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--red) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--red) 35%, var(--line))", color: "var(--red)", fontSize: 10 }}>ECC</span><b>ECDSA / ECDH</b></span><span style={{ fontSize: 10, color: "var(--dim)", marginLeft: 6 }}>P-256, P-384, Ed25519</span></td>
                <td><span style={{ padding: "3px 8px", borderRadius: 99, background: "var(--panel-2)", border: "1px solid var(--line)", fontSize: 11 }}>ECDLP</span></td>
                <td><span style={{ fontSize: 11, color: "var(--red)" }}>Shor's (poly-time)</span> <Bar value={1} tone="red" /></td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>ML-DSA / ML-KEM</td>
                <td><Badge tone="red">DISALLOWED POST-2035</Badge></td>
              </tr>
              <tr>
                <td><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--red) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--red) 35%, var(--line))", color: "var(--red)", fontSize: 9 }}>DH</span><b>Diffie-Hellman / DSA</b></span></td>
                <td><span style={{ padding: "3px 8px", borderRadius: 99, background: "var(--panel-2)", border: "1px solid var(--line)", fontSize: 11 }}>Discrete Log</span></td>
                <td><span style={{ fontSize: 11, color: "var(--red)" }}>Shor's</span> <Bar value={0.95} tone="red" /></td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>ML-KEM-768</td>
                <td><Badge tone="red">DISALLOWED POST-2030</Badge></td>
              </tr>
              <tr>
                <td><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: "color-mix(in srgb, var(--amber) 14%, transparent)", border: "1px solid color-mix(in srgb, var(--amber) 35%, var(--line))", color: "var(--amber)", fontSize: 9 }}>SYM</span><b>AES-128</b></span></td>
                <td><span style={{ padding: "3px 8px", borderRadius: 99, background: "var(--panel-2)", border: "1px solid var(--line)", fontSize: 11 }}>SPN Symmetric</span></td>
                <td><span style={{ fontSize: 11, color: "var(--amber)" }}>Grover's → 64-bit</span> <Bar value={0.5} tone="amber" /></td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11 }}>AES-256 (128-bit margin)</td>
                <td><Badge tone="amber">DEPRECATED POST-2030</Badge></td>
              </tr>
              <tr style={{ background: "color-mix(in srgb, var(--green) 6%, transparent)" }}>
                <td><span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><span style={{ width: 22, height: 22, borderRadius: 6, display: "grid", placeItems: "center", background: "var(--green)", color: "#fff", fontSize: 10 }}>✓</span><b>AES-256 / SHA-384 / SHA-512</b></span></td>
                <td><span style={{ padding: "3px 8px", borderRadius: 99, background: "color-mix(in srgb, var(--green) 12%, transparent)", border: "1px solid color-mix(in srgb, var(--green) 35%, var(--line))", fontSize: 11, color: "var(--green)" }}>Hash / Sponge</span></td>
                <td><span style={{ fontSize: 11, color: "var(--green)" }}>Grover-resistant</span> <Bar value={0.1} tone="green" /></td>
                <td style={{ fontFamily: "var(--mono)", fontSize: 11, color: "var(--green)" }}>FIPS 203/204/205 Ready</td>
                <td><Badge tone="green">QUANTUM SECURE</Badge></td>
              </tr>
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 16px", background: "var(--bg-2)", borderTop: "1px solid var(--line)", display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, color: "var(--dim)" }}>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--red)", display: "inline-block" }} /> Shor-breakable</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--amber)", display: "inline-block" }} /> Grover-halved</span>
          <span><span style={{ width: 8, height: 8, borderRadius: 99, background: "var(--green)", display: "inline-block" }} /> Quantum-secure</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--mono)" }}>NIST IR 8547 · CNSA 2.0 · FIPS 203/204/205</span>
        </div>
      </div>
    </div>
  );
}
